package trust

import (
	stdcrypto "crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/crypto"
	"github.com/grwna/osiris/internal/fsutil"
	"github.com/grwna/osiris/internal/manifest"
	"github.com/grwna/osiris/internal/strictjson"
)

const (
	SchemaValue = "minisign-trust/v1"
	MaxSize     = 1 << 20
)

type Entry struct {
	KeyID        string
	Algorithm    crypto.Profile
	PublicKeyPEM string
	Packages     []string

	PublicKey stdcrypto.PublicKey
}

func (e *Entry) Allows(pkg string) bool {
	for _, p := range e.Packages {
		if p == pkg {
			return true
		}
	}
	return false
}

type Store struct {
	Keys []*Entry
}

func (s *Store) Lookup(keyid string) (*Entry, bool) {
	for _, e := range s.Keys {
		if e.KeyID == keyid {
			return e, true
		}
	}
	return nil, false
}

func Parse(data []byte) (*Store, error) {
	if len(data) > MaxSize {
		return nil, apperr.Format("trust store too large: %d bytes (max %d)", len(data), MaxSize)
	}
	obj, err := strictjson.ParseObject(data)
	if err != nil {
		return nil, apperr.Format("trust store: %v", err)
	}
	if err := obj.ExpectFields("trust store", "schema", "keys"); err != nil {
		return nil, apperr.WrapFormat(err)
	}
	schema, err := obj.String("schema")
	if err != nil {
		return nil, apperr.Format("trust store: %v", err)
	}
	if schema != SchemaValue {
		return nil, apperr.Format("trust store: schema must be %q, got %q", SchemaValue, schema)
	}
	keys, err := obj.Array("keys")
	if err != nil {
		return nil, apperr.Format("trust store: %v", err)
	}
	s := &Store{}
	for i, kv := range keys {
		where := fmt.Sprintf("trust store keys[%d]", i)
		if kv.Kind != strictjson.Object {
			return nil, apperr.Format("%s: must be an object, got %s", where, kv.Kind)
		}
		e, err := parseEntry(kv.Obj, where)
		if err != nil {
			return nil, apperr.WrapFormat(err)
		}
		if _, dup := s.Lookup(e.KeyID); dup {
			return nil, apperr.Format("%s: duplicate keyid %s", where, e.KeyID)
		}
		s.Keys = append(s.Keys, e)
	}
	return s, nil
}

func parseEntry(o *strictjson.Obj, where string) (*Entry, error) {
	if err := o.ExpectFields(where, "keyid", "algorithm", "public_key_pem", "packages"); err != nil {
		return nil, err
	}
	keyid, err := o.String("keyid")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", where, err)
	}
	if !manifest.HexPattern.MatchString(keyid) {
		return nil, fmt.Errorf("%s: keyid must be 64 lowercase hex characters", where)
	}
	alg, err := o.String("algorithm")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", where, err)
	}
	profile, err := crypto.ParseProfile(alg)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", where, err)
	}
	pubPEM, err := o.String("public_key_pem")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", where, err)
	}
	keyProfile, pub, realID, err := crypto.ParsePublicKeyPEM([]byte(pubPEM))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", where, err)
	}
	if realID != keyid {
		return nil, fmt.Errorf("%s: keyid %s does not match the fingerprint of public_key_pem (%s)", where, keyid, realID)
	}
	if keyProfile != profile {
		return nil, fmt.Errorf("%s: algorithm %s does not match the %s public key", where, profile, keyProfile)
	}
	pkgVals, err := o.Array("packages")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", where, err)
	}
	if len(pkgVals) == 0 {
		return nil, fmt.Errorf("%s: packages must not be empty", where)
	}
	pkgs := make([]string, 0, len(pkgVals))
	for j, pv := range pkgVals {
		if pv.Kind != strictjson.String {
			return nil, fmt.Errorf("%s: packages[%d] must be a string, got %s", where, j, pv.Kind)
		}
		if err := checkPackage(pv.Str); err != nil {
			return nil, fmt.Errorf("%s: packages[%d]: %v", where, j, err)
		}
		for _, p := range pkgs {
			if p == pv.Str {
				return nil, fmt.Errorf("%s: duplicate package %q", where, pv.Str)
			}
		}
		pkgs = append(pkgs, pv.Str)
	}
	return &Entry{KeyID: keyid, Algorithm: profile, PublicKeyPEM: pubPEM, Packages: pkgs, PublicKey: pub}, nil
}

func checkPackage(p string) error {
	if strings.ContainsAny(p, "*?[]") {
		return fmt.Errorf("wildcards are not allowed in package names (%q)", p)
	}
	if !manifest.PackagePattern.MatchString(p) {
		return fmt.Errorf("package %q does not match %s", p, manifest.PackagePattern)
	}
	return nil
}

func Load(path string) (*Store, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, apperr.Input("read trust store: %v", err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && !fi.Mode().IsRegular() {
		return nil, apperr.Input("read trust store: %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, apperr.Input("read trust store: %v", err)
	}
	return Parse(data)
}

func LoadOrEmpty(path string) (s *Store, existed bool, err error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return &Store{}, false, nil
	}
	s, err = Load(path)
	return s, err == nil, err
}

type AddResult struct {
	Entry         *Entry
	Created       bool
	AddedPackages []string
}

func (r AddResult) Changed() bool { return r.Created || len(r.AddedPackages) > 0 }

func (s *Store) Add(pubPEM []byte, packages []string) (AddResult, error) {
	if len(packages) == 0 {
		return AddResult{}, apperr.Input("at least one --package is required")
	}
	for _, p := range packages {
		if err := checkPackage(p); err != nil {
			return AddResult{}, apperr.Input("%v", err)
		}
	}
	profile, pub, keyid, err := crypto.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		return AddResult{}, apperr.Input("%v", err)
	}
	res := AddResult{}
	e, ok := s.Lookup(keyid)
	if !ok {
		canon, err := canonicalPEM(pub)
		if err != nil {
			return AddResult{}, apperr.Input("%v", err)
		}
		e = &Entry{KeyID: keyid, Algorithm: profile, PublicKeyPEM: canon, PublicKey: pub}
		s.Keys = append(s.Keys, e)
		res.Created = true
	}
	for _, p := range packages {
		if !e.Allows(p) {
			e.Packages = append(e.Packages, p)
			res.AddedPackages = append(res.AddedPackages, p)
		}
	}
	res.Entry = e
	return res, nil
}

func (s *Store) Remove(keyid string, packages []string) (removedEntry bool, err error) {
	idx := -1
	for i, e := range s.Keys {
		if e.KeyID == keyid {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, apperr.Input("keyid %s not found in trust store", keyid)
	}
	e := s.Keys[idx]
	if len(packages) > 0 {
		for _, p := range packages {
			if !e.Allows(p) {
				return false, apperr.Input("key %s is not trusted for package %q", keyid, p)
			}
		}
		kept := e.Packages[:0:0]
		for _, p := range e.Packages {
			drop := false
			for _, q := range packages {
				drop = drop || p == q
			}
			if !drop {
				kept = append(kept, p)
			}
		}
		if len(kept) > 0 {
			e.Packages = kept
			return false, nil
		}
	}
	s.Keys = append(s.Keys[:idx:idx], s.Keys[idx+1:]...)
	return true, nil
}

func canonicalPEM(pub stdcrypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

type fileEntry struct {
	KeyID        string   `json:"keyid"`
	Algorithm    string   `json:"algorithm"`
	PublicKeyPEM string   `json:"public_key_pem"`
	Packages     []string `json:"packages"`
}

type fileStore struct {
	Schema string      `json:"schema"`
	Keys   []fileEntry `json:"keys"`
}

func (s *Store) Marshal() ([]byte, error) {
	fs := fileStore{Schema: SchemaValue, Keys: []fileEntry{}}
	for _, e := range s.Keys {
		fs.Keys = append(fs.Keys, fileEntry{
			KeyID: e.KeyID, Algorithm: string(e.Algorithm), PublicKeyPEM: e.PublicKeyPEM, Packages: e.Packages,
		})
	}
	out, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func Save(path string, s *Store) error {
	data, err := s.Marshal()
	if err != nil {
		return apperr.Input("encode trust store: %v", err)
	}
	if _, err := Parse(data); err != nil {
		return apperr.Input("refusing to write an invalid trust store: %v", err)
	}
	if err := fsutil.WriteFileAtomic(path, data, 0o644, true); err != nil {
		return apperr.Input("write trust store: %v", err)
	}
	return nil
}
