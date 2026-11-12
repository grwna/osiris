package trust

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/crypto"
)

const (
	edID  = "cfdb5d3afdbc7f0a89126769789bf8ce161bc85a25b87efa5a47ecb04d16b05f"
	rsaID = "f9abd441a6d76111b72ff4989d40de0b934d459010c3055fc8cf18a300851623"
	ecID  = "990c9a65aac1f5728d5333642ec6b27c211aa2f22a5a27654ed9532ff8d4408b"
)

func readKey(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "keys", name))
	if err != nil {
		t.Fatal(err)
	}

	return bytes.ReplaceAll(b, []byte("\r"), nil)
}

type rawEntry struct {
	KeyID        any `json:"keyid,omitempty"`
	Algorithm    any `json:"algorithm,omitempty"`
	PublicKeyPEM any `json:"public_key_pem,omitempty"`
	Packages     any `json:"packages,omitempty"`
}

func storeJSON(t *testing.T, entries ...rawEntry) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"schema": SchemaValue, "keys": entries})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func edEntry(t *testing.T) rawEntry {
	return rawEntry{edID, "ed25519", string(readKey(t, "test-ed25519.pub.pem")), []string{"contoh-app"}}
}

func TestParseValid(t *testing.T) {
	ed := edEntry(t)
	rsa := rawEntry{rsaID, "rsa-pss-sha256", string(readKey(t, "test-rsa.pub.pem")), []string{"a", "b.c"}}
	ec := rawEntry{ecID, "ecdsa-p256-sha256", string(readKey(t, "test-ecdsa.pub.pem")), []string{"x"}}
	s, err := Parse(storeJSON(t, ed, rsa, ec))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Keys) != 3 {
		t.Fatalf("got %d keys", len(s.Keys))
	}
	e, ok := s.Lookup(rsaID)
	if !ok || e.Algorithm != crypto.RSAPSS || !e.Allows("b.c") || e.Allows("c") || e.PublicKey == nil {
		t.Fatalf("rsa entry wrong: %+v", e)
	}
	if _, ok := s.Lookup(strings.ToUpper(edID)); ok {
		t.Fatal("lookup must be exact")
	}

	crlf := edEntry(t)
	crlf.PublicKeyPEM = strings.ReplaceAll(crlf.PublicKeyPEM.(string), "\n", "\r\n")
	if _, err := Parse(storeJSON(t, crlf)); err != nil {
		t.Fatalf("CRLF PEM rejected: %v", err)
	}

	if s, err := Parse([]byte(`{"schema":"minisign-trust/v1","keys":[]}`)); err != nil || len(s.Keys) != 0 {
		t.Fatalf("empty store: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	edPEM := string(readKey(t, "test-ed25519.pub.pem"))
	rsaPEM := string(readKey(t, "test-rsa.pub.pem"))
	mod := func(f func(e *rawEntry)) []byte {
		e := edEntry(t)
		f(&e)
		return storeJSON(t, e)
	}
	cases := map[string][]byte{
		"not json":             []byte(`schema: minisign-trust/v1`),
		"wrong schema":         []byte(`{"schema":"minisign-trust/v2","keys":[]}`),
		"missing keys":         []byte(`{"schema":"minisign-trust/v1"}`),
		"keys null":            []byte(`{"schema":"minisign-trust/v1","keys":null}`),
		"extra top field":      []byte(`{"schema":"minisign-trust/v1","keys":[],"auto_add":true}`),
		"duplicate top field":  []byte(`{"schema":"minisign-trust/v1","keys":[],"keys":[]}`),
		"entry not object":     []byte(`{"schema":"minisign-trust/v1","keys":["x"]}`),
		"duplicate keyid":      storeJSON(t, edEntry(t), edEntry(t)),
		"empty packages":       mod(func(e *rawEntry) { e.Packages = []string{} }),
		"missing packages":     mod(func(e *rawEntry) { e.Packages = nil }),
		"duplicate package":    mod(func(e *rawEntry) { e.Packages = []string{"a", "a"} }),
		"wildcard package":     mod(func(e *rawEntry) { e.Packages = []string{"*"} }),
		"glob package":         mod(func(e *rawEntry) { e.Packages = []string{"contoh-*"} }),
		"bad package":          mod(func(e *rawEntry) { e.Packages = []string{"Contoh App"} }),
		"package not string":   mod(func(e *rawEntry) { e.Packages = []any{1} }),
		"fingerprint mismatch": mod(func(e *rawEntry) { e.KeyID = rsaID }),
		"uppercase keyid":      mod(func(e *rawEntry) { e.KeyID = strings.ToUpper(edID) }),
		"algorithm vs key":     mod(func(e *rawEntry) { e.Algorithm = "rsa-pss-sha256" }),
		"unknown algorithm":    mod(func(e *rawEntry) { e.Algorithm = "ed448" }),
		"pem garbage":          mod(func(e *rawEntry) { e.PublicKeyPEM = "not a key" }),
		"private key pem":      mod(func(e *rawEntry) { e.PublicKeyPEM = string(readKey(t, "test-ed25519.key.pem")) }),
		"rsa pem in ed entry":  mod(func(e *rawEntry) { e.PublicKeyPEM = rsaPEM }),
		"two pem blocks":       mod(func(e *rawEntry) { e.PublicKeyPEM = edPEM + edPEM }),
		"keyid as number":      mod(func(e *rawEntry) { e.KeyID = 5 }),
		"too large":            append(storeJSON(t), bytes.Repeat([]byte(" "), MaxSize)...),
	}
	for name, data := range cases {
		_, err := Parse(data)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !apperr.IsFormat(err) {
			t.Errorf("%s: want FormatError, got %v", name, err)
		}
	}

	data := strings.Replace(string(storeJSON(t, edEntry(t))), `"keyid"`, `"comment":"x","keyid"`, 1)
	if _, err := Parse([]byte(data)); err == nil {
		t.Error("extra entry field accepted")
	}
}

func TestAddIdempotentAndMerge(t *testing.T) {
	s := &Store{}
	pub := readKey(t, "test-ed25519.pub.pem")
	r, err := s.Add(pub, []string{"contoh-app"})
	if err != nil || !r.Created || r.Entry.KeyID != edID {
		t.Fatalf("first add: %+v %v", r, err)
	}
	r, err = s.Add(pub, []string{"contoh-app"})
	if err != nil || r.Changed() {
		t.Fatalf("second add must be a no-op: %+v %v", r, err)
	}

	r, err = s.Add(bytes.ReplaceAll(pub, []byte("\n"), []byte("\r\n")), []string{"contoh-app", "other"})
	if err != nil || r.Created || len(r.AddedPackages) != 1 || r.AddedPackages[0] != "other" {
		t.Fatalf("merge: %+v %v", r, err)
	}
	if len(s.Keys) != 1 || strings.Join(s.Keys[0].Packages, ",") != "contoh-app,other" {
		t.Fatalf("store: %+v", s.Keys[0])
	}
	for name, tc := range map[string]struct {
		pem  []byte
		pkgs []string
	}{
		"no packages": {pub, nil},
		"wildcard":    {pub, []string{"*"}},
		"bad package": {pub, []string{"UPPER"}},
		"private key": {readKey(t, "test-ed25519.key.pem"), []string{"a"}},
		"garbage":     {[]byte("hello"), []string{"a"}},
	} {
		if _, err := s.Add(tc.pem, tc.pkgs); !apperr.IsInput(err) {
			t.Errorf("%s: want InputError, got %v", name, err)
		}
	}
}

func TestRemove(t *testing.T) {
	s := &Store{}
	s.Add(readKey(t, "test-ed25519.pub.pem"), []string{"a", "b"})
	s.Add(readKey(t, "test-rsa.pub.pem"), []string{"a"})
	if _, err := s.Remove(ecID, nil); !apperr.IsInput(err) {
		t.Fatalf("unknown keyid: %v", err)
	}
	if _, err := s.Remove(edID, []string{"zzz"}); !apperr.IsInput(err) {
		t.Fatalf("unknown package: %v", err)
	}
	removed, err := s.Remove(edID, []string{"a"})
	if err != nil || removed {
		t.Fatalf("partial revoke: %v %v", removed, err)
	}
	if e, _ := s.Lookup(edID); e.Allows("a") || !e.Allows("b") {
		t.Fatalf("after partial revoke: %+v", e.Packages)
	}
	removed, err = s.Remove(edID, []string{"b"})
	if err != nil || !removed {
		t.Fatalf("revoking last package must drop the entry: %v %v", removed, err)
	}
	removed, err = s.Remove(rsaID, nil)
	if err != nil || !removed || len(s.Keys) != 0 {
		t.Fatalf("remove: %v %v %d", removed, err, len(s.Keys))
	}
}

func TestSaveLoadRoundTripAndAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "trust.json")
	if _, err := Load(path); !apperr.IsInput(err) {
		t.Fatalf("missing store: want InputError, got %v", err)
	}
	s, existed, err := LoadOrEmpty(path)
	if err != nil || existed || len(s.Keys) != 0 {
		t.Fatalf("LoadOrEmpty: %v %v", existed, err)
	}
	s.Add(readKey(t, "test-ecdsa.pub.pem"), []string{"contoh-app"})
	s.Add(readKey(t, "test-rsa.pub.pem"), []string{"contoh-app", "lib"})
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || len(got.Keys) != 2 || got.Keys[0].KeyID != ecID || got.Keys[1].KeyID != rsaID {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}

	os.WriteFile(path, []byte(`{"schema":"minisign-trust/v1","keys":[`), 0o644)
	if _, _, err := LoadOrEmpty(path); !apperr.IsFormat(err) {
		t.Fatalf("damaged store: want FormatError, got %v", err)
	}
	if _, err := Load(dir); !apperr.IsInput(err) {
		t.Fatalf("directory: want InputError, got %v", err)
	}
}
