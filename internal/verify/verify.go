package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/bundle"
	"github.com/grwna/osiris/internal/crypto"
	"github.com/grwna/osiris/internal/manifest"
	"github.com/grwna/osiris/internal/trust"
)

type Status string

const (
	OK                   Status = "OK"
	InputError           Status = "INPUT_ERROR"
	FormatError          Status = "FORMAT_ERROR"
	UnsupportedAlgorithm Status = "UNSUPPORTED_ALGORITHM"
	KeyNotTrusted        Status = "KEY_NOT_TRUSTED"
	InvalidSignature     Status = "INVALID_SIGNATURE"
	MetadataMismatch     Status = "METADATA_MISMATCH"
	ArtifactMismatch     Status = "ARTIFACT_MISMATCH"
)

const (
	ExitOK       = 0
	ExitRejected = 1
	ExitInput    = 2
)

func (s Status) ExitCode() int {
	switch s {
	case OK:
		return ExitOK
	case InputError:
		return ExitInput
	}
	return ExitRejected
}

type Options struct {
	File       string
	Bundle     string
	TrustStore string
	Package    string
	Version    string
}

type Result struct {
	Valid     bool    `json:"valid"`
	Status    Status  `json:"status"`
	Message   string  `json:"message"`
	Algorithm *string `json:"algorithm"`
	KeyID     *string `json:"keyid"`
	Package   *string `json:"package"`
	Version   *string `json:"version"`

	Manifest *manifest.Manifest `json:"-"`
}

func (r *Result) ExitCode() int { return r.Status.ExitCode() }

func (r *Result) MarshalLine() []byte {
	out, err := json.Marshal(r)
	if err != nil {
		out = []byte(`{"valid":false,"status":"INPUT_ERROR","message":"internal error encoding result","algorithm":null,"keyid":null,"package":null,"version":null}`)
	}
	return append(out, '\n')
}

func (r *Result) fail(s Status, format string, a ...any) *Result {
	r.Valid = false
	r.Status = s
	r.Message = fmt.Sprintf(format, a...)
	return r
}

func fromErr(r *Result, err error) *Result {
	if apperr.IsFormat(err) {
		return r.fail(FormatError, "%v", err)
	}
	return r.fail(InputError, "%v", err)
}

func strp(s string) *string { return &s }

func Release(o Options) *Result {
	r := &Result{}

	for _, req := range []struct{ name, val string }{
		{"--file", o.File}, {"--bundle", o.Bundle}, {"--trust-store", o.TrustStore},
		{"--package", o.Package}, {"--version", o.Version},
	} {
		if req.val == "" {
			return r.fail(InputError, "missing required option %s", req.name)
		}
	}
	if !manifest.PackagePattern.MatchString(o.Package) {
		return r.fail(InputError, "invalid --package %q: must match %s", o.Package, manifest.PackagePattern)
	}
	if !manifest.VersionPattern.MatchString(o.Version) {
		return r.fail(InputError, "invalid --version %q: must match %s", o.Version, manifest.VersionPattern)
	}
	fi, err := os.Stat(o.File)
	if err != nil {
		return r.fail(InputError, "read artifact: %v", err)
	}
	if !fi.Mode().IsRegular() {
		return r.fail(InputError, "read artifact: %s is not a regular file", o.File)
	}
	bundleData, err := bundle.ReadFile(o.Bundle)
	if err != nil {
		return fromErr(r, err)
	}
	store, err := trust.Load(o.TrustStore)
	if err != nil {
		return fromErr(r, err)
	}

	M, sig, err := bundle.Parse(bundleData)
	if err != nil {
		return fromErr(r, err)
	}

	m, err := manifest.ParseStrict(M)
	if err != nil {
		return r.fail(FormatError, "%v", err)
	}
	r.Manifest = &m
	r.Algorithm, r.KeyID, r.Package, r.Version = strp(m.Algorithm), strp(m.KeyID), strp(m.Package), strp(m.Version)

	profile, err := crypto.ParseProfile(m.Algorithm)
	if err != nil {
		return r.fail(UnsupportedAlgorithm, "algorithm %q is not supported (supported: rsa-pss-sha256, ecdsa-p256-sha256, ed25519)", m.Algorithm)
	}

	entry, ok := store.Lookup(m.KeyID)
	if !ok {
		return r.fail(KeyNotTrusted, "key %s is not in the trust store", m.KeyID)
	}
	if entry.Algorithm != profile {
		return r.fail(KeyNotTrusted, "key %s is trusted for algorithm %s, but the manifest declares %s", m.KeyID, entry.Algorithm, profile)
	}
	if !entry.Allows(m.Package) {
		return r.fail(KeyNotTrusted, "key %s is not trusted for package %q", m.KeyID, m.Package)
	}

	if !crypto.Verify(profile, entry.PublicKey, M, sig) {
		return r.fail(InvalidSignature, "%s signature does not verify with key %s", profile, m.KeyID)
	}

	if m.Package != o.Package {
		return r.fail(MetadataMismatch, "package mismatch: manifest has %q, expected %q", m.Package, o.Package)
	}
	if m.Version != o.Version {
		return r.fail(MetadataMismatch, "version mismatch: manifest has %q, expected %q", m.Version, o.Version)
	}
	if name := filepath.Base(o.File); name != m.Artifact.Name {
		return r.fail(MetadataMismatch, "artifact name mismatch: manifest has %q, file is %q", m.Artifact.Name, name)
	}

	size, sum, err := hashFile(o.File)
	if err != nil {
		return r.fail(InputError, "read artifact: %v", err)
	}
	if size != m.Artifact.Size {
		return r.fail(ArtifactMismatch, "artifact size mismatch: manifest has %d bytes, file has %d", m.Artifact.Size, size)
	}
	if sum != m.Artifact.SHA256 {
		return r.fail(ArtifactMismatch, "artifact SHA-256 mismatch: manifest has %s, file has %s", m.Artifact.SHA256, sum)
	}

	r.Valid = true
	r.Status = OK
	r.Message = fmt.Sprintf("%s %s (%s) verified with %s key %s", m.Package, m.Version, m.Artifact.Name, profile, m.KeyID)
	return r
}

func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}
