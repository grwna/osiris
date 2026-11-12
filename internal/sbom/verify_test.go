package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grwna/osiris/internal/sign"
	"github.com/grwna/osiris/internal/trust"
	"github.com/grwna/osiris/internal/verify"
)

type sbomFixture struct {
	t                                   *testing.T
	dir, art, bnd, sbom, sbomBnd, store string
	key                                 string
}

func newSBOMFixture(t *testing.T) *sbomFixture {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join("..", "..", "tests", "keys")
	f := &sbomFixture{t: t, dir: dir,
		art: filepath.Join(dir, "contoh-app.zip"), bnd: filepath.Join(dir, "contoh-app.bundle.json"),
		sbom: filepath.Join(dir, "sbom.json"), sbomBnd: filepath.Join(dir, "sbom.bundle.json"),
		store: filepath.Join(dir, "trust.json"), key: filepath.Join(keys, "test-ed25519.key.pem")}
	check(t, os.WriteFile(f.art, []byte("release bytes"), 0o644))
	_, err := sign.Run(sign.Options{File: f.art, Package: "contoh-app", Version: "1.0.0", KeyPath: f.key, OutPath: f.bnd})
	check(t, err)
	check(t, Generate(GenerateOptions{File: f.art, Package: "contoh-app", Version: "1.0.0", OutPath: f.sbom}))
	_, err = Sign(SignOptions{SBOMPath: f.sbom, ArtifactPath: f.art, Package: "contoh-app", Version: "1.0.0", KeyPath: f.key, OutPath: f.sbomBnd})
	check(t, err)
	pub, err := os.ReadFile(filepath.Join(keys, "test-ed25519.pub.pem"))
	check(t, err)
	s := &trust.Store{}
	_, err = s.Add(pub, []string{"contoh-app"})
	check(t, err)
	check(t, trust.Save(f.store, s))
	return f
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *sbomFixture) verify() *VerifyResult {
	return Verify(VerifyOptions{File: f.art, Bundle: f.bnd, SBOM: f.sbom, SBOMBundle: f.sbomBnd,
		TrustStore: f.store, Package: "contoh-app", Version: "1.0.0"})
}

func want(t *testing.T, r *VerifyResult, status verify.Status, target string) {
	t.Helper()
	if r.Status != status || r.Target != target || r.Valid != (status == verify.OK) {
		t.Fatalf("got %s/%s (%s), want %s/%s", r.Status, r.Target, r.Message, status, target)
	}
}

func TestSBOMVerifyOK(t *testing.T) {
	f := newSBOMFixture(t)
	r := f.verify()
	want(t, r, verify.OK, TargetBinding)
	line := string(r.MarshalLine())
	if !strings.HasSuffix(line, `"target":"binding"}`+"\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("json: %s", line)
	}
}

func TestSBOMModifiedAfterSigning(t *testing.T) {
	f := newSBOMFixture(t)
	data, _ := os.ReadFile(f.sbom)
	check(t, os.WriteFile(f.sbom, []byte(strings.Replace(string(data), `"version": 1`, `"version": 2`, 1)), 0o644))
	want(t, f.verify(), verify.ArtifactMismatch, TargetSBOM)
}

func TestSBOMReleaseArtifactReplaced(t *testing.T) {
	f := newSBOMFixture(t)
	check(t, os.WriteFile(f.art, []byte("evil bytes!!!"), 0o644))
	want(t, f.verify(), verify.ArtifactMismatch, TargetRelease)
}

func TestSBOMDoesNotReferenceArtifact(t *testing.T) {
	f := newSBOMFixture(t)
	check(t, os.WriteFile(f.art, []byte("release bytes v2"), 0o644))
	_, err := sign.Run(sign.Options{File: f.art, Package: "contoh-app", Version: "1.0.0", KeyPath: f.key, OutPath: f.bnd, Force: true})
	check(t, err)
	r := f.verify()
	want(t, r, verify.ArtifactMismatch, TargetBinding)
	if !strings.Contains(r.Message, "does not reference") {
		t.Fatalf("message: %s", r.Message)
	}
}

func TestSBOMInvalidJSONButSigned(t *testing.T) {
	f := newSBOMFixture(t)
	check(t, os.WriteFile(f.sbom, []byte(`{"a":"1","a":"2"}`), 0o644))
	_, err := sign.Run(sign.Options{File: f.sbom, Package: "contoh-app", Version: "1.0.0", KeyPath: f.key, OutPath: f.sbomBnd, Force: true})
	check(t, err)
	want(t, f.verify(), verify.FormatError, TargetBinding)
}

func TestSBOMVerifyInputAndTrust(t *testing.T) {
	f := newSBOMFixture(t)
	r := Verify(VerifyOptions{File: f.art, Bundle: f.bnd, TrustStore: f.store, Package: "contoh-app", Version: "1.0.0"})
	want(t, r, verify.InputError, TargetSBOM)
	check(t, os.WriteFile(f.store, []byte(`{"schema":"minisign-trust/v1","keys":[]}`), 0o644))
	want(t, f.verify(), verify.KeyNotTrusted, TargetRelease)
}
