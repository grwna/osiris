package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/keygen"
	"github.com/grwna/osiris/internal/sign"
)

const sum = "bc84580ded6ffcf4b5fede8bf12ffc40f3fd781c7d11c77cb0fbde986e9ecc48"

func TestReferences(t *testing.T) {
	cases := []struct {
		name, doc string
		want, err bool
	}{
		{"cyclonedx", `{"components":[{"hashes":[{"alg":"SHA-256","content":"` + sum + `"}]}]}`, true, false},
		{"spdx upper", `{"checksums":[{"algorithm":"SHA256","checksumValue":"` + strings.ToUpper(sum) + `"}]}`, true, false},
		{"absent", `{"a":"b","n":[1,2,{"x":null}]}`, false, false},
		{"hash only as key", `{"` + sum + `":"x"}`, false, false},
		{"duplicate key", `{"a":"1","a":"` + sum + `"}`, false, true},
		{"nested duplicate", `{"a":{"b":1,"b":2}}`, false, true},
		{"trailing data", `{"a":"` + sum + `"} {}`, false, true},
		{"array root", `["` + sum + `"]`, false, true},
		{"truncated", `{"a":`, false, true},
		{"empty", ``, false, true},
	}
	for _, c := range cases {
		got, err := References([]byte(c.doc), sum)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%s: got (%v, %v), want (%v, err=%v)", c.name, got, err, c.want, c.err)
		}
	}
}

func TestGenerateAndSign(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "app.zip")
	os.WriteFile(art, []byte("release bytes"), 0o644)
	other := filepath.Join(dir, "other.zip")
	os.WriteFile(other, []byte("different bytes"), 0o644)
	kr, err := keygen.Run(keygen.Options{Algorithm: "ed25519", OutPrefix: filepath.Join(dir, "k")})
	if err != nil {
		t.Fatal(err)
	}
	sb := filepath.Join(dir, "sbom.json")
	if err := Generate(GenerateOptions{File: art, Package: "app", Version: "1.0.0", OutPath: sb}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "sbom.bundle.json")
	opts := SignOptions{SBOMPath: sb, ArtifactPath: art, Package: "app", Version: "1.0.0", KeyPath: kr.PrivatePath, OutPath: out}
	res, err := Sign(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Manifest), `"name":"sbom.json"`) {
		t.Fatalf("SBOM must be signed as its own artifact: %s", res.Manifest)
	}
	_, wantSum, _ := sign.HashFile(sb)
	if !strings.Contains(string(res.Manifest), wantSum) {
		t.Fatal("manifest does not carry the SBOM hash")
	}

	opts.ArtifactPath = other
	opts.OutPath = filepath.Join(dir, "x.json")
	if _, err := Sign(opts); err == nil || !apperr.IsInput(err) {
		t.Fatalf("want InputError for unrelated artifact, got %v", err)
	}
	if _, err := os.Stat(opts.OutPath); err == nil {
		t.Fatal("bundle written for unrelated artifact")
	}
	os.WriteFile(sb, []byte(`{"bomFormat":"CycloneDX"}`), 0o644)
	opts.ArtifactPath = art
	if _, err := Sign(opts); err == nil {
		t.Fatal("SBOM without hash accepted")
	}
}
