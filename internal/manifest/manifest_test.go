package manifest

import (
	"strings"
	"testing"

	"github.com/grwna/osiris/internal/crypto"
)

const (
	hex64a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hex64b = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestSerializeGolden(t *testing.T) {
	m := New("contoh-app", "1.0.0", crypto.Ed25519, hex64a, "contoh-app.zip", 1048576, hex64b)
	got, err := Serialize(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"minisign-manifest/v1","package":"contoh-app","version":"1.0.0",` +
		`"algorithm":"ed25519","keyid":"` + hex64a + `","artifact":{"name":"contoh-app.zip",` +
		`"size":1048576,"sha256":"` + hex64b + `"}}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if strings.ContainsAny(string(got), " \n\r\t") {
		t.Fatal("whitespace in canonical manifest")
	}
}

func TestSerializeEdgeSizes(t *testing.T) {
	for size, want := range map[int64]string{0: `"size":0,`, MaxArtifactSize: `"size":9007199254740991,`} {
		m := New("p", "1", crypto.Ed25519, hex64a, "f", size, hex64b)
		got, err := Serialize(m)
		if err != nil || !strings.Contains(string(got), want) {
			t.Fatalf("size %d: %s %v", size, got, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	ok := New("contoh-app", "1.0.0", crypto.RSAPSS, hex64a, "a.zip", 1, hex64b)
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(m *Manifest){
		"schema":         func(m *Manifest) { m.Schema = "x" },
		"uppercase pkg":  func(m *Manifest) { m.Package = "Contoh" },
		"empty pkg":      func(m *Manifest) { m.Package = "" },
		"long pkg":       func(m *Manifest) { m.Package = strings.Repeat("a", 65) },
		"bad version":    func(m *Manifest) { m.Version = "-1" },
		"quote version":  func(m *Manifest) { m.Version = `1"0` },
		"algorithm":      func(m *Manifest) { m.Algorithm = "rsa" },
		"keyid upper":    func(m *Manifest) { m.KeyID = strings.ToUpper(hex64a) },
		"keyid short":    func(m *Manifest) { m.KeyID = "abc" },
		"name dir":       func(m *Manifest) { m.Artifact.Name = "d/a.zip" },
		"name non-ascii": func(m *Manifest) { m.Artifact.Name = "é.zip" },
		"neg size":       func(m *Manifest) { m.Artifact.Size = -1 },
		"huge size":      func(m *Manifest) { m.Artifact.Size = MaxArtifactSize + 1 },
		"sha upper":      func(m *Manifest) { m.Artifact.SHA256 = strings.ToUpper(hex64b) },
	}
	for name, mut := range cases {
		m := ok
		mut(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
		if _, err := Serialize(m); err == nil {
			t.Errorf("%s: Serialize accepted invalid manifest", name)
		}
	}
}
