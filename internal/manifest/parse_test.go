package manifest

import (
	"strings"
	"testing"

	"github.com/grwna/osiris/internal/crypto"
)

const (
	tKeyID = "cfdb5d3afdbc7f0a89126769789bf8ce161bc85a25b87efa5a47ecb04d16b05f"
	tSHA   = "bc84580ded6ffcf4b5fede8bf12ffc40f3fd781c7d11c77cb0fbde986e9ecc48"
)

func good(t *testing.T) []byte {
	t.Helper()
	M, err := Serialize(New("contoh-app", "1.0.0", crypto.Ed25519, tKeyID, "contoh-app.zip", 1234, tSHA))
	if err != nil {
		t.Fatal(err)
	}
	return M
}

func TestParseStrictRoundTrip(t *testing.T) {
	for _, p := range crypto.Profiles {
		for _, size := range []int64{0, 1, MaxArtifactSize} {
			m := New("contoh-app", "1.0.0-rc.1+build.5", p, tKeyID, "contoh-app_v1.tar.gz", size, tSHA)
			M, err := Serialize(m)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseStrict(M)
			if err != nil {
				t.Fatalf("%s/%d: %v", p, size, err)
			}
			if got != m {
				t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, m)
			}
		}
	}
}

func TestParseStrictUnknownAlgorithmIsNotFormatError(t *testing.T) {
	M := strings.Replace(string(good(t)), `"algorithm":"ed25519"`, `"algorithm":"rsa-pkcs1v15-sha256"`, 1)
	m, err := ParseStrict([]byte(M))
	if err != nil {
		t.Fatalf("unknown algorithm must parse (checked later as UNSUPPORTED_ALGORITHM): %v", err)
	}
	if m.Algorithm != "rsa-pkcs1v15-sha256" {
		t.Fatalf("algorithm = %q", m.Algorithm)
	}
}

func TestParseStrictRejects(t *testing.T) {
	M := string(good(t))
	rep := func(old, new string) string {
		if !strings.Contains(M, old) {
			t.Fatalf("fixture does not contain %q", old)
		}
		return strings.Replace(M, old, new, 1)
	}
	const bs = "\\"
	cases := map[string]string{
		"duplicate field":          rep(`"version":"1.0.0",`, `"version":"1.0.0","version":"1.0.0",`),
		"duplicate field escaped":  rep(`"version":"1.0.0",`, `"version":"1.0.0","`+bs+`u0076ersion":"1.0.0",`),
		"extra field":              rep(`"keyid"`, `"extra":"x","keyid"`),
		"extra artifact field":     rep(`"sha256"`, `"mode":"0644","sha256"`),
		"missing field":            rep(`"version":"1.0.0",`, ``),
		"null value":               rep(`"version":"1.0.0"`, `"version":null`),
		"size as string":           rep(`"size":1234`, `"size":"1234"`),
		"size as bool":             rep(`"size":1234`, `"size":true`),
		"size leading zero":        rep(`"size":1234`, `"size":01234`),
		"size fraction":            rep(`"size":1234`, `"size":1234.0`),
		"size exponent":            rep(`"size":1234`, `"size":1.234e3`),
		"size negative":            rep(`"size":1234`, `"size":-1`),
		"size above 2^53-1":        rep(`"size":1234`, `"size":9007199254740992`),
		"algorithm as number":      rep(`"algorithm":"ed25519"`, `"algorithm":1`),
		"empty algorithm":          rep(`"algorithm":"ed25519"`, `"algorithm":""`),
		"artifact as array":        rep(`"artifact":{"name":"contoh-app.zip","size":1234,"sha256":"`+tSHA+`"}`, `"artifact":[]`),
		"wrong schema":             rep(`minisign-manifest/v1`, `minisign-manifest/v2`),
		"bad package":              rep(`"package":"contoh-app"`, `"package":"Contoh-App"`),
		"bad version":              rep(`"version":"1.0.0"`, `"version":"-1"`),
		"uppercase keyid":          rep(tKeyID, strings.ToUpper(tKeyID)),
		"short sha":                rep(tSHA, tSHA[:63]),
		"bad name":                 rep(`"name":"contoh-app.zip"`, `"name":"../x.zip"`),
		"space after colon":        rep(`"package":"contoh-app"`, `"package": "contoh-app"`),
		"leading space":            " " + M,
		"trailing newline":         M + "\n",
		"reordered fields":         rep(`"package":"contoh-app","version":"1.0.0"`, `"version":"1.0.0","package":"contoh-app"`),
		"escaped char":             rep(`"package":"contoh-app"`, `"package":"contoh`+bs+`u002dapp"`),
		"escaped solidus":          rep(`minisign-manifest/v1`, `minisign-manifest`+bs+`/v1`),
		"non-ascii":                rep(`"version":"1.0.0"`, "\"version\":\"1.0.0é\""),
		"unicode escape non-ascii": rep(`"name":"contoh-app.zip"`, `"name":"contoh-app.zip`+bs+`u00e9"`),
		"trailing data":            M + "{}",
		"top-level array":          "[" + M + "]",
		"too large":                M[:len(M)-2] + `,"pad":"` + strings.Repeat("a", MaxSize) + `"}}`,
	}
	for name, in := range cases {
		if _, err := ParseStrict([]byte(in)); err == nil {
			t.Errorf("%s: accepted %q", name, in)
		}
	}
}
