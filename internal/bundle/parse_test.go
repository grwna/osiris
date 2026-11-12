package bundle

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grwna/osiris/internal/apperr"
)

func TestDecodeBase64Strict(t *testing.T) {
	ok := map[string]string{"": "", "QQ==": "A", "QUI=": "AB", "QUJD": "ABC", "+/+/": "\xfb\xff\xbf"}
	for in, want := range ok {
		got, err := DecodeBase64Strict(in)
		if err != nil || string(got) != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	bad := []string{
		"QQ", "QQ=", "QQ===", "Q===",
		"QR==",
		"QUI=QUI=",
		"QU I=", "QUI=\n", "\tQUI=", "QU\r\nI=",
		"QUI_", "QUI-", "QUI!", "QUI\x00", "QUé",
	}
	for _, in := range bad {
		if _, err := DecodeBase64Strict(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func doc(m, s string) string {
	return `{"schema":"minisign-bundle/v1","manifest_b64":"` + m + `","signature_b64":"` + s + `"}`
}

func TestParseAcceptsWriterOutputAndFreeLayout(t *testing.T) {
	M, sig := []byte(`{"a":1}`), bytes.Repeat([]byte{0xab}, 64)
	data, err := Marshal(M, sig)
	if err != nil {
		t.Fatal(err)
	}
	gotM, gotS, err := Parse(data)
	if err != nil || !bytes.Equal(gotM, M) || !bytes.Equal(gotS, sig) {
		t.Fatalf("writer output rejected: %v", err)
	}
	mb, sb := base64.StdEncoding.EncodeToString(M), base64.StdEncoding.EncodeToString(sig)
	reordered := "\n\t{ \"signature_b64\" :\r\n \"" + sb + "\",\n\n  \"manifest_b64\":\"" + mb + "\" ,\"schema\":   \"minisign-bundle/v1\"\n}\n\n"
	gotM, gotS, err = Parse([]byte(reordered))
	if err != nil || !bytes.Equal(gotM, M) || !bytes.Equal(gotS, sig) {
		t.Fatalf("reordered/whitespace bundle rejected: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	m, s := base64.StdEncoding.EncodeToString([]byte("M")), base64.StdEncoding.EncodeToString([]byte("S"))
	cases := map[string]string{
		"duplicate field":   `{"schema":"minisign-bundle/v1","manifest_b64":"` + m + `","manifest_b64":"` + m + `","signature_b64":"` + s + `"}`,
		"extra field":       `{"schema":"minisign-bundle/v1","manifest_b64":"` + m + `","signature_b64":"` + s + `","public_key":"x"}`,
		"missing signature": `{"schema":"minisign-bundle/v1","manifest_b64":"` + m + `"}`,
		"null signature":    `{"schema":"minisign-bundle/v1","manifest_b64":"` + m + `","signature_b64":null}`,
		"number signature":  `{"schema":"minisign-bundle/v1","manifest_b64":"` + m + `","signature_b64":5}`,
		"wrong schema":      `{"schema":"minisign-bundle/v2","manifest_b64":"` + m + `","signature_b64":"` + s + `"}`,
		"schema as bool":    `{"schema":true,"manifest_b64":"` + m + `","signature_b64":"` + s + `"}`,
		"b64 whitespace":    doc(m[:2]+" "+m[2:], s),
		"b64 newline":       doc(m, s[:2]+`\n`+s[2:]),
		"b64 bad padding":   doc(strings.TrimRight(m, "="), s),
		"b64 urlsafe":       doc(m, "-_-_"),
		"b64 noncanonical":  doc("QR==", s),
		"top-level array":   `[` + doc(m, s) + `]`,
		"trailing data":     doc(m, s) + `{}`,
		"not json":          `schema=minisign-bundle/v1`,
		"too large":         doc(m, s) + strings.Repeat(" ", MaxSize),
	}
	for name, in := range cases {
		_, _, err := Parse([]byte(in))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !apperr.IsFormat(err) {
			t.Errorf("%s: want FormatError, got %T %v", name, err, err)
		}
	}
}

func TestReadFileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadFile(filepath.Join(dir, "missing.json")); !apperr.IsInput(err) {
		t.Errorf("missing file: want InputError, got %v", err)
	}
	if _, err := ReadFile(dir); !apperr.IsInput(err) {
		t.Errorf("directory: want InputError, got %v", err)
	}
	big := filepath.Join(dir, "big.json")
	os.WriteFile(big, bytes.Repeat([]byte(" "), MaxSize+1), 0o644)
	if _, err := ReadFile(big); !apperr.IsFormat(err) {
		t.Errorf("oversized: want FormatError, got %v", err)
	}
}
