package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var keysDir = filepath.Join("..", "..", "tests", "keys")

func runCLI(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

func decodeLine(t *testing.T, out string) map[string]any {
	t.Helper()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "}\n") {
		t.Fatalf("stdout must be one JSON object + one newline, got %q", out)
	}
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("stdout is not JSON: %v (%q)", err, out)
	}
	for _, k := range []string{"valid", "status", "message", "algorithm", "keyid", "package", "version"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing field %q in %s", k, out)
		}
	}
	return m
}

type env struct {
	dir, art, bnd, store string
}

func setup(t *testing.T) env {
	t.Helper()
	dir := t.TempDir()
	e := env{dir, filepath.Join(dir, "contoh-app.zip"), filepath.Join(dir, "b.json"), filepath.Join(dir, "trust.json")}
	os.WriteFile(e.art, []byte("artifact"), 0o644)
	if code, _, se := runCLI("trust", "add", "--store", e.store, "--key", filepath.Join(keysDir, "test-ecdsa.pub.pem"), "--package", "contoh-app"); code != 0 {
		t.Fatalf("trust add: %d %s", code, se)
	}
	if code, _, se := runCLI("sign", "--file", e.art, "--package", "contoh-app", "--version", "1.0.0",
		"--key", filepath.Join(keysDir, "test-ecdsa.key.pem"), "--out", e.bnd); code != 0 {
		t.Fatalf("sign: %d %s", code, se)
	}
	return e
}

func (e env) verify(extra ...string) (int, string, string) {
	args := append([]string{"verify", "--file", e.art, "--bundle", e.bnd, "--trust-store", e.store,
		"--package", "contoh-app", "--version", "1.0.0"}, extra...)
	return runCLI(args...)
}

func TestVerifyJSONContract(t *testing.T) {
	e := setup(t)
	for _, flag := range []string{"-json", "--json"} {
		code, out, errOut := e.verify(flag)
		m := decodeLine(t, out)
		if code != 0 || m["valid"] != true || m["status"] != "OK" || m["algorithm"] != "ecdsa-p256-sha256" {
			t.Fatalf("%s: code %d %v", flag, code, m)
		}
		if errOut != "" {
			t.Fatalf("stderr must be empty on success with --json, got %q", errOut)
		}
	}
	code, out, errOut := runCLI("verify", "--file", e.art, "--bundle", e.bnd, "--trust-store", e.store,
		"--package", "contoh-app", "--version", "2.0.0", "-json")
	m := decodeLine(t, out)
	if code != 1 || m["status"] != "METADATA_MISMATCH" || m["valid"] != false || !strings.Contains(errOut, "METADATA_MISMATCH") {
		t.Fatalf("mismatch: %d %v %q", code, m, errOut)
	}
}

func TestVerifyJSONInputErrors(t *testing.T) {
	e := setup(t)
	cases := [][]string{
		{"verify", "-json"},
		{"verify", "-json", "--file", filepath.Join(e.dir, "nope"), "--bundle", e.bnd, "--trust-store", e.store, "--package", "contoh-app", "--version", "1.0.0"},
		{"verify", "--unknown-flag", "--json"},
		{"verify", "--json", "positional"},
	}
	for _, args := range cases {
		code, out, _ := runCLI(args...)
		m := decodeLine(t, out)
		if code != 2 || m["status"] != "INPUT_ERROR" || m["algorithm"] != nil {
			t.Errorf("%v: code %d %v", args, code, m)
		}
	}
}

func TestVerifyWithoutJSON(t *testing.T) {
	e := setup(t)
	code, out, _ := e.verify()
	if code != 0 || !strings.HasPrefix(out, "OK:") {
		t.Fatalf("%d %q", code, out)
	}
	os.WriteFile(e.art, []byte("artifacT"), 0o644)
	code, out, errOut := e.verify()
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "ARTIFACT_MISMATCH:") {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
}

func TestTrustCommands(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "trust.json")
	pub := filepath.Join(keysDir, "test-ed25519.pub.pem")
	const edID = "cfdb5d3afdbc7f0a89126769789bf8ce161bc85a25b87efa5a47ecb04d16b05f"

	code, out, _ := runCLI("trust", "add", "--store", store, "--key", pub, "--package", "a")
	if code != 0 || !strings.Contains(out, edID) || !strings.Contains(out, "ed25519") || !strings.Contains(out, "added") {
		t.Fatalf("add: %d %q", code, out)
	}
	before, _ := os.ReadFile(store)
	code, out, _ = runCLI("trust", "add", "--store", store, "--key", pub, "--package", "a")
	after, _ := os.ReadFile(store)
	if code != 0 || !strings.Contains(out, "unchanged") || !bytes.Equal(before, after) {
		t.Fatalf("idempotent add: %d %q", code, out)
	}
	code, out, _ = runCLI("trust", "add", "--store", store, "--key", pub, "--package", "b", "--package", "c")
	if code != 0 || !strings.Contains(out, "a, b, c") {
		t.Fatalf("merge add: %d %q", code, out)
	}
	code, _, _ = runCLI("trust", "add", "--store", store, "--key", filepath.Join(keysDir, "test-rsa.pub.pem"),
		"--package", "a", "--expect-keyid", edID)
	if code != 2 {
		t.Fatalf("expect-keyid mismatch must fail with 2, got %d", code)
	}
	code, out, _ = runCLI("trust", "list", "--store", store)
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.Contains(out, "a,b,c") {
		t.Fatalf("list (rsa key must not have been added): %d %q", code, out)
	}
	code, out, _ = runCLI("trust", "list", "--store", store, "--json")
	if code != 0 || !json.Valid([]byte(out)) {
		t.Fatalf("list --json: %d %q", code, out)
	}
	for name, args := range map[string][]string{
		"wildcard":        {"trust", "add", "--store", store, "--key", pub, "--package", "*"},
		"private key":     {"trust", "add", "--store", store, "--key", filepath.Join(keysDir, "test-ed25519.key.pem"), "--package", "a"},
		"no package":      {"trust", "add", "--store", store, "--key", pub},
		"remove unknown":  {"trust", "remove", "--store", store, "--keyid", strings.Repeat("0", 64)},
		"remove bad id":   {"trust", "remove", "--store", store, "--keyid", "xyz"},
		"list missing":    {"trust", "list", "--store", filepath.Join(dir, "missing.json")},
		"unknown command": {"trust", "frobnicate"},
	} {
		if code, _, _ := runCLI(args...); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
	if code, _, _ := runCLI("trust", "remove", "--store", store, "--keyid", strings.ToUpper(edID), "--package", "b"); code != 0 {
		t.Fatalf("partial remove: %d", code)
	}
	if code, _, _ := runCLI("trust", "remove", "--store", store, "--keyid", edID); code != 0 {
		t.Fatalf("remove: %d", code)
	}
	if code, _, _ := runCLI("trust", "remove", "--store", store, "--keyid", edID); code != 2 {
		t.Fatalf("second remove must be exit 2, got %d", code)
	}

	os.WriteFile(store, []byte("{broken"), 0o644)
	if code, _, _ := runCLI("trust", "add", "--store", store, "--key", pub, "--package", "a"); code != 1 {
		t.Fatalf("damaged store add: %d", code)
	}
	if b, _ := os.ReadFile(store); string(b) != "{broken" {
		t.Fatal("damaged store was overwritten")
	}
}

func TestHelpAndVersion(t *testing.T) {
	for _, a := range []string{"-help", "--help", "-h"} {
		if code, out, _ := runCLI(a); code != 0 || !strings.Contains(out, "verify") {
			t.Fatalf("%s: %d", a, code)
		}
	}
	for _, a := range []string{"-version", "--version"} {
		if code, out, _ := runCLI(a); code != 0 || !strings.HasPrefix(out, "osiris ") {
			t.Fatalf("%s: %d %q", a, code, out)
		}
	}
	for _, args := range [][]string{{"verify", "-help"}, {"trust", "--help"}, {"trust", "add", "-help"}, {"sbom", "verify", "-help"}} {
		if code, _, _ := runCLI(args...); code != 0 {
			t.Fatalf("%v: %d", args, code)
		}
	}
	if code, _, _ := runCLI(); code != 2 {
		t.Fatal("no args must be exit 2")
	}
	if code, _, _ := runCLI("bogus"); code != 2 {
		t.Fatal("unknown command must be exit 2")
	}
}

func TestSBOMVerifyCLI(t *testing.T) {
	e := setup(t)
	sb, sbb := filepath.Join(e.dir, "sbom.json"), filepath.Join(e.dir, "sbom.bundle.json")
	if code, _, se := runCLI("sbom", "generate", "--file", e.art, "--package", "contoh-app", "--version", "1.0.0", "--out", sb); code != 0 {
		t.Fatal(se)
	}
	if code, _, se := runCLI("sbom", "sign", "--sbom", sb, "--file", e.art, "--package", "contoh-app", "--version", "1.0.0",
		"--key", filepath.Join(keysDir, "test-ecdsa.key.pem"), "--out", sbb); code != 0 {
		t.Fatal(se)
	}
	base := []string{"sbom", "verify", "--file", e.art, "--bundle", e.bnd, "--sbom", sb, "--sbom-bundle", sbb,
		"--trust-store", e.store, "--package", "contoh-app", "--version", "1.0.0", "--json"}
	code, out, _ := runCLI(base...)
	m := decodeLine(t, out)
	if code != 0 || m["status"] != "OK" || m["target"] != "binding" {
		t.Fatalf("%d %v", code, m)
	}
	os.WriteFile(sb, []byte(`{"tampered":true}`), 0o644)
	code, out, _ = runCLI(base...)
	m = decodeLine(t, out)
	if code != 1 || m["status"] != "ARTIFACT_MISMATCH" || m["target"] != "sbom" {
		t.Fatalf("%d %v", code, m)
	}
}
