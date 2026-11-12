package sign

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/crypto"
	"github.com/grwna/osiris/internal/keygen"
)

func setup(t *testing.T, alg string, content []byte) (dir, art, key string, pubPEM []byte, keyid string) {
	t.Helper()
	dir = t.TempDir()
	res, err := keygen.Run(keygen.Options{Algorithm: alg, OutPrefix: filepath.Join(dir, "k")})
	if err != nil {
		t.Fatal(err)
	}
	art = filepath.Join(dir, "contoh-app.zip")
	if err := os.WriteFile(art, content, 0o644); err != nil {
		t.Fatal(err)
	}
	pubPEM, _ = os.ReadFile(res.PublicPath)
	return dir, art, res.PrivatePath, pubPEM, res.KeyID
}

func TestSignEndToEnd(t *testing.T) {
	contents := map[string][]byte{
		"text":   []byte("hello release\n"),
		"binary": {0x00, 0xff, 0x10, 0x80, 0x00},
		"empty":  {},
	}
	for _, p := range crypto.Profiles {
		for kind, content := range contents {
			t.Run(string(p)+"/"+kind, func(t *testing.T) {
				dir, art, key, pubPEM, keyid := setup(t, string(p), content)
				out := filepath.Join(dir, "release.json")
				res, err := Run(Options{File: art, Package: "contoh-app", Version: "1.0.0", KeyPath: key, OutPath: out})
				if err != nil {
					t.Fatal(err)
				}
				if res.KeyID != keyid || res.Profile != p {
					t.Fatalf("result mismatch: %+v", res)
				}
				raw, _ := os.ReadFile(out)
				var b struct{ Schema, Manifest_b64, Signature_b64 string }
				if err := json.Unmarshal(raw, &b); err != nil {
					t.Fatal(err)
				}
				if b.Schema != "minisign-bundle/v1" {
					t.Fatalf("schema %q", b.Schema)
				}
				M, err := base64.StdEncoding.DecodeString(b.Manifest_b64)
				if err != nil {
					t.Fatal(err)
				}
				sig, err := base64.StdEncoding.DecodeString(b.Signature_b64)
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(content)
				for _, want := range []string{
					`"algorithm":"` + string(p) + `"`, `"keyid":"` + keyid + `"`,
					`"sha256":"` + hex.EncodeToString(sum[:]) + `"`, `"name":"contoh-app.zip"`,
				} {
					if !strings.Contains(string(M), want) {
						t.Fatalf("manifest missing %s: %s", want, M)
					}
				}
				if bytes.Contains(raw, []byte("PRIVATE")) {
					t.Fatal("private key material in bundle")
				}
				_, pub, _, err := crypto.ParsePublicKeyPEM(pubPEM)
				if err != nil {
					t.Fatal(err)
				}
				if !crypto.Verify(p, pub, M, sig) {
					t.Fatal("bundle signature does not verify")
				}
				got, _ := os.ReadFile(art)
				if !bytes.Equal(got, content) {
					t.Fatal("artifact modified")
				}
			})
		}
	}
}

func TestSignInputErrors(t *testing.T) {
	dir, art, key, _, _ := setup(t, "ed25519", []byte("x"))
	out := filepath.Join(dir, "r.json")
	base := Options{File: art, Package: "contoh-app", Version: "1.0.0", KeyPath: key, OutPath: out}
	mut := map[string]func(o *Options){
		"missing file":     func(o *Options) { o.File = "" },
		"missing package":  func(o *Options) { o.Package = "" },
		"missing version":  func(o *Options) { o.Version = "" },
		"missing key":      func(o *Options) { o.KeyPath = "" },
		"missing out":      func(o *Options) { o.OutPath = "" },
		"bad package":      func(o *Options) { o.Package = "Bad Name" },
		"bad version":      func(o *Options) { o.Version = "../x" },
		"artifact missing": func(o *Options) { o.File = filepath.Join(dir, "nope.zip") },
		"artifact is dir":  func(o *Options) { o.File = dir },
		"key missing":      func(o *Options) { o.KeyPath = filepath.Join(dir, "nope.pem") },
		"key is pub":       func(o *Options) { o.KeyPath = filepath.Join(dir, "k.pub.pem") },
	}
	for name, f := range mut {
		o := base
		f(&o)
		_, err := Run(o)
		if err == nil || !apperr.IsInput(err) {
			t.Errorf("%s: want InputError, got %v", name, err)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("bundle written despite errors")
	}
}

func TestSignRefusesOverwriteWithoutForce(t *testing.T) {
	dir, art, key, _, _ := setup(t, "ed25519", []byte("x"))
	o := Options{File: art, Package: "p", Version: "1", KeyPath: key, OutPath: filepath.Join(dir, "r.json")}
	if _, err := Run(o); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(o); err == nil {
		t.Fatal("overwrote bundle without --force")
	}
	o.Force = true
	if _, err := Run(o); err != nil {
		t.Fatal(err)
	}
}

func TestKeygenOverwriteProtection(t *testing.T) {
	dir := t.TempDir()
	o := keygen.Options{Algorithm: "ed25519", OutPrefix: filepath.Join(dir, "k")}
	if _, err := keygen.Run(o); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "k.key.pem"))
	if _, err := keygen.Run(o); err == nil {
		t.Fatal("overwrote private key without --force")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "k.key.pem"))
	if !bytes.Equal(before, after) {
		t.Fatal("private key changed")
	}
	o.Force = true
	if _, err := keygen.Run(o); err != nil {
		t.Fatal(err)
	}
	if _, err := keygen.Run(keygen.Options{Algorithm: "rsa-1024", OutPrefix: filepath.Join(dir, "z")}); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
}
