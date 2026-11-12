package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grwna/osiris/internal/bundle"
	"github.com/grwna/osiris/internal/crypto"
	"github.com/grwna/osiris/internal/keygen"
	"github.com/grwna/osiris/internal/sign"
	"github.com/grwna/osiris/internal/trust"
)

var testKeys = map[crypto.Profile]string{
	crypto.RSAPSS:    "test-rsa",
	crypto.ECDSAP256: "test-ecdsa",
	crypto.Ed25519:   "test-ed25519",
}

func keyPath(prefix, ext string) string {
	return filepath.Join("..", "..", "tests", "keys", prefix+ext)
}

type fixture struct {
	t                      *testing.T
	dir, art, bundle, tstr string
	profile                crypto.Profile
	keyid                  string
}

func newFixture(t *testing.T, p crypto.Profile, content []byte) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, dir: dir, profile: p,
		art: filepath.Join(dir, "contoh-app.zip"), bundle: filepath.Join(dir, "contoh-app.bundle.json"),
		tstr: filepath.Join(dir, "trust.json")}
	must(t, os.WriteFile(f.art, content, 0o644))
	res, err := sign.Run(sign.Options{File: f.art, Package: "contoh-app", Version: "1.0.0",
		KeyPath: keyPath(testKeys[p], ".key.pem"), OutPath: f.bundle})
	must(t, err)
	f.keyid = res.KeyID
	f.trustKeys(map[string][]string{keyPath(testKeys[p], ".pub.pem"): {"contoh-app"}})
	return f
}

func (f *fixture) trustKeys(keys map[string][]string) {
	f.t.Helper()
	s := &trust.Store{}
	for path, pkgs := range keys {
		pem, err := os.ReadFile(path)
		must(f.t, err)
		_, err = s.Add(pem, pkgs)
		must(f.t, err)
	}
	must(f.t, trust.Save(f.tstr, s))
}

func (f *fixture) opts() Options {
	return Options{File: f.art, Bundle: f.bundle, TrustStore: f.tstr, Package: "contoh-app", Version: "1.0.0"}
}

func (f *fixture) run(mod func(o *Options)) *Result {
	o := f.opts()
	if mod != nil {
		mod(&o)
	}
	return Release(o)
}

func (f *fixture) parts() (M, sig []byte) {
	f.t.Helper()
	M, sig, err := bundle.ParseFile(f.bundle)
	must(f.t, err)
	return M, sig
}

func (f *fixture) writeBundle(M, sig []byte) {
	f.t.Helper()
	data, err := bundle.Marshal(M, sig)
	must(f.t, err)
	must(f.t, os.WriteFile(f.bundle, data, 0o644))
}

func (f *fixture) writeRaw(s string) {
	must(f.t, os.WriteFile(f.bundle, []byte(s), 0o644))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func expect(t *testing.T, r *Result, want Status) {
	t.Helper()
	if r.Status != want {
		t.Fatalf("status = %s (%s), want %s", r.Status, r.Message, want)
	}
	if r.Valid != (want == OK) {
		t.Fatalf("valid = %v for status %s", r.Valid, want)
	}
	wantExit := map[Status]int{OK: 0, InputError: 2}[want]
	if want != OK && want != InputError {
		wantExit = 1
	}
	if r.ExitCode() != wantExit {
		t.Fatalf("exit = %d, want %d", r.ExitCode(), wantExit)
	}
}

func forEachProfile(t *testing.T, fn func(t *testing.T, p crypto.Profile)) {
	for _, p := range crypto.Profiles {
		t.Run(string(p), func(t *testing.T) { fn(t, p) })
	}
}

func TestU01SignVerifyAllProfiles(t *testing.T) {
	contents := map[string][]byte{
		"text": []byte("hello release\r\nline 2\n"), "binary": {0, 0xff, 0x7f, 0x80, 0, 1}, "empty": {},
	}
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		for kind, c := range contents {
			f := newFixture(t, p, c)
			r := f.run(nil)
			if r.Status != OK {
				t.Fatalf("%s: %s %s", kind, r.Status, r.Message)
			}
			expect(t, r, OK)
			if *r.Algorithm != string(p) || *r.KeyID != f.keyid || *r.Package != "contoh-app" || *r.Version != "1.0.0" {
				t.Fatalf("%s: result fields wrong: %+v", kind, r)
			}
		}
	})
}

func TestU02ArtifactByteChanged(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		f := newFixture(t, p, []byte("hello release"))
		must(t, os.WriteFile(f.art, []byte("hellO release"), 0o644))
		r := f.run(nil)
		expect(t, r, ArtifactMismatch)
		if !strings.Contains(r.Message, "SHA-256") {
			t.Fatalf("message should name the hash: %s", r.Message)
		}
	})
}

func TestU03ArtifactSizeChanged(t *testing.T) {
	for name, content := range map[string]string{"append": "hello release!", "remove": "hello releas", "empty": ""} {
		f := newFixture(t, crypto.Ed25519, []byte("hello release"))
		must(t, os.WriteFile(f.art, []byte(content), 0o644))
		r := f.run(nil)
		expect(t, r, ArtifactMismatch)
		if !strings.Contains(r.Message, "size") {
			t.Fatalf("%s: message should name the size: %s", name, r.Message)
		}
	}
}

func TestU04ManifestChangedOldSignature(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		f := newFixture(t, p, []byte("x"))
		M, sig := f.parts()
		M2 := bytes.Replace(M, []byte(`"version":"1.0.0"`), []byte(`"version":"1.0.1"`), 1)
		f.writeBundle(M2, sig)
		expect(t, f.run(func(o *Options) { o.Version = "1.0.1" }), InvalidSignature)
		expect(t, f.run(nil), InvalidSignature)
	})
}

func TestU05SignatureBitFlip(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		for _, pos := range []int{0, p.SignatureLen() / 2, p.SignatureLen() - 1} {
			f := newFixture(t, p, []byte("x"))
			M, sig := f.parts()
			sig[pos] ^= 0x01
			f.writeBundle(M, sig)
			expect(t, f.run(nil), InvalidSignature)
		}
	})
}

func TestU06TrustStoreEmptyOrKeyRemoved(t *testing.T) {
	f := newFixture(t, crypto.ECDSAP256, []byte("x"))
	must(t, os.WriteFile(f.tstr, []byte(`{"schema":"minisign-trust/v1","keys":[]}`), 0o644))
	expect(t, f.run(nil), KeyNotTrusted)

	f = newFixture(t, crypto.Ed25519, []byte("x"))
	s, err := trust.Load(f.tstr)
	must(t, err)
	_, err = s.Remove(f.keyid, nil)
	must(t, err)
	must(t, trust.Save(f.tstr, s))
	expect(t, f.run(nil), KeyNotTrusted)
}

func TestU07KeyTrustedForOtherPackage(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		f := newFixture(t, p, []byte("x"))
		f.trustKeys(map[string][]string{keyPath(testKeys[p], ".pub.pem"): {"other-app", "contoh-app-extra"}})
		r := f.run(nil)
		expect(t, r, KeyNotTrusted)
		if !strings.Contains(r.Message, "package") {
			t.Fatalf("message: %s", r.Message)
		}
	})
}

func TestU08ExpectedVersionDiffers(t *testing.T) {
	f := newFixture(t, crypto.RSAPSS, []byte("x"))
	expect(t, f.run(func(o *Options) { o.Version = "1.0.1" }), MetadataMismatch)
	expect(t, f.run(func(o *Options) { o.Package = "other-app" }), MetadataMismatch)
}

func TestU09ArtifactRenamed(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		f := newFixture(t, p, []byte("x"))
		renamed := filepath.Join(f.dir, "contoh-app-v2.zip")
		must(t, os.Rename(f.art, renamed))
		r := f.run(func(o *Options) { o.File = renamed })
		expect(t, r, MetadataMismatch)
		if !strings.Contains(r.Message, "name") {
			t.Fatalf("message: %s", r.Message)
		}
	})
}

func TestU10FormatErrors(t *testing.T) {
	f := newFixture(t, crypto.Ed25519, []byte("x"))
	M, sig := f.parts()
	mb, sb := base64.StdEncoding.EncodeToString(M), base64.StdEncoding.EncodeToString(sig)
	reM := func(old, new string) string {
		if !bytes.Contains(M, []byte(old)) {
			t.Fatalf("manifest lacks %q", old)
		}
		m2 := bytes.Replace(M, []byte(old), []byte(new), 1)
		return `{"schema":"minisign-bundle/v1","manifest_b64":"` + base64.StdEncoding.EncodeToString(m2) + `","signature_b64":"` + sb + `"}`
	}
	big := `{"pad":"` + strings.Repeat("a", 17*1024) + `"}`
	cases := map[string]string{
		"bundle duplicate field":   `{"schema":"minisign-bundle/v1","manifest_b64":"` + mb + `","signature_b64":"` + sb + `","signature_b64":"` + sb + `"}`,
		"manifest duplicate field": reM(`"version":"1.0.0"`, `"version":"1.0.0","version":"1.0.0"`),
		"manifest size as string":  reM(`"size":1`, `"size":"1"`),
		"manifest size as bool":    reM(`"size":1`, `"size":true`),
		"manifest extra field":     reM(`"keyid"`, `"note":"x","keyid"`),
		"manifest null":            reM(`"version":"1.0.0"`, `"version":null`),
		"manifest not canonical":   reM(`"package":"contoh-app"`, `"package" : "contoh-app"`),
		"manifest over 16 KiB":     `{"schema":"minisign-bundle/v1","manifest_b64":"` + base64.StdEncoding.EncodeToString([]byte(big)) + `","signature_b64":"` + sb + `"}`,
		"bundle signature number":  `{"schema":"minisign-bundle/v1","manifest_b64":"` + mb + `","signature_b64":7}`,
		"base64 with newline":      `{"schema":"minisign-bundle/v1","manifest_b64":"` + mb[:10] + `\n` + mb[10:] + `","signature_b64":"` + sb + `"}`,
		"base64 without padding":   `{"schema":"minisign-bundle/v1","manifest_b64":"` + mb + `","signature_b64":"` + strings.TrimRight(sb, "=") + `"}`,
		"base64 bad alphabet":      `{"schema":"minisign-bundle/v1","manifest_b64":"` + mb + `","signature_b64":"` + strings.Replace(sb, sb[:1], "*", 1) + `"}`,
		"bundle wrong schema":      `{"schema":"cosign-bundle/v1","manifest_b64":"` + mb + `","signature_b64":"` + sb + `"}`,
		"bundle extra field":       `{"schema":"minisign-bundle/v1","manifest_b64":"` + mb + `","signature_b64":"` + sb + `","public_key_pem":"x"}`,
		"bundle not json":          `not json`,
		"bundle over 64 KiB":       `{"schema":"minisign-bundle/v1","manifest_b64":"` + mb + `","signature_b64":"` + sb + `"}` + strings.Repeat(" ", 64*1024),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			f.writeRaw(doc)
			r := f.run(nil)
			expect(t, r, FormatError)
			if r.Algorithm != nil || r.KeyID != nil || r.Package != nil || r.Version != nil {
				t.Fatalf("fields must be null before the manifest is read: %+v", r)
			}
		})
	}

	f.writeBundle(M, sig)
	for name, ts := range map[string]string{
		"truncated":    `{"schema":"minisign-trust/v1","keys":[`,
		"wrong schema": `{"schema":"x","keys":[]}`,
		"wildcard":     `{"schema":"minisign-trust/v1","keys":[{"keyid":"` + f.keyid + `","algorithm":"ed25519","public_key_pem":"x","packages":["*"]}]}`,
	} {
		must(t, os.WriteFile(f.tstr, []byte(ts), 0o644))
		if r := f.run(nil); r.Status != FormatError {
			t.Errorf("trust store %s: %s %s", name, r.Status, r.Message)
		}
	}
}

func TestU11UnsupportedAlgorithm(t *testing.T) {
	for _, alg := range []string{"rsa-pkcs1v15-sha256", "ed448", "ecdsa-p384-sha384", "RSA-PSS-SHA256", "none"} {
		f := newFixture(t, crypto.Ed25519, []byte("x"))
		M, sig := f.parts()
		f.writeBundle(bytes.Replace(M, []byte(`"algorithm":"ed25519"`), []byte(`"algorithm":"`+alg+`"`), 1), sig)
		r := f.run(nil)
		expect(t, r, UnsupportedAlgorithm)
		if r.Algorithm == nil || *r.Algorithm != alg {
			t.Fatalf("algorithm field should echo the manifest: %+v", r.Algorithm)
		}
	}
}

func TestU12UntrustedKeySameProfile(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		f := newFixture(t, p, []byte("x"))
		other, err := keygen.Run(keygen.Options{Algorithm: string(p), OutPrefix: filepath.Join(f.dir, "other")})
		must(t, err)
		_, err = sign.Run(sign.Options{File: f.art, Package: "contoh-app", Version: "1.0.0",
			KeyPath: other.PrivatePath, OutPath: f.bundle, Force: true})
		must(t, err)
		r := f.run(nil)
		expect(t, r, KeyNotTrusted)
		if *r.KeyID != other.KeyID {
			t.Fatalf("keyid = %s, want %s", *r.KeyID, other.KeyID)
		}
	})
}

func TestU13BundleLayoutIsFree(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		f := newFixture(t, p, []byte("x"))
		M, sig := f.parts()
		f.writeRaw("\r\n\t{\n  \"signature_b64\"\t:  \"" + base64.StdEncoding.EncodeToString(sig) + "\" ,\n\n" +
			"\"schema\":\"minisign-bundle/v1\",   \"manifest_b64\" :\"" + base64.StdEncoding.EncodeToString(M) + "\"\r\n}   \n")
		expect(t, f.run(nil), OK)
	})
}

func TestStopsAtFirstFailure(t *testing.T) {
	f := newFixture(t, crypto.Ed25519, []byte("hello"))
	must(t, os.WriteFile(f.art, []byte("HELLO"), 0o644))
	M, sig := f.parts()
	sig[0] ^= 1
	f.writeBundle(M, sig)
	expect(t, f.run(func(o *Options) { o.Version = "9.9.9" }), InvalidSignature)

	must(t, os.WriteFile(f.tstr, []byte(`{"schema":"minisign-trust/v1","keys":[]}`), 0o644))
	expect(t, f.run(nil), KeyNotTrusted)
}

func TestAlgorithmMustMatchTrustedKey(t *testing.T) {
	f := newFixture(t, crypto.Ed25519, []byte("x"))
	M, sig := f.parts()
	f.writeBundle(bytes.Replace(M, []byte(`"algorithm":"ed25519"`), []byte(`"algorithm":"ecdsa-p256-sha256"`), 1), sig)
	expect(t, f.run(nil), KeyNotTrusted)
}

func TestSignatureLengthAndECDSADomain(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		f := newFixture(t, p, []byte("x"))
		M, sig := f.parts()
		for name, bad := range map[string][]byte{
			"short": sig[:len(sig)-1], "long": append(append([]byte{}, sig...), 0), "empty": {},
			"zeros": make([]byte, len(sig)), "ones": bytes.Repeat([]byte{0xff}, len(sig)),
		} {
			f.writeBundle(M, bad)
			if r := f.run(nil); r.Status != InvalidSignature {
				t.Errorf("%s: %s %s", name, r.Status, r.Message)
			}
		}
	})
}

func TestInputErrors(t *testing.T) {
	f := newFixture(t, crypto.Ed25519, []byte("x"))
	missing := filepath.Join(f.dir, "missing")
	cases := map[string]func(o *Options){
		"no file":           func(o *Options) { o.File = "" },
		"no bundle":         func(o *Options) { o.Bundle = "" },
		"no trust store":    func(o *Options) { o.TrustStore = "" },
		"no package":        func(o *Options) { o.Package = "" },
		"no version":        func(o *Options) { o.Version = "" },
		"bad package":       func(o *Options) { o.Package = "Bad Package" },
		"artifact missing":  func(o *Options) { o.File = missing },
		"artifact is dir":   func(o *Options) { o.File = f.dir },
		"bundle missing":    func(o *Options) { o.Bundle = missing },
		"trust missing":     func(o *Options) { o.TrustStore = missing },
		"trust store a dir": func(o *Options) { o.TrustStore = f.dir },
	}
	for name, mod := range cases {
		r := f.run(mod)
		if r.Status != InputError || r.ExitCode() != 2 {
			t.Errorf("%s: %s exit %d (%s)", name, r.Status, r.ExitCode(), r.Message)
		}
	}
}

func TestVerifyNeverModifiesTrustStore(t *testing.T) {
	f := newFixture(t, crypto.Ed25519, []byte("x"))
	before, _ := os.ReadFile(f.tstr)
	f.run(nil)
	other, _ := keygen.Run(keygen.Options{Algorithm: "ed25519", OutPrefix: filepath.Join(f.dir, "o")})
	sign.Run(sign.Options{File: f.art, Package: "contoh-app", Version: "1.0.0", KeyPath: other.PrivatePath, OutPath: f.bundle, Force: true})
	expect(t, f.run(nil), KeyNotTrusted)
	after, _ := os.ReadFile(f.tstr)
	if !bytes.Equal(before, after) {
		t.Fatal("verify changed the trust store")
	}
}

func TestInteropFixturesFullVerify(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p crypto.Profile) {
		dir := t.TempDir()
		art := filepath.Join(dir, "interop.bin")
		must(t, os.WriteFile(art, []byte("interop artifact"), 0o644))
		f := &fixture{t: t, dir: dir, art: art, tstr: filepath.Join(dir, "trust.json"),
			bundle: filepath.Join("..", "..", "tests", "interop", "fixtures", string(p)+".json")}
		f.trustKeys(map[string][]string{keyPath(testKeys[p], ".pub.pem"): {"interop-app"}})
		r := Release(Options{File: art, Bundle: f.bundle, TrustStore: f.tstr, Package: "interop-app", Version: "1.0.0"})
		expect(t, r, OK)
	})
}

func TestResultJSON(t *testing.T) {
	r := &Result{Status: InputError, Message: "x"}
	line := r.MarshalLine()
	if bytes.Count(line, []byte("\n")) != 1 || line[len(line)-1] != '\n' {
		t.Fatalf("must be exactly one line: %q", line)
	}
	want := `{"valid":false,"status":"INPUT_ERROR","message":"x","algorithm":null,"keyid":null,"package":null,"version":null}` + "\n"
	if string(line) != want {
		t.Fatalf("got  %s\nwant %s", line, want)
	}
	var m map[string]any
	must(t, json.Unmarshal(line, &m))
	if len(m) != 7 {
		t.Fatalf("expected exactly 7 fields, got %v", m)
	}
}
