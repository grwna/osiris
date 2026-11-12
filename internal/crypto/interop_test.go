package crypto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalSignatures(t *testing.T) {
	fixtures := map[Profile]string{RSAPSS: "test-rsa", ECDSAP256: "test-ecdsa", Ed25519: "test-ed25519"}
	for p, prefix := range fixtures {
		path := filepath.Join("..", "..", "tests", "interop", "fixtures", string(p)+".json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("no fixtures (run: python3 tests/interop/interop.py make-fixtures): %v", err)
		}
		var b struct {
			Manifest  string `json:"manifest_b64"`
			Signature string `json:"signature_b64"`
		}
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		M, _ := base64.StdEncoding.DecodeString(b.Manifest)
		sig, _ := base64.StdEncoding.DecodeString(b.Signature)
		pubPEM, err := os.ReadFile(filepath.Join("..", "..", "tests", "keys", prefix+".pub.pem"))
		if err != nil {
			t.Fatal(err)
		}
		gotP, pub, _, err := ParsePublicKeyPEM(pubPEM)
		if err != nil || gotP != p {
			t.Fatalf("%s: %v", p, err)
		}
		if !Verify(p, pub, M, sig) {
			t.Fatalf("%s: signature by python-cryptography rejected", p)
		}
		M[0] ^= 1
		if Verify(p, pub, M, sig) {
			t.Fatalf("%s: tampered manifest accepted", p)
		}
	}
}
