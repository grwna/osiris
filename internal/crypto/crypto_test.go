package crypto

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
)

type keyset struct {
	privPEM, pubPEM []byte
	keyid           string
}

var (
	cacheMu sync.Mutex
	cache   = map[Profile]keyset{}
)

func keys(t *testing.T, p Profile) keyset {
	t.Helper()
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if k, ok := cache[p]; ok {
		return k
	}
	priv, pub, id, err := GenerateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	k := keyset{priv, pub, id}
	cache[p] = k
	return k
}

func TestRoundTripAndSizes(t *testing.T) {
	msg := []byte(`{"hello":"world"}`)
	for _, p := range Profiles {
		t.Run(string(p), func(t *testing.T) {
			k := keys(t, p)
			gotP, priv, err := ParsePrivateKeyPEM(k.privPEM)
			if err != nil || gotP != p {
				t.Fatalf("parse private: %v %v", gotP, err)
			}
			pubP, pub, id, err := ParsePublicKeyPEM(k.pubPEM)
			if err != nil || pubP != p {
				t.Fatalf("parse public: %v %v", pubP, err)
			}
			if id != k.keyid {
				t.Fatalf("keyid mismatch %s vs %s", id, k.keyid)
			}
			sig, err := Sign(p, priv, msg)
			if err != nil {
				t.Fatal(err)
			}
			if len(sig) != p.SignatureLen() {
				t.Fatalf("sig len %d want %d", len(sig), p.SignatureLen())
			}
			if !Verify(p, pub, msg, sig) {
				t.Fatal("valid signature rejected")
			}
			if Verify(p, pub, append([]byte("x"), msg...), sig) {
				t.Fatal("signature accepted for other message")
			}
			bad := append([]byte(nil), sig...)
			bad[len(bad)-1] ^= 1
			if Verify(p, pub, msg, bad) {
				t.Fatal("bit-flipped signature accepted")
			}
			if Verify(p, pub, msg, sig[:len(sig)-1]) {
				t.Fatal("short signature accepted")
			}
		})
	}
}

func TestNoDoubleHashing(t *testing.T) {
	msg := []byte("manifest bytes")
	digest := sha256.Sum256(msg)

	_, rpriv, _ := ParsePrivateKeyPEM(keys(t, RSAPSS).privPEM)
	sig, _ := Sign(RSAPSS, rpriv, msg)
	rpub := &rpriv.(*rsa.PrivateKey).PublicKey
	if err := rsa.VerifyPSS(rpub, stdcrypto.SHA256, digest[:], sig,
		&rsa.PSSOptions{SaltLength: 32}); err != nil {
		t.Fatalf("rsa: %v", err)
	}
	if err := rsa.VerifyPSS(rpub, stdcrypto.SHA256, digest[:], sig,
		&rsa.PSSOptions{SaltLength: 20}); err == nil {
		t.Fatal("rsa signature does not use 32-byte salt")
	}

	_, epriv, _ := ParsePrivateKeyPEM(keys(t, ECDSAP256).privPEM)
	sig, _ = Sign(ECDSAP256, epriv, msg)
	der, err := RSToDER(sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&epriv.(*ecdsa.PrivateKey).PublicKey, digest[:], der) {
		t.Fatal("ecdsa: does not verify over single SHA-256")
	}

	_, opriv, _ := ParsePrivateKeyPEM(keys(t, Ed25519).privPEM)
	sig, _ = Sign(Ed25519, opriv, msg)
	if !ed25519.Verify(opriv.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("ed25519: does not verify over raw message")
	}
}

// RFC 8032 section 7.1, TEST 1
func TestEd25519RFC8032Vector(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	wantPub := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	wantSig := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
	priv := ed25519.NewKeyFromSeed(seed)
	if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != wantPub {
		t.Fatal("public key mismatch")
	}
	sig, err := Sign(Ed25519, priv, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sig) != wantSig {
		t.Fatalf("signature mismatch:\n got %x\nwant %s", sig, wantSig)
	}
}

func TestRSDERConversion(t *testing.T) {
	der := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}
	rs, err := DERToRS(der)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 64)
	want[31], want[63] = 1, 2
	if !bytes.Equal(rs, want) {
		t.Fatalf("got %x", rs)
	}
	back, err := RSToDER(rs)
	if err != nil || !bytes.Equal(back, der) {
		t.Fatalf("roundtrip %x %v", back, err)
	}
	rs2 := bytes.Repeat([]byte{0xff}, 64)
	der2, err := RSToDER(rs2)
	if err != nil {
		t.Fatal(err)
	}
	rs3, err := DERToRS(der2)
	if err != nil || !bytes.Equal(rs3, rs2) {
		t.Fatalf("high-bit roundtrip failed: %x %v", rs3, err)
	}
	if _, err := DERToRS(append(der, 0)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := RSToDER(rs[:63]); err == nil {
		t.Fatal("short r||s accepted")
	}
}

func TestECDSAOutOfRangeRS(t *testing.T) {
	_, pub, _, _ := ParsePublicKeyPEM(keys(t, ECDSAP256).pubPEM)
	zero := make([]byte, 64)
	if Verify(ECDSAP256, pub, []byte("m"), zero) {
		t.Fatal("r=s=0 accepted")
	}
	ff := bytes.Repeat([]byte{0xff}, 64)
	if Verify(ECDSAP256, pub, []byte("m"), ff) {
		t.Fatal("r,s >= n accepted")
	}
}

func TestKeyIDIgnoresPEMFormatting(t *testing.T) {
	k := keys(t, Ed25519)
	crlf := bytes.ReplaceAll(k.pubPEM, []byte("\n"), []byte("\r\n"))
	_, _, id, err := ParsePublicKeyPEM(crlf)
	if err != nil || id != k.keyid {
		t.Fatalf("CRLF: %v %s", err, id)
	}
	b, _ := pem.Decode(k.pubPEM)
	rewrapped := "-----BEGIN PUBLIC KEY-----\n"
	s := pem.EncodeToMemory(&pem.Block{Type: "X", Bytes: b.Bytes})
	lines := strings.Split(string(s), "\n")
	rewrapped += strings.Join(lines[1:len(lines)-2], "\n") + "\n-----END PUBLIC KEY-----\n"
	_, _, id2, err := ParsePublicKeyPEM([]byte(rewrapped))
	if err != nil || id2 != k.keyid {
		t.Fatalf("rewrapped: %v %s", err, id2)
	}
}

func TestKeyEncoding(t *testing.T) {
	for _, p := range Profiles {
		k := keys(t, p)
		if !bytes.HasPrefix(k.privPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
			t.Fatalf("%s: private PEM label", p)
		}
		if !bytes.HasPrefix(k.pubPEM, []byte("-----BEGIN PUBLIC KEY-----")) {
			t.Fatalf("%s: public PEM label", p)
		}
	}
	b, _ := pem.Decode(keys(t, Ed25519).pubPEM)
	if len(b.Bytes) != 44 {
		t.Fatalf("ed25519 SPKI len %d, want 44", len(b.Bytes))
	}
	b, _ = pem.Decode(keys(t, ECDSAP256).pubPEM)
	if len(b.Bytes) != 91 {
		t.Fatalf("p256 SPKI len %d, want 91", len(b.Bytes))
	}
}

func TestRejectWrongParameters(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(rk)
	if _, _, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("RSA-2048 private accepted")
	}
	pder, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if _, _, _, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pder})); err == nil {
		t.Fatal("RSA-2048 public accepted")
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalPKCS8PrivateKey(ek)
	if _, _, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("P-384 private accepted")
	}
	k := keys(t, Ed25519)
	if _, _, err := ParsePrivateKeyPEM(k.pubPEM); err == nil {
		t.Fatal("public PEM accepted as private")
	}
	if _, _, _, err := ParsePublicKeyPEM(append(append([]byte(nil), k.pubPEM...), k.pubPEM...)); err == nil {
		t.Fatal("two PEM blocks accepted")
	}
	if _, _, err := ParsePrivateKeyPEM([]byte("garbage")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestSignKeyProfileMismatch(t *testing.T) {
	_, priv, _ := ParsePrivateKeyPEM(keys(t, Ed25519).privPEM)
	if _, err := Sign(RSAPSS, priv, []byte("m")); err == nil {
		t.Fatal("profile/key mismatch accepted")
	}
	if _, err := Sign(Profile("nope"), priv, []byte("m")); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestSignatureDeterminism(t *testing.T) {
	msg := []byte("same manifest")
	for p, wantEqual := range map[Profile]bool{RSAPSS: false, ECDSAP256: false, Ed25519: true} {
		_, priv, _ := ParsePrivateKeyPEM(keys(t, p).privPEM)
		a, _ := Sign(p, priv, msg)
		b, _ := Sign(p, priv, msg)
		if bytes.Equal(a, b) != wantEqual {
			t.Fatalf("%s: identical=%v, want %v", p, bytes.Equal(a, b), wantEqual)
		}
	}
}
