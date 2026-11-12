package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

type ecdsaSig struct{ R, S *big.Int }

func Sign(p Profile, priv stdcrypto.Signer, M []byte) ([]byte, error) {
	var sig []byte
	switch p {
	case RSAPSS:
		k, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, keyMismatch(p, priv)
		}
		digest := sha256.Sum256(M)
		var err error
		sig, err = rsa.SignPSS(rand.Reader, k, stdcrypto.SHA256, digest[:],
			&rsa.PSSOptions{SaltLength: RSASaltLen, Hash: stdcrypto.SHA256})
		if err != nil {
			return nil, fmt.Errorf("rsa-pss sign: %w", err)
		}
	case ECDSAP256:
		k, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, keyMismatch(p, priv)
		}
		digest := sha256.Sum256(M)
		der, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil {
			return nil, fmt.Errorf("ecdsa sign: %w", err)
		}
		sig, err = DERToRS(der)
		if err != nil {
			return nil, err
		}
	case Ed25519:
		k, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, keyMismatch(p, priv)
		}
		sig = ed25519.Sign(k, M)
	default:
		return nil, fmt.Errorf("unsupported algorithm profile %q", p)
	}
	if len(sig) != p.SignatureLen() {
		return nil, fmt.Errorf("unexpected %s signature length %d (want %d)", p, len(sig), p.SignatureLen())
	}
	return sig, nil
}

func Verify(p Profile, pub stdcrypto.PublicKey, M, sig []byte) bool {
	if len(sig) != p.SignatureLen() {
		return false
	}
	switch p {
	case RSAPSS:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		digest := sha256.Sum256(M)
		return rsa.VerifyPSS(k, stdcrypto.SHA256, digest[:], sig,
			&rsa.PSSOptions{SaltLength: RSASaltLen, Hash: stdcrypto.SHA256}) == nil
	case ECDSAP256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		der, err := RSToDER(sig)
		if err != nil {
			return false
		}
		digest := sha256.Sum256(M)
		return ecdsa.VerifyASN1(k, digest[:], der)
	case Ed25519:
		k, ok := pub.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(k, M, sig)
	}
	return false
}

func DERToRS(der []byte) ([]byte, error) {
	var s ecdsaSig
	rest, err := asn1.Unmarshal(der, &s)
	if err != nil {
		return nil, fmt.Errorf("decode ECDSA DER signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after ECDSA DER signature")
	}
	if s.R == nil || s.S == nil || s.R.Sign() < 0 || s.S.Sign() < 0 ||
		s.R.BitLen() > 256 || s.S.BitLen() > 256 {
		return nil, errors.New("ECDSA r/s out of range")
	}
	out := make([]byte, ECDSASigLen)
	s.R.FillBytes(out[:32])
	s.S.FillBytes(out[32:])
	return out, nil
}

func RSToDER(rs []byte) ([]byte, error) {
	if len(rs) != ECDSASigLen {
		return nil, fmt.Errorf("ECDSA signature must be %d bytes, got %d", ECDSASigLen, len(rs))
	}
	r := new(big.Int).SetBytes(rs[:32])
	s := new(big.Int).SetBytes(rs[32:])
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}

func keyMismatch(p Profile, k stdcrypto.Signer) error {
	return fmt.Errorf("private key type %T does not match profile %s", k, p)
}
