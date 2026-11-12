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
	"errors"
	"fmt"
)

const (
	privPEMLabel = "PRIVATE KEY"
	pubPEMLabel  = "PUBLIC KEY"
)

func GenerateKey(p Profile) (privPEM, pubPEM []byte, keyid string, err error) {
	var priv stdcrypto.Signer
	switch p {
	case RSAPSS:
		priv, err = rsa.GenerateKey(rand.Reader, RSAKeyBits)
	case ECDSAP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case Ed25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, nil, "", fmt.Errorf("unsupported algorithm profile %q", p)
	}
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate %s key: %w", p, err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("encode private key: %w", err)
	}
	defer clear(privDER)
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, nil, "", fmt.Errorf("encode public key: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: privPEMLabel, Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: pubPEMLabel, Bytes: pubDER})
	return privPEM, pubPEM, KeyID(pubDER), nil
}

func KeyID(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return hex.EncodeToString(sum[:])
}

func PublicKeyID(pub stdcrypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("export public key: %w", err)
	}
	return KeyID(der), nil
}

func decodeSinglePEM(data []byte, label string) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != label {
		return nil, fmt.Errorf("unexpected PEM label %q (want %q)", block.Type, label)
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("PEM headers are not allowed (encrypted keys unsupported)")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("unexpected data after PEM block")
	}
	return block.Bytes, nil
}

func checkRSAPublic(k *rsa.PublicKey) error {
	if k.N.BitLen() != RSAKeyBits {
		return fmt.Errorf("RSA modulus must be %d bits, got %d", RSAKeyBits, k.N.BitLen())
	}
	if k.E != RSAPublicExponent {
		return fmt.Errorf("RSA public exponent must be %d, got %d", RSAPublicExponent, k.E)
	}
	return nil
}

func ParsePrivateKeyPEM(data []byte) (Profile, stdcrypto.Signer, error) {
	der, err := decodeSinglePEM(data, privPEMLabel)
	if err != nil {
		return "", nil, fmt.Errorf("private key: %w", err)
	}
	defer clear(der)
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", nil, fmt.Errorf("private key: invalid PKCS#8: %w", err)
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if err := checkRSAPublic(&k.PublicKey); err != nil {
			return "", nil, fmt.Errorf("private key: %w", err)
		}
		if err := k.Validate(); err != nil {
			return "", nil, fmt.Errorf("private key: %w", err)
		}
		return RSAPSS, k, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return "", nil, errors.New("private key: ECDSA curve must be NIST P-256")
		}
		return ECDSAP256, k, nil
	case ed25519.PrivateKey:
		return Ed25519, k, nil
	default:
		return "", nil, fmt.Errorf("private key: unsupported key type %T", key)
	}
}

func ParsePublicKeyPEM(data []byte) (Profile, stdcrypto.PublicKey, string, error) {
	der, err := decodeSinglePEM(data, pubPEMLabel)
	if err != nil {
		return "", nil, "", fmt.Errorf("public key: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", nil, "", fmt.Errorf("public key: invalid SPKI: %w", err)
	}
	var p Profile
	switch k := key.(type) {
	case *rsa.PublicKey:
		if err := checkRSAPublic(k); err != nil {
			return "", nil, "", fmt.Errorf("public key: %w", err)
		}
		p = RSAPSS
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", nil, "", errors.New("public key: ECDSA curve must be NIST P-256")
		}
		p = ECDSAP256
	case ed25519.PublicKey:
		p = Ed25519
	default:
		return "", nil, "", fmt.Errorf("public key: unsupported key type %T", key)
	}
	id, err := PublicKeyID(key)
	if err != nil {
		return "", nil, "", err
	}
	return p, key, id, nil
}
