package crypto

import "fmt"

type Profile string

const (
	RSAPSS    Profile = "rsa-pss-sha256"
	ECDSAP256 Profile = "ecdsa-p256-sha256"
	Ed25519   Profile = "ed25519"
)

const (
	RSAKeyBits        = 3072
	RSAPublicExponent = 65537
	RSASaltLen        = 32
	RSASigLen         = 384
	ECDSASigLen       = 64
	Ed25519SigLen     = 64
)

var Profiles = []Profile{RSAPSS, ECDSAP256, Ed25519}

func ParseProfile(s string) (Profile, error) {
	for _, p := range Profiles {
		if string(p) == s {
			return p, nil
		}
	}
	return "", fmt.Errorf("unsupported algorithm profile %q", s)
}

func (p Profile) SignatureLen() int {
	switch p {
	case RSAPSS:
		return RSASigLen
	case ECDSAP256:
		return ECDSASigLen
	case Ed25519:
		return Ed25519SigLen
	}
	return 0
}
