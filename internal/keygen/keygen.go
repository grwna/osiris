package keygen

import (
	"fmt"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/crypto"
	"github.com/grwna/osiris/internal/fsutil"
)

type Options struct {
	Algorithm string
	OutPrefix string
	Force     bool
}

type Result struct {
	Profile     crypto.Profile
	KeyID       string
	PrivatePath string
	PublicPath  string
}

func Run(o Options) (*Result, error) {
	if o.Algorithm == "" {
		return nil, apperr.Input("missing required option --algorithm")
	}
	if o.OutPrefix == "" {
		return nil, apperr.Input("missing required option --out")
	}
	profile, err := crypto.ParseProfile(o.Algorithm)
	if err != nil {
		return nil, apperr.Input("%v (supported: rsa-pss-sha256, ecdsa-p256-sha256, ed25519)", err)
	}
	privPath := o.OutPrefix + ".key.pem"
	pubPath := o.OutPrefix + ".pub.pem"
	for _, p := range []string{privPath, pubPath} {
		if err := fsutil.CheckWritable(p, o.Force); err != nil {
			return nil, apperr.WrapInput(err)
		}
	}
	privPEM, pubPEM, keyid, err := crypto.GenerateKey(profile)
	if err != nil {
		return nil, apperr.WrapInput(err)
	}
	defer clear(privPEM)
	if err := fsutil.WriteFileAtomic(privPath, privPEM, 0o600, o.Force); err != nil {
		return nil, apperr.WrapInput(fmt.Errorf("write private key: %w", err))
	}
	if err := fsutil.WriteFileAtomic(pubPath, pubPEM, 0o644, o.Force); err != nil {
		return nil, apperr.WrapInput(fmt.Errorf("write public key: %w", err))
	}
	return &Result{Profile: profile, KeyID: keyid, PrivatePath: privPath, PublicPath: pubPath}, nil
}
