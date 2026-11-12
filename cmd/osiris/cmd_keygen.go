package main

import (
	"fmt"
	"io"

	"github.com/grwna/osiris/internal/keygen"
)

func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("keygen", stderr)
	algorithm := fs.String("algorithm", "", "profile: rsa-pss-sha256 | ecdsa-p256-sha256 | ed25519 (required)")
	out := fs.String("out", "", "output prefix; writes <prefix>.key.pem and <prefix>.pub.pem (required)")
	force := fs.Bool("force", false, "overwrite existing key files")
	if code, done := parseFlags(fs, args); done {
		return code
	}
	res, err := keygen.Run(keygen.Options{Algorithm: *algorithm, OutPrefix: *out, Force: *force})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInput
	}
	fmt.Fprintf(stderr, "algorithm:   %s\nprivate key: %s\npublic key:  %s\n", res.Profile, res.PrivatePath, res.PublicPath)
	fmt.Fprintln(stdout, res.KeyID)
	return exitOK
}
