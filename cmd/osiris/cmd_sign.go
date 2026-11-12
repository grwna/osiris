package main

import (
	"fmt"
	"io"

	"github.com/grwna/osiris/internal/sign"
)

func cmdSign(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("sign", stderr)
	file := fs.String("file", "", "artifact path (required)")
	pkg := fs.String("package", "", "package name (required)")
	version := fs.String("version", "", "release version (required)")
	key := fs.String("key", "", "PKCS#8 PEM private key (required)")
	out := fs.String("out", "", "bundle output path (required)")
	force := fs.Bool("force", false, "overwrite an existing bundle file")
	if code, done := parseFlags(fs, args); done {
		return code
	}
	res, err := sign.Run(sign.Options{
		File: *file, Package: *pkg, Version: *version,
		KeyPath: *key, OutPath: *out, Force: *force,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInput
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	fmt.Fprintf(stderr, "signed with %s key %s\nbundle: %s\n", res.Profile, res.KeyID, res.Bundle)
	return exitOK
}
