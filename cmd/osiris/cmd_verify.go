package main

import (
	"fmt"
	"io"

	"github.com/grwna/osiris/internal/verify"
)

func wantsJSON(args []string) bool {
	for _, a := range args {
		switch a {
		case "-json", "--json", "-json=true", "--json=true":
			return true
		}
	}
	return false
}

func usageFailure(asJSON bool, stdout io.Writer) int {
	if asJSON {
		r := &verify.Result{Status: verify.InputError, Message: "invalid command line (see stderr)"}
		stdout.Write(r.MarshalLine())
	}
	return exitInput
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	file := fs.String("file", "", "artifact path (required)")
	bnd := fs.String("bundle", "", "bundle path (required)")
	store := fs.String("trust-store", "", "trust store path (required)")
	pkg := fs.String("package", "", "expected package name (required)")
	version := fs.String("version", "", "expected version (required)")
	asJSON := fs.Bool("json", false, "print the result as one JSON object on stdout")
	if code, done := parseFlags(fs, args); done {
		if code == exitOK {
			return code
		}
		return usageFailure(wantsJSON(args), stdout)
	}
	r := verify.Release(verify.Options{
		File: *file, Bundle: *bnd, TrustStore: *store, Package: *pkg, Version: *version,
	})
	if *asJSON {
		stdout.Write(r.MarshalLine())
		if !r.Valid {
			fmt.Fprintf(stderr, "%s: %s\n", r.Status, r.Message)
		}
	} else if r.Valid {
		fmt.Fprintf(stdout, "%s: %s\n", r.Status, r.Message)
	} else {
		fmt.Fprintf(stderr, "%s: %s\n", r.Status, r.Message)
	}
	return r.ExitCode()
}
