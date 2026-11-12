package main

import (
	"fmt"
	"io"
)

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	fs.String("file", "", "artifact path (required)")
	fs.String("bundle", "", "bundle path (required)")
	fs.String("trust-store", "", "trust store path (required)")
	fs.String("package", "", "expected package name (required)")
	fs.String("version", "", "expected version (required)")
	fs.Bool("json", false, "print the result as JSON")
	if code, done := parseFlags(fs, args); done {
		return code
	}
	fmt.Fprintln(stderr, "error: verify is not implemented yet")
	return exitInput
}

func cmdTrust(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: osiris trust <add|list|remove> [options]")
		return exitInput
	}
	switch args[0] {
	case "-help", "--help", "-h":
		fmt.Fprintln(stdout, "usage: osiris trust <add|list|remove> [options]")
		return exitOK
	case "add":
		fs := newFlagSet("trust add", stderr)
		fs.String("key", "", "public key PEM (required)")
		fs.String("package", "", "package name to allow (required)")
		fs.String("store", "", "trust store path (required)")
		if code, done := parseFlags(fs, args[1:]); done {
			return code
		}
	case "list":
		fs := newFlagSet("trust list", stderr)
		fs.String("store", "", "trust store path (required)")
		if code, done := parseFlags(fs, args[1:]); done {
			return code
		}
	case "remove":
		fs := newFlagSet("trust remove", stderr)
		fs.String("keyid", "", "keyid to remove (required)")
		fs.String("store", "", "trust store path (required)")
		if code, done := parseFlags(fs, args[1:]); done {
			return code
		}
	default:
		fmt.Fprintf(stderr, "error: unknown trust command %q\n", args[0])
		return exitInput
	}
	fmt.Fprintf(stderr, "error: trust %s is not implemented yet\n", args[0])
	return exitInput
}
