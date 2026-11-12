package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

var Version = "0.1.0-dev"

const (
	exitOK       = 0
	exitRejected = 1
	exitInput    = 2
)

const usageText = `osiris - sign and verify software releases

Usage:
  osiris <command> [options]

Commands:
  keygen        generate a key pair
  sign          sign an artifact and write a bundle
  verify        verify an artifact against a bundle and a trust store
  trust add     allow a public key to sign a package
  trust list    list trusted keys
  trust remove  remove a trusted key
  sbom          generate / sign / verify an SBOM (bonus)

Global options:
  --help        show help (also: <command> --help)
  --version     show program version

Profiles (--algorithm): rsa-pss-sha256, ecdsa-p256-sha256, ed25519

Examples:
  osiris keygen --algorithm ed25519 --out keys/release
  osiris trust add --store trust.json --key keys/release.pub.pem --package contoh-app
  osiris sign --file contoh-app.zip --package contoh-app --version 1.0.0 \
              --key keys/release.key.pem --out contoh-app.bundle.json
  osiris verify --file contoh-app.zip --bundle contoh-app.bundle.json \
                --trust-store trust.json --package contoh-app --version 1.0.0 --json

Exit codes: 0 success, 1 rejected (verification failed), 2 input/usage/I-O error.
verify statuses: OK, INPUT_ERROR, FORMAT_ERROR, UNSUPPORTED_ALGORITHM,
  KEY_NOT_TRUSTED, INVALID_SIGNATURE, METADATA_MISMATCH, ARTIFACT_MISMATCH
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitInput
	}
	switch args[0] {
	case "-help", "--help", "-h", "help":
		fmt.Fprint(stdout, usageText)
		return exitOK
	case "-version", "--version", "version":
		fmt.Fprintf(stdout, "osiris %s\n", Version)
		return exitOK
	case "keygen":
		return cmdKeygen(args[1:], stdout, stderr)
	case "sign":
		return cmdSign(args[1:], stdout, stderr)
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	case "trust":
		return cmdTrust(args[1:], stdout, stderr)
	case "sbom":
		return cmdSBOM(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n\n%s", args[0], usageText)
		return exitInput
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) (code int, done bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, true
		}
		return exitInput, true
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "error: unexpected argument %q\n", fs.Arg(0))
		return exitInput, true
	}
	return 0, false
}
