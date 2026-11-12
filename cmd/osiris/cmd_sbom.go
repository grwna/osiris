package main

import (
	"fmt"
	"io"

	"github.com/grwna/osiris/internal/sbom"
)

const sbomUsage = `usage: osiris sbom <generate|sign|verify> [options]

  generate  --file <artifact> --package <name> --version <ver> --out <sbom.json> [--force]
  sign      --sbom <sbom.json> --file <artifact> --package <name> --version <ver>
            --key <private.pem> --out <sbom.bundle.json> [--force]
  verify    (owned by B) verify release bundle + SBOM bundle and the SHA-256 binding
`

func cmdSBOM(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, sbomUsage)
		return exitInput
	}
	switch args[0] {
	case "-help", "--help", "-h":
		fmt.Fprint(stdout, sbomUsage)
		return exitOK
	case "generate":
		fs := newFlagSet("sbom generate", stderr)
		file := fs.String("file", "", "release artifact (required)")
		pkg := fs.String("package", "", "package name (required)")
		version := fs.String("version", "", "release version (required)")
		out := fs.String("out", "", "SBOM output path (required)")
		force := fs.Bool("force", false, "overwrite an existing SBOM")
		if code, done := parseFlags(fs, args[1:]); done {
			return code
		}
		if err := sbom.Generate(sbom.GenerateOptions{File: *file, Package: *pkg, Version: *version, OutPath: *out, Force: *force}); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitInput
		}
		fmt.Fprintf(stderr, "SBOM written: %s\n", *out)
		return exitOK
	case "sign":
		fs := newFlagSet("sbom sign", stderr)
		sb := fs.String("sbom", "", "SBOM JSON file to sign (required)")
		file := fs.String("file", "", "release artifact the SBOM must reference (required)")
		pkg := fs.String("package", "", "package name (required)")
		version := fs.String("version", "", "release version (required)")
		key := fs.String("key", "", "PKCS#8 PEM private key (required)")
		out := fs.String("out", "", "SBOM bundle output path (required)")
		force := fs.Bool("force", false, "overwrite an existing bundle")
		if code, done := parseFlags(fs, args[1:]); done {
			return code
		}
		res, err := sbom.Sign(sbom.SignOptions{
			SBOMPath: *sb, ArtifactPath: *file, Package: *pkg, Version: *version,
			KeyPath: *key, OutPath: *out, Force: *force,
		})
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitInput
		}
		for _, w := range res.Warnings {
			fmt.Fprintf(stderr, "warning: %s\n", w)
		}
		fmt.Fprintf(stderr, "SBOM signed with %s key %s\nbundle: %s\n", res.Profile, res.KeyID, res.Bundle)
		return exitOK
	case "verify":
		fmt.Fprintln(stderr, "error: sbom verify is not implemented yet")
		return exitInput
	default:
		fmt.Fprintf(stderr, "error: unknown sbom command %q\n", args[0])
		return exitInput
	}
}
