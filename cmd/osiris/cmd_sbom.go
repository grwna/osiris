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
  verify    --file <artifact> --bundle <release.bundle.json> --sbom <sbom.json>
            --sbom-bundle <sbom.bundle.json> --trust-store <trust.json>
            --package <name> --version <ver> [--json]
            verify both bundles and that the SBOM references the artifact SHA-256
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
		fs := newFlagSet("sbom verify", stderr)
		file := fs.String("file", "", "release artifact (required)")
		bnd := fs.String("bundle", "", "release bundle (required)")
		sb := fs.String("sbom", "", "SBOM file (required)")
		sbBnd := fs.String("sbom-bundle", "", "SBOM bundle (required)")
		store := fs.String("trust-store", "", "trust store path (required)")
		pkg := fs.String("package", "", "expected package name (required)")
		version := fs.String("version", "", "expected version (required)")
		asJSON := fs.Bool("json", false, "print the result as one JSON object on stdout")
		if code, done := parseFlags(fs, args[1:]); done {
			if code == exitOK {
				return code
			}
			return usageFailure(wantsJSON(args[1:]), stdout)
		}
		r := sbom.Verify(sbom.VerifyOptions{
			File: *file, Bundle: *bnd, SBOM: *sb, SBOMBundle: *sbBnd,
			TrustStore: *store, Package: *pkg, Version: *version,
		})
		if *asJSON {
			stdout.Write(r.MarshalLine())
			if !r.Valid {
				fmt.Fprintf(stderr, "%s (%s): %s\n", r.Status, r.Target, r.Message)
			}
		} else if r.Valid {
			fmt.Fprintf(stdout, "%s: %s\n", r.Status, r.Message)
		} else {
			fmt.Fprintf(stderr, "%s (%s): %s\n", r.Status, r.Target, r.Message)
		}
		return r.ExitCode()
	default:
		fmt.Fprintf(stderr, "error: unknown sbom command %q\n", args[0])
		return exitInput
	}
}
