package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/grwna/osiris/internal/verify"
)

const (
	TargetRelease = "release"
	TargetSBOM    = "sbom"
	TargetBinding = "binding"
)

type VerifyOptions struct {
	File       string
	Bundle     string
	SBOM       string
	SBOMBundle string
	TrustStore string
	Package    string
	Version    string
}

type VerifyResult struct {
	verify.Result
	Target string `json:"target"`
}

func (r *VerifyResult) MarshalLine() []byte {
	out, err := json.Marshal(r)
	if err != nil {
		return r.Result.MarshalLine()
	}
	return append(out, '\n')
}

func Verify(o VerifyOptions) *VerifyResult {
	if o.SBOM == "" || o.SBOMBundle == "" {
		r := &VerifyResult{Target: TargetSBOM}
		r.Status = verify.InputError
		r.Message = "missing required option --sbom or --sbom-bundle"
		return r
	}
	rel := verify.Release(verify.Options{
		File: o.File, Bundle: o.Bundle, TrustStore: o.TrustStore, Package: o.Package, Version: o.Version,
	})
	if !rel.Valid {
		return &VerifyResult{Result: *rel, Target: TargetRelease}
	}
	sb := verify.Release(verify.Options{
		File: o.SBOM, Bundle: o.SBOMBundle, TrustStore: o.TrustStore, Package: o.Package, Version: o.Version,
	})
	if !sb.Valid {
		return &VerifyResult{Result: *sb, Target: TargetSBOM}
	}

	out := &VerifyResult{Result: *rel, Target: TargetBinding}
	fail := func(s verify.Status, format string, a ...any) *VerifyResult {
		out.Valid = false
		out.Status = s
		out.Message = fmt.Sprintf(format, a...)
		return out
	}

	data, err := ReadFile(o.SBOM)
	if err != nil {
		return fail(verify.InputError, "read SBOM: %v", err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != sb.Manifest.Artifact.SHA256 {
		return fail(verify.ArtifactMismatch, "SBOM changed after its signature was verified")
	}
	artSHA := rel.Manifest.Artifact.SHA256
	ok, err := References(data, artSHA)
	if err != nil {
		return fail(verify.FormatError, "SBOM: %v", err)
	}
	if !ok {
		return fail(verify.ArtifactMismatch, "SBOM does not reference the release artifact SHA-256 %s", artSHA)
	}
	out.Valid = true
	out.Status = verify.OK
	out.Message = fmt.Sprintf("%s %s (%s) verified; signed SBOM %s references its SHA-256",
		rel.Manifest.Package, rel.Manifest.Version, rel.Manifest.Artifact.Name, sb.Manifest.Artifact.Name)
	return out
}
