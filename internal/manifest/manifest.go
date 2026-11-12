package manifest

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/grwna/osiris/internal/crypto"
)

const (
	SchemaValue           = "minisign-manifest/v1"
	MaxSize               = 16 * 1024
	MaxArtifactSize int64 = 9007199254740991
)

var (
	PackagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	VersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	NamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	HexPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Artifact struct {
	Name   string
	Size   int64
	SHA256 string
}

type Manifest struct {
	Schema    string
	Package   string
	Version   string
	Algorithm string
	KeyID     string
	Artifact  Artifact
}

func New(pkg, version string, profile crypto.Profile, keyid, name string, size int64, sha256hex string) Manifest {
	return Manifest{
		Schema:    SchemaValue,
		Package:   pkg,
		Version:   version,
		Algorithm: string(profile),
		KeyID:     keyid,
		Artifact:  Artifact{Name: name, Size: size, SHA256: sha256hex},
	}
}

func (m Manifest) Validate() error {
	if m.Schema != SchemaValue {
		return fmt.Errorf("schema must be %q", SchemaValue)
	}
	if !PackagePattern.MatchString(m.Package) {
		return fmt.Errorf("package %q does not match %s", m.Package, PackagePattern)
	}
	if !VersionPattern.MatchString(m.Version) {
		return fmt.Errorf("version %q does not match %s", m.Version, VersionPattern)
	}
	if _, err := crypto.ParseProfile(m.Algorithm); err != nil {
		return err
	}
	if !HexPattern.MatchString(m.KeyID) {
		return errors.New("keyid must be 64 lowercase hex characters")
	}
	if !NamePattern.MatchString(m.Artifact.Name) {
		return fmt.Errorf("artifact name %q does not match %s", m.Artifact.Name, NamePattern)
	}
	if m.Artifact.Size < 0 || m.Artifact.Size > MaxArtifactSize {
		return fmt.Errorf("artifact size %d out of range 0..%d", m.Artifact.Size, MaxArtifactSize)
	}
	if !HexPattern.MatchString(m.Artifact.SHA256) {
		return errors.New("artifact sha256 must be 64 lowercase hex characters")
	}
	return nil
}

func Serialize(m Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(`{"schema":"`)
	b.WriteString(m.Schema)
	b.WriteString(`","package":"`)
	b.WriteString(m.Package)
	b.WriteString(`","version":"`)
	b.WriteString(m.Version)
	b.WriteString(`","algorithm":"`)
	b.WriteString(m.Algorithm)
	b.WriteString(`","keyid":"`)
	b.WriteString(m.KeyID)
	b.WriteString(`","artifact":{"name":"`)
	b.WriteString(m.Artifact.Name)
	b.WriteString(`","size":`)
	b.WriteString(strconv.FormatInt(m.Artifact.Size, 10))
	b.WriteString(`,"sha256":"`)
	b.WriteString(m.Artifact.SHA256)
	b.WriteString(`"}}`)
	out := []byte(b.String())
	if len(out) > MaxSize {
		return nil, fmt.Errorf("manifest too large: %d bytes (max %d)", len(out), MaxSize)
	}
	return out, nil
}
