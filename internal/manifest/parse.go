package manifest

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/grwna/osiris/internal/strictjson"
)

func ParseStrict(M []byte) (Manifest, error) {
	if len(M) > MaxSize {
		return Manifest{}, fmt.Errorf("manifest too large: %d bytes (max %d)", len(M), MaxSize)
	}
	for i, c := range M {
		if c < 0x20 || c > 0x7e {
			return Manifest{}, fmt.Errorf("manifest byte %d (0x%02x) is not printable ASCII", i, c)
		}
	}
	obj, err := strictjson.ParseObject(M)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if err := obj.ExpectFields("manifest", "schema", "package", "version", "algorithm", "keyid", "artifact"); err != nil {
		return Manifest{}, err
	}
	var m Manifest
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"schema", &m.Schema}, {"package", &m.Package}, {"version", &m.Version},
		{"algorithm", &m.Algorithm}, {"keyid", &m.KeyID},
	} {
		if *f.dst, err = obj.String(f.key); err != nil {
			return Manifest{}, fmt.Errorf("manifest: %w", err)
		}
	}
	art, err := obj.Object("artifact")
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if err := art.ExpectFields("manifest.artifact", "name", "size", "sha256"); err != nil {
		return Manifest{}, err
	}
	if m.Artifact.Name, err = art.String("name"); err != nil {
		return Manifest{}, fmt.Errorf("manifest.artifact: %w", err)
	}
	if m.Artifact.Size, err = art.Integer("size"); err != nil {
		return Manifest{}, fmt.Errorf("manifest.artifact: %w", err)
	}
	if m.Artifact.SHA256, err = art.String("sha256"); err != nil {
		return Manifest{}, fmt.Errorf("manifest.artifact: %w", err)
	}

	if m.Schema != SchemaValue {
		return Manifest{}, fmt.Errorf("manifest: schema must be %q, got %q", SchemaValue, m.Schema)
	}
	if !PackagePattern.MatchString(m.Package) {
		return Manifest{}, fmt.Errorf("manifest: package %q does not match %s", m.Package, PackagePattern)
	}
	if !VersionPattern.MatchString(m.Version) {
		return Manifest{}, fmt.Errorf("manifest: version %q does not match %s", m.Version, VersionPattern)
	}
	if m.Algorithm == "" {
		return Manifest{}, errors.New("manifest: algorithm must not be empty")
	}
	if !HexPattern.MatchString(m.KeyID) {
		return Manifest{}, errors.New("manifest: keyid must be 64 lowercase hex characters")
	}
	if !NamePattern.MatchString(m.Artifact.Name) {
		return Manifest{}, fmt.Errorf("manifest: artifact name %q does not match %s", m.Artifact.Name, NamePattern)
	}
	if m.Artifact.Size > MaxArtifactSize {
		return Manifest{}, fmt.Errorf("manifest: artifact size out of range 0..%d", MaxArtifactSize)
	}
	if !HexPattern.MatchString(m.Artifact.SHA256) {
		return Manifest{}, errors.New("manifest: artifact sha256 must be 64 lowercase hex characters")
	}
	if !bytes.Equal(encode(m), M) {
		return Manifest{}, errors.New("manifest is not in canonical form (field order, whitespace or escaping differs)")
	}
	return m, nil
}
