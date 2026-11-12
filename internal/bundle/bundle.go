package bundle

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/grwna/osiris/internal/fsutil"
)

const (
	SchemaValue = "minisign-bundle/v1"
	MaxSize     = 64 * 1024
)

type Bundle struct {
	Schema       string `json:"schema"`
	ManifestB64  string `json:"manifest_b64"`
	SignatureB64 string `json:"signature_b64"`
}

func Marshal(manifestBytes, sig []byte) ([]byte, error) {
	b := Bundle{
		Schema:       SchemaValue,
		ManifestB64:  base64.StdEncoding.EncodeToString(manifestBytes),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	if len(out) > MaxSize {
		return nil, fmt.Errorf("bundle too large: %d bytes (max %d)", len(out), MaxSize)
	}
	return out, nil
}

func Write(path string, manifestBytes, sig []byte, overwrite bool) error {
	data, err := Marshal(manifestBytes, sig)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, data, 0o644, overwrite)
}
