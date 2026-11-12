package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/fsutil"
	"github.com/grwna/osiris/internal/sign"
)

const (
	MaxSize  = 16 << 20
	maxDepth = 64
)

func References(data []byte, sha256hex string) (bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false, errors.New("SBOM must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	found := false
	if err := walk(dec, sha256hex, &found, 0); err != nil {
		return false, fmt.Errorf("invalid SBOM JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return false, errors.New("invalid SBOM JSON: unexpected data after the top-level object")
	}
	return found, nil
}

func walk(dec *json.Decoder, target string, found *bool, depth int) error {
	if depth > maxDepth {
		return errors.New("nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, _ := kt.(string)
				if seen[key] {
					return fmt.Errorf("duplicate field %q", key)
				}
				seen[key] = true
				if err := walk(dec, target, found, depth+1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(dec, target, found, depth+1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
	case string:
		if strings.EqualFold(t, target) {
			*found = true
		}
	}
	return nil
}

func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%s exceeds the %d byte SBOM limit", path, MaxSize)
	}
	return data, nil
}

type GenerateOptions struct {
	File    string
	Package string
	Version string
	OutPath string
	Force   bool
}

func Generate(o GenerateOptions) error {
	for _, r := range []struct{ n, v string }{{"--file", o.File}, {"--package", o.Package}, {"--version", o.Version}, {"--out", o.OutPath}} {
		if r.v == "" {
			return apperr.Input("missing required option %s", r.n)
		}
	}
	if err := fsutil.CheckWritable(o.OutPath, o.Force); err != nil {
		return apperr.Input("output SBOM: %v", err)
	}
	size, sum, err := sign.HashFile(o.File)
	if err != nil {
		return apperr.Input("read artifact: %v", err)
	}
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"component": map[string]any{
				"type":    "application",
				"name":    o.Package,
				"version": o.Version,
				"hashes":  []map[string]string{{"alg": "SHA-256", "content": sum}},
				"properties": []map[string]string{
					{"name": "artifact:file", "value": baseName(o.File)},
					{"name": "artifact:size", "value": fmt.Sprint(size)},
				},
			},
		},
		"components": []any{},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return apperr.Input("encode SBOM: %v", err)
	}
	data = append(data, '\n')
	if err := fsutil.WriteFileAtomic(o.OutPath, data, 0o644, o.Force); err != nil {
		return apperr.Input("write SBOM: %v", err)
	}
	return nil
}

type SignOptions struct {
	SBOMPath     string
	ArtifactPath string
	Package      string
	Version      string
	KeyPath      string
	OutPath      string
	Force        bool
}

func Sign(o SignOptions) (*sign.Result, error) {
	if o.SBOMPath == "" {
		return nil, apperr.Input("missing required option --sbom")
	}
	if o.ArtifactPath == "" {
		return nil, apperr.Input("missing required option --file")
	}
	_, artSum, err := sign.HashFile(o.ArtifactPath)
	if err != nil {
		return nil, apperr.Input("read release artifact: %v", err)
	}
	data, err := ReadFile(o.SBOMPath)
	if err != nil {
		return nil, apperr.Input("read SBOM: %v", err)
	}
	ok, err := References(data, artSum)
	if err != nil {
		return nil, apperr.Input("%v", err)
	}
	if !ok {
		return nil, apperr.Input("SBOM does not reference the SHA-256 (%s) of the release artifact", artSum)
	}
	return sign.Run(sign.Options{
		File: o.SBOMPath, Package: o.Package, Version: o.Version,
		KeyPath: o.KeyPath, OutPath: o.OutPath, Force: o.Force,
	})
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
