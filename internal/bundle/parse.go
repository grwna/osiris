package bundle

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/strictjson"
)

func DecodeBase64Strict(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return nil, fmt.Errorf("invalid Base64 character 0x%02x at offset %d", c, i)
		}
	}
	if len(s)%4 != 0 {
		return nil, fmt.Errorf("invalid Base64 length %d (must be a multiple of 4)", len(s))
	}
	out, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid Base64: %v", err)
	}
	if base64.StdEncoding.EncodeToString(out) != s {
		return nil, errors.New("invalid Base64: not in canonical form")
	}
	return out, nil
}

func Parse(data []byte) (M, sig []byte, err error) {
	if len(data) > MaxSize {
		return nil, nil, apperr.Format("bundle too large: %d bytes (max %d)", len(data), MaxSize)
	}
	obj, err := strictjson.ParseObject(data)
	if err != nil {
		return nil, nil, apperr.Format("bundle: %v", err)
	}
	if err := obj.ExpectFields("bundle", "schema", "manifest_b64", "signature_b64"); err != nil {
		return nil, nil, apperr.WrapFormat(err)
	}
	schema, err := obj.String("schema")
	if err != nil {
		return nil, nil, apperr.Format("bundle: %v", err)
	}
	if schema != SchemaValue {
		return nil, nil, apperr.Format("bundle: schema must be %q, got %q", SchemaValue, schema)
	}
	mb64, err := obj.String("manifest_b64")
	if err != nil {
		return nil, nil, apperr.Format("bundle: %v", err)
	}
	sb64, err := obj.String("signature_b64")
	if err != nil {
		return nil, nil, apperr.Format("bundle: %v", err)
	}
	if M, err = DecodeBase64Strict(mb64); err != nil {
		return nil, nil, apperr.Format("bundle manifest_b64: %v", err)
	}
	if sig, err = DecodeBase64Strict(sb64); err != nil {
		return nil, nil, apperr.Format("bundle signature_b64: %v", err)
	}
	return M, sig, nil
}

func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, apperr.Input("read bundle: %v", err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && !fi.Mode().IsRegular() {
		return nil, apperr.Input("read bundle: %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, apperr.Input("read bundle: %v", err)
	}
	if len(data) > MaxSize {
		return nil, apperr.Format("bundle too large: more than %d bytes", MaxSize)
	}
	return data, nil
}

func ParseFile(path string) (M, sig []byte, err error) {
	data, err := ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Parse(data)
}
