package sign

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/bundle"
	"github.com/grwna/osiris/internal/crypto"
	"github.com/grwna/osiris/internal/fsutil"
	"github.com/grwna/osiris/internal/manifest"
)

const maxKeyFileSize = 64 * 1024

type Options struct {
	File    string
	Package string
	Version string
	KeyPath string
	OutPath string
	Force   bool
}

type Result struct {
	Profile  crypto.Profile
	KeyID    string
	Manifest []byte
	Bundle   string
	Warnings []string
}

func keyPermWarning(path string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Sprintf("private key %s has permissive mode %04o; use chmod 600", path, fi.Mode().Perm())
	}
	return ""
}

func HashFile(path string) (int64, string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, "", err
	}
	if !fi.Mode().IsRegular() {
		return 0, "", fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func Run(o Options) (*Result, error) {
	for _, req := range []struct{ name, val string }{
		{"--file", o.File}, {"--package", o.Package}, {"--version", o.Version},
		{"--key", o.KeyPath}, {"--out", o.OutPath},
	} {
		if req.val == "" {
			return nil, apperr.Input("missing required option %s", req.name)
		}
	}
	if !manifest.PackagePattern.MatchString(o.Package) {
		return nil, apperr.Input("invalid --package %q: must match %s", o.Package, manifest.PackagePattern)
	}
	if !manifest.VersionPattern.MatchString(o.Version) {
		return nil, apperr.Input("invalid --version %q: must match %s", o.Version, manifest.VersionPattern)
	}
	name := filepath.Base(o.File)
	if !manifest.NamePattern.MatchString(name) {
		return nil, apperr.Input("invalid artifact file name %q: must match %s", name, manifest.NamePattern)
	}
	if err := fsutil.CheckWritable(o.OutPath, o.Force); err != nil {
		return nil, apperr.Input("output bundle: %v", err)
	}

	keyPEM, err := readLimited(o.KeyPath, maxKeyFileSize)
	if err != nil {
		return nil, apperr.Input("read private key: %v", err)
	}
	profile, priv, err := crypto.ParsePrivateKeyPEM(keyPEM)
	clear(keyPEM)
	if err != nil {
		return nil, apperr.Input("%v", err)
	}
	keyid, err := crypto.PublicKeyID(priv.Public())
	if err != nil {
		return nil, apperr.Input("%v", err)
	}

	size, sum, err := HashFile(o.File)
	if err != nil {
		return nil, apperr.Input("read artifact: %v", err)
	}

	m := manifest.New(o.Package, o.Version, profile, keyid, name, size, sum)
	M, err := manifest.Serialize(m)
	if err != nil {
		return nil, apperr.Input("build manifest: %v", err)
	}
	sig, err := crypto.Sign(profile, priv, M)
	if err != nil {
		return nil, apperr.Input("sign: %v", err)
	}
	// never emit a bundle that does not verify
	if !crypto.Verify(profile, priv.Public(), M, sig) {
		return nil, apperr.Input("internal error: produced signature does not verify")
	}
	if err := bundle.Write(o.OutPath, M, sig, o.Force); err != nil {
		return nil, apperr.Input("write bundle: %v", err)
	}
	res := &Result{Profile: profile, KeyID: keyid, Manifest: M, Bundle: o.OutPath}
	if w := keyPermWarning(o.KeyPath); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	return res, nil
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is too large to be a key file", path)
	}
	return data, nil
}
