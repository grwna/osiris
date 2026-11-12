package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrExists = errors.New("file already exists (use the explicit overwrite option)")

func CheckWritable(path string, overwrite bool) error {
	fi, err := os.Stat(path)
	switch {
	case err == nil:
		if fi.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		if !overwrite {
			return fmt.Errorf("%s: %w", path, ErrExists)
		}
		return nil
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return err
	}
}

func WriteFileAtomic(path string, data []byte, perm os.FileMode, overwrite bool) error {
	if err := CheckWritable(path, overwrite); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
