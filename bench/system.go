package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type SystemInfo struct {
	CPU      string
	VCPU     int
	RAM      string
	OSKernel string
	GoVer    string
}

func getSystemInfo() SystemInfo {
	info := SystemInfo{
		GoVer:    runtime.Version(),
		VCPU:     runtime.NumCPU(),
		OSKernel: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}

	if out, err := exec.Command("uname", "-srm").Output(); err == nil {
		info.OSKernel = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("sh", "-c", "lscpu | grep 'Model name' | head -n1 | cut -d: -f2").Output(); err == nil && len(out) > 0 {
		info.CPU = strings.TrimSpace(string(out))
	} else {
		info.CPU = runtime.GOARCH
	}
	if out, err := exec.Command("sh", "-c", "free -h | awk '/Mem:/ {print $2}'").Output(); err == nil && len(out) > 0 {
		info.RAM = strings.TrimSpace(string(out))
	} else {
		info.RAM = "Unknown"
	}
	return info
}

func ensureBinary(rootDir string) (string, error) {
	binPath := filepath.Join(rootDir, "bin", "osiris")
	if _, err := os.Stat(binPath); err == nil {
		return binPath, nil
	}
	cmd := exec.Command("go", "build", "-ldflags", "-s -w -X main.Version=0.1.0", "-o", binPath, "./cmd/osiris")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build osiris binary: %w", err)
	}
	return binPath, nil
}

func ensureArtifact(path string, size int64) error {
	info, err := os.Stat(path)
	if err == nil && info.Size() == size {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 1024*1024)
	var written int64
	for written < size {
		toWrite := int64(len(buf))
		if size-written < toWrite {
			toWrite = size - written
		}
		n, err := f.Write(buf[:toWrite])
		if err != nil {
			return err
		}
		written += int64(n)
	}
	return nil
}
