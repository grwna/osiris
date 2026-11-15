package main

import (
	stdcrypto "crypto"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/grwna/osiris/internal/bundle"
	"github.com/grwna/osiris/internal/crypto"
	"github.com/grwna/osiris/internal/manifest"
)

type ArtifactSpec struct {
	Name string
	Path string
	Size int64
}

type KeyContext struct {
	PrivPEM []byte
	PubPEM  []byte
	KeyID   string
	Signer  stdcrypto.Signer
	PubKey  stdcrypto.PublicKey
}

type KeygenRecord struct {
	Iteration int
	Algorithm string
	Duration  time.Duration
}

type HashRecord struct {
	Iteration int
	Artifact  string
	Size      int64
	Duration  time.Duration
}

type CryptoRecord struct {
	Iteration int
	Algorithm string
	Artifact  string
	Operation string
	Duration  time.Duration
}

type E2ERecord struct {
	Iteration int
	Algorithm string
	Artifact  string
	Operation string
	Duration  time.Duration
}

type SizeRecord struct {
	Algorithm    string
	PrivDERBytes int
	PubDERBytes  int
	SigBytes     int
	BundleBytes  int
}

func prepareKeyMap(profiles []crypto.Profile) (map[crypto.Profile]KeyContext, error) {
	m := make(map[crypto.Profile]KeyContext, len(profiles))
	for _, p := range profiles {
		privPEM, pubPEM, keyid, err := crypto.GenerateKey(p)
		if err != nil {
			return nil, fmt.Errorf("generate key for %s: %w", p, err)
		}
		_, signer, err := crypto.ParsePrivateKeyPEM(privPEM)
		if err != nil {
			return nil, fmt.Errorf("parse private key for %s: %w", p, err)
		}
		_, pubKey, _, err := crypto.ParsePublicKeyPEM(pubPEM)
		if err != nil {
			return nil, fmt.Errorf("parse public key for %s: %w", p, err)
		}
		m[p] = KeyContext{
			PrivPEM: privPEM,
			PubPEM:  pubPEM,
			KeyID:   keyid,
			Signer:  signer,
			PubKey:  pubKey,
		}
	}
	return m, nil
}

func benchmarkKeygen(profiles []crypto.Profile, iterations int) ([]KeygenRecord, error) {
	var records []KeygenRecord
	for _, p := range profiles {
		for i := 1; i <= iterations; i++ {
			t0 := time.Now()
			_, _, _, err := crypto.GenerateKey(p)
			dur := time.Since(t0)
			if err != nil {
				return nil, fmt.Errorf("keygen %s iter %d: %w", p, i, err)
			}
			records = append(records, KeygenRecord{
				Iteration: i,
				Algorithm: string(p),
				Duration:  dur,
			})
		}
	}
	return records, nil
}

func benchmarkHash(artifacts []ArtifactSpec, warmups, iterations int) ([]HashRecord, map[string]string, error) {
	var records []HashRecord
	hashes := make(map[string]string, len(artifacts))

	for _, art := range artifacts {
		for w := 0; w < warmups; w++ {
			f, err := os.Open(art.Path)
			if err != nil {
				return nil, nil, fmt.Errorf("open %s: %w", art.Path, err)
			}
			h := sha256.New()
			io.Copy(h, f)
			f.Close()
		}

		var lastHash string
		for i := 1; i <= iterations; i++ {
			f, err := os.Open(art.Path)
			if err != nil {
				return nil, nil, fmt.Errorf("open %s: %w", art.Path, err)
			}
			h := sha256.New()
			t0 := time.Now()
			io.Copy(h, f)
			digest := h.Sum(nil)
			dur := time.Since(t0)
			f.Close()

			lastHash = fmt.Sprintf("%x", digest)
			records = append(records, HashRecord{
				Iteration: i,
				Artifact:  art.Name,
				Size:      art.Size,
				Duration:  dur,
			})
		}
		hashes[art.Name] = lastHash
	}
	return records, hashes, nil
}

func benchmarkCrypto(
	profiles []crypto.Profile,
	artifacts []ArtifactSpec,
	keyMap map[crypto.Profile]KeyContext,
	hashes map[string]string,
	warmups, iterations int,
) ([]CryptoRecord, error) {
	var records []CryptoRecord

	for _, p := range profiles {
		k := keyMap[p]
		for _, art := range artifacts {
			m := manifest.New("test-package", "1.0.0", p, k.KeyID, filepath.Base(art.Path), art.Size, hashes[art.Name])
			mBytes, err := manifest.Serialize(m)
			if err != nil {
				return nil, fmt.Errorf("serialize manifest for %s/%s: %w", p, art.Name, err)
			}

			var warmSig []byte
			for w := 0; w < warmups; w++ {
				warmSig, err = crypto.Sign(p, k.Signer, mBytes)
				if err != nil {
					return nil, fmt.Errorf("warmup sign %s/%s: %w", p, art.Name, err)
				}
			}

			var sig []byte
			for i := 1; i <= iterations; i++ {
				t0 := time.Now()
				sig, err = crypto.Sign(p, k.Signer, mBytes)
				dur := time.Since(t0)
				if err != nil {
					return nil, fmt.Errorf("sign %s/%s iter %d: %w", p, art.Name, i, err)
				}
				records = append(records, CryptoRecord{
					Iteration: i,
					Algorithm: string(p),
					Artifact:  art.Name,
					Operation: "sign",
					Duration:  dur,
				})
			}

			for w := 0; w < warmups; w++ {
				if !crypto.Verify(p, k.PubKey, mBytes, warmSig) {
					return nil, fmt.Errorf("warmup verify failed for %s/%s", p, art.Name)
				}
			}

			for i := 1; i <= iterations; i++ {
				t0 := time.Now()
				ok := crypto.Verify(p, k.PubKey, mBytes, sig)
				dur := time.Since(t0)
				if !ok {
					return nil, fmt.Errorf("verify failed for %s/%s iter %d", p, art.Name, i)
				}
				records = append(records, CryptoRecord{
					Iteration: i,
					Algorithm: string(p),
					Artifact:  art.Name,
					Operation: "verify",
					Duration:  dur,
				})
			}
		}
	}
	return records, nil
}

func benchmarkE2E(
	binPath, tmpDir string,
	profiles []crypto.Profile,
	artifacts []ArtifactSpec,
	keyMap map[crypto.Profile]KeyContext,
	warmups, iterations int,
) ([]E2ERecord, error) {
	var records []E2ERecord
	trustStorePath := filepath.Join(tmpDir, "trust.json")

	for _, p := range profiles {
		k := keyMap[p]
		keyFilePath := filepath.Join(tmpDir, string(p)+".pub.pem")
		if err := os.WriteFile(keyFilePath, k.PubPEM, 0o644); err != nil {
			return nil, err
		}
		cmd := exec.Command(binPath, "trust", "add", "--store", trustStorePath, "--key", keyFilePath, "--package", "test-package")
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("trust add %s: %s (%w)", p, out, err)
		}
	}

	for _, p := range profiles {
		k := keyMap[p]
		privFilePath := filepath.Join(tmpDir, string(p)+".key.pem")
		if err := os.WriteFile(privFilePath, k.PrivPEM, 0o600); err != nil {
			return nil, err
		}

		for _, art := range artifacts {
			bundlePath := filepath.Join(tmpDir, fmt.Sprintf("%s-%s.bundle.json", p, art.Name))

			for w := 0; w < warmups; w++ {
				cmd := exec.Command(binPath, "sign",
					"--file", art.Path,
					"--package", "test-package",
					"--version", "1.0.0",
					"--key", privFilePath,
					"--out", bundlePath,
					"--force")
				if out, err := cmd.CombinedOutput(); err != nil {
					return nil, fmt.Errorf("e2e warm sign %s/%s: %s (%w)", p, art.Name, out, err)
				}
			}

			for i := 1; i <= iterations; i++ {
				cmd := exec.Command(binPath, "sign",
					"--file", art.Path,
					"--package", "test-package",
					"--version", "1.0.0",
					"--key", privFilePath,
					"--out", bundlePath,
					"--force")
				t0 := time.Now()
				out, err := cmd.CombinedOutput()
				dur := time.Since(t0)
				if err != nil {
					return nil, fmt.Errorf("e2e sign %s/%s iter %d: %s (%w)", p, art.Name, i, out, err)
				}
				records = append(records, E2ERecord{
					Iteration: i,
					Algorithm: string(p),
					Artifact:  art.Name,
					Operation: "sign",
					Duration:  dur,
				})
			}

			for w := 0; w < warmups; w++ {
				cmd := exec.Command(binPath, "verify",
					"--file", art.Path,
					"--bundle", bundlePath,
					"--trust-store", trustStorePath,
					"--package", "test-package",
					"--version", "1.0.0",
					"--json")
				if out, err := cmd.CombinedOutput(); err != nil {
					return nil, fmt.Errorf("e2e warm verify %s/%s: %s (%w)", p, art.Name, out, err)
				}
			}

			for i := 1; i <= iterations; i++ {
				cmd := exec.Command(binPath, "verify",
					"--file", art.Path,
					"--bundle", bundlePath,
					"--trust-store", trustStorePath,
					"--package", "test-package",
					"--version", "1.0.0",
					"--json")
				t0 := time.Now()
				out, err := cmd.CombinedOutput()
				dur := time.Since(t0)
				if err != nil {
					return nil, fmt.Errorf("e2e verify %s/%s iter %d: %s (%w)", p, art.Name, i, out, err)
				}
				records = append(records, E2ERecord{
					Iteration: i,
					Algorithm: string(p),
					Artifact:  art.Name,
					Operation: "verify",
					Duration:  dur,
				})
			}
		}
	}
	return records, nil
}

func measureSizes(
	profiles []crypto.Profile,
	keyMap map[crypto.Profile]KeyContext,
	hashes map[string]string,
) ([]SizeRecord, error) {
	var records []SizeRecord
	for _, p := range profiles {
		k := keyMap[p]
		privBlock, _ := pem.Decode(k.PrivPEM)
		pubBlock, _ := pem.Decode(k.PubPEM)

		m := manifest.New("test-package", "1.0.0", p, k.KeyID, "artifact-1KiB.bin", 1024, hashes["1KiB"])
		mBytes, err := manifest.Serialize(m)
		if err != nil {
			return nil, err
		}
		sig, err := crypto.Sign(p, k.Signer, mBytes)
		if err != nil {
			return nil, err
		}
		bndBytes, err := bundle.Marshal(mBytes, sig)
		if err != nil {
			return nil, err
		}

		records = append(records, SizeRecord{
			Algorithm:    string(p),
			PrivDERBytes: len(privBlock.Bytes),
			PubDERBytes:  len(pubBlock.Bytes),
			SigBytes:     len(sig),
			BundleBytes:  len(bndBytes),
		})
	}
	return records, nil
}
