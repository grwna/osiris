package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/grwna/osiris/internal/crypto"
)

func main() {
	rootDir, err := filepath.Abs(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get root directory: %v\n", err)
		os.Exit(1)
	}

	resultsDir := filepath.Join(rootDir, "bench", "results")
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create results directory: %v\n", err)
		os.Exit(1)
	}

	tmpDir, err := os.MkdirTemp("", "osiris-bench-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	artifacts := []ArtifactSpec{
		{Name: "1KiB", Path: filepath.Join(rootDir, "bench", "artifacts", "artifact-1KiB.bin"), Size: 1024},
		{Name: "1MiB", Path: filepath.Join(rootDir, "bench", "artifacts", "artifact-1MiB.bin"), Size: 1024 * 1024},
		{Name: "64MiB", Path: filepath.Join(rootDir, "bench", "artifacts", "artifact-64MiB.bin"), Size: 64 * 1024 * 1024},
	}
	for _, art := range artifacts {
		if err := ensureArtifact(art.Path, art.Size); err != nil {
			fmt.Fprintf(os.Stderr, "ensure artifact %s: %v\n", art.Name, err)
			os.Exit(1)
		}
	}

	binPath, err := ensureBinary(rootDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Starting Osiris Benchmark Suite ===")
	sys := getSystemInfo()
	fmt.Printf("System: %s (%d vCPUs), RAM: %s, OS: %s, Go: %s\n\n", sys.CPU, sys.VCPU, sys.RAM, sys.OSKernel, sys.GoVer)

	profiles := []crypto.Profile{
		crypto.RSAPSS,
		crypto.ECDSAP256,
		crypto.Ed25519,
	}

	keyMap, err := prepareKeyMap(profiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare key map: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("-> Running Keygen Benchmark (10 iterations/algorithm)...")
	keygenRecords, err := benchmarkKeygen(profiles, 10)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark keygen: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("-> Running Artifact Hash Benchmark (5 warm-up + 30 measured runs)...")
	hashRecords, hashes, err := benchmarkHash(artifacts, 5, 30)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark hash: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("-> Running Crypto Sign & Verify Benchmark (5 warm-up + 30 measured runs)...")
	cryptoRecords, err := benchmarkCrypto(profiles, artifacts, keyMap, hashes, 5, 30)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark crypto: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("-> Running End-to-End CLI Benchmark (5 warm-up + 30 measured runs)...")
	e2eRecords, err := benchmarkE2E(binPath, tmpDir, profiles, artifacts, keyMap, 5, 30)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark e2e: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("-> Measuring Key, Signature, and Bundle Sizes...")
	sizeRecords, err := measureSizes(profiles, keyMap, hashes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "measure sizes: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("-> Writing CSV files to bench/results/...")
	if err := exportCSVs(resultsDir, keygenRecords, hashRecords, cryptoRecords, e2eRecords, sizeRecords); err != nil {
		fmt.Fprintf(os.Stderr, "export csvs: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("-> Generating bench/results/SUMMARY.md...")
	summaryPath := filepath.Join(resultsDir, "SUMMARY.md")
	if err := generateSummaryMD(summaryPath, sys, keygenRecords, hashRecords, cryptoRecords, e2eRecords, sizeRecords, artifacts, profiles); err != nil {
		fmt.Fprintf(os.Stderr, "generate summary: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=== Osiris Benchmark Suite Completed Successfully ===")
	fmt.Printf("Summary markdown written to: %s\n", summaryPath)
}
