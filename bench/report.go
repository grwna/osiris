package main

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grwna/osiris/internal/crypto"
)

func calcStats(durations []time.Duration) (median time.Duration, p95 time.Duration) {
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	n := len(sorted)
	if n == 0 {
		return 0, 0
	}
	if n%2 == 1 {
		median = sorted[n/2]
	} else {
		median = (sorted[n/2-1] + sorted[n/2]) / 2
	}
	rank := int(math.Ceil(0.95 * float64(n)))
	if rank < 1 {
		rank = 1
	} else if rank > n {
		rank = n
	}
	p95 = sorted[rank-1]
	return median, p95
}

func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%.2f ns", float64(d.Nanoseconds()))
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.2f µs", float64(d.Nanoseconds())/1000.0)
	}
	if d < time.Second {
		return fmt.Sprintf("%.2f ms", float64(d.Microseconds())/1000.0)
	}
	return fmt.Sprintf("%.3f s", d.Seconds())
}

func writeCSV(path string, header []string, writeRows func(*csv.Writer)) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		return err
	}
	writeRows(w)
	w.Flush()
	return w.Error()
}

func exportCSVs(
	resultsDir string,
	keygen []KeygenRecord,
	hash []HashRecord,
	cryptoRecs []CryptoRecord,
	e2e []E2ERecord,
	sizes []SizeRecord,
) error {
	err := writeCSV(filepath.Join(resultsDir, "keygen.csv"), []string{"iteration", "algorithm", "duration_ns", "duration_ms"}, func(w *csv.Writer) {
		for _, r := range keygen {
			w.Write([]string{
				strconv.Itoa(r.Iteration),
				r.Algorithm,
				strconv.FormatInt(r.Duration.Nanoseconds(), 10),
				fmt.Sprintf("%.4f", float64(r.Duration.Microseconds())/1000.0),
			})
		}
	})
	if err != nil {
		return err
	}

	err = writeCSV(filepath.Join(resultsDir, "hash.csv"), []string{"iteration", "artifact", "size_bytes", "duration_ns", "duration_ms"}, func(w *csv.Writer) {
		for _, r := range hash {
			w.Write([]string{
				strconv.Itoa(r.Iteration),
				r.Artifact,
				strconv.FormatInt(r.Size, 10),
				strconv.FormatInt(r.Duration.Nanoseconds(), 10),
				fmt.Sprintf("%.4f", float64(r.Duration.Microseconds())/1000.0),
			})
		}
	})
	if err != nil {
		return err
	}

	err = writeCSV(filepath.Join(resultsDir, "crypto.csv"), []string{"iteration", "algorithm", "artifact", "operation", "duration_ns", "duration_us"}, func(w *csv.Writer) {
		for _, r := range cryptoRecs {
			w.Write([]string{
				strconv.Itoa(r.Iteration),
				r.Algorithm,
				r.Artifact,
				r.Operation,
				strconv.FormatInt(r.Duration.Nanoseconds(), 10),
				fmt.Sprintf("%.3f", float64(r.Duration.Nanoseconds())/1000.0),
			})
		}
	})
	if err != nil {
		return err
	}

	err = writeCSV(filepath.Join(resultsDir, "e2e.csv"), []string{"iteration", "algorithm", "artifact", "operation", "duration_ns", "duration_ms"}, func(w *csv.Writer) {
		for _, r := range e2e {
			w.Write([]string{
				strconv.Itoa(r.Iteration),
				r.Algorithm,
				r.Artifact,
				r.Operation,
				strconv.FormatInt(r.Duration.Nanoseconds(), 10),
				fmt.Sprintf("%.4f", float64(r.Duration.Microseconds())/1000.0),
			})
		}
	})
	if err != nil {
		return err
	}

	return writeCSV(filepath.Join(resultsDir, "sizes.csv"), []string{"algorithm", "priv_der_bytes", "pub_der_bytes", "sig_bytes", "bundle_bytes"}, func(w *csv.Writer) {
		for _, r := range sizes {
			w.Write([]string{
				r.Algorithm,
				strconv.Itoa(r.PrivDERBytes),
				strconv.Itoa(r.PubDERBytes),
				strconv.Itoa(r.SigBytes),
				strconv.Itoa(r.BundleBytes),
			})
		}
	})
}

func generateSummaryMD(
	path string,
	sys SystemInfo,
	keygenRecords []KeygenRecord,
	hashRecords []HashRecord,
	cryptoRecords []CryptoRecord,
	e2eRecords []E2ERecord,
	sizeRecords []SizeRecord,
	artifacts []ArtifactSpec,
	profiles []crypto.Profile,
) error {
	var sb strings.Builder

	sb.WriteString("# Osiris Performance Benchmark Report\n\n")
	sb.WriteString("Executed locally in a single continuous session using Go monotonic clock (`time.Now()` / `time.Since()`).\n\n")

	sb.WriteString("## Environment & Hardware Specification\n\n")
	sb.WriteString("| Component | Specification |\n")
	sb.WriteString("|---|---|\n")
	sb.WriteString(fmt.Sprintf("| **CPU** | %s (%d vCPUs) |\n", sys.CPU, sys.VCPU))
	sb.WriteString(fmt.Sprintf("| **RAM** | %s |\n", sys.RAM))
	sb.WriteString(fmt.Sprintf("| **Operating System** | %s |\n", sys.OSKernel))
	sb.WriteString(fmt.Sprintf("| **Runtime & Toolchain** | Go %s |\n", sys.GoVer))
	sb.WriteString("| **Timing Clock** | Monotonic clock (`runtimeNano` via `time.Since`) |\n")
	sb.WriteString("| **Percentile Method** | Nearest-rank: position $\\lceil 0.95 \\times n \\rceil$ (rank 29 of 30 ordered samples) |\n\n")

	sb.WriteString("## 1. Key Generation (Keygen)\n\n")
	sb.WriteString("Measured across 10 key pairs per algorithm. Operation is measured separately from signing and verification.\n\n")
	sb.WriteString("| Algorithm | Samples | Median |\n")
	sb.WriteString("|---|---|---|\n")
	for _, p := range profiles {
		var durs []time.Duration
		for _, r := range keygenRecords {
			if r.Algorithm == string(p) {
				durs = append(durs, r.Duration)
			}
		}
		med, _ := calcStats(durs)
		sb.WriteString(fmt.Sprintf("| `%s` | %d pairs | %s |\n", p, len(durs), formatDuration(med)))
	}
	sb.WriteString("\n")

	sb.WriteString("## 2. Artifact Hashing (SHA-256)\n\n")
	sb.WriteString("Raw SHA-256 digest computation time over artifact bytes, independently from manifest creation and signature operations.\n\n")
	sb.WriteString("| Artifact | Size (Bytes) | Median | P95 (Nearest-Rank) |\n")
	sb.WriteString("|---|---|---|---|\n")
	for _, art := range artifacts {
		var durs []time.Duration
		for _, r := range hashRecords {
			if r.Artifact == art.Name {
				durs = append(durs, r.Duration)
			}
		}
		med, p95 := calcStats(durs)
		sb.WriteString(fmt.Sprintf("| %s | %d | %s | %s |\n", art.Name, art.Size, formatDuration(med), formatDuration(p95)))
	}
	sb.WriteString("\n")

	sb.WriteString("## 3. Operations (Sign & Verify)\n\n")
	sb.WriteString("Cryptographic operations over canonical manifest bytes, including algorithm-internal hashing.\n\n")
	sb.WriteString("| Algorithm | Artifact | Operation | Median | P95 (Nearest-Rank) |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, p := range profiles {
		for _, art := range artifacts {
			for _, op := range []string{"sign", "verify"} {
				var durs []time.Duration
				for _, r := range cryptoRecords {
					if r.Algorithm == string(p) && r.Artifact == art.Name && r.Operation == op {
						durs = append(durs, r.Duration)
					}
				}
				med, p95 := calcStats(durs)
				sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s | %s |\n", p, art.Name, op, formatDuration(med), formatDuration(p95)))
			}
		}
	}
	sb.WriteString("\n")

	sb.WriteString("## 4. End-to-End Latency\n\n")
	sb.WriteString("Full application execution latency (sign and verify), including I/O, artifact hashing, manifest serialization, trust store validation, and output writing.\n\n")
	sb.WriteString("| Algorithm | Artifact | Command | Median | P95 |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, p := range profiles {
		for _, art := range artifacts {
			for _, op := range []string{"sign", "verify"} {
				var durs []time.Duration
				for _, r := range e2eRecords {
					if r.Algorithm == string(p) && r.Artifact == art.Name && r.Operation == op {
						durs = append(durs, r.Duration)
					}
				}
				med, p95 := calcStats(durs)
				sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s | %s |\n", p, art.Name, op, formatDuration(med), formatDuration(p95)))
			}
		}
	}
	sb.WriteString("\n")

	sb.WriteString("## 5. Key, Signature, and Bundle Sizes\n\n")
	sb.WriteString("Exact size in bytes per algorithm profile. Unencrypted public and private keys, raw signatures before Base64 encoding, and complete bundle JSON (with 1 KiB artifact manifest).\n\n")
	sb.WriteString("| Algorithm | Private Key (PKCS#8 DER) | Public Key (SPKI DER) | Raw Signature Bytes | Bundle JSON |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, r := range sizeRecords {
		sb.WriteString(fmt.Sprintf("| `%s` | %d bytes | %d bytes | %d bytes | %d bytes |\n",
			r.Algorithm, r.PrivDERBytes, r.PubDERBytes, r.SigBytes, r.BundleBytes))
	}
	sb.WriteString("\n")

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}
