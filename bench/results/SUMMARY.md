# Osiris Performance Benchmark Report

Executed locally in a single continuous session using Go monotonic clock (`time.Now()` / `time.Since()`).

## Environment & Hardware Specification

| Component | Specification |
|---|---|
| **CPU** | 12th Gen Intel(R) Core(TM) i7-12700H (20 vCPUs) |
| **RAM** | 7.7Gi |
| **Operating System** | Linux 6.18.58.1-microsoft-standard-WSL2 x86_64 |
| **Runtime & Toolchain** | Go go1.27.1 |
| **Timing Clock** | Monotonic clock (`runtimeNano` via `time.Since`) |
| **Percentile Method** | Nearest-rank: position $\lceil 0.95 \times n \rceil$ (rank 29 of 30 ordered samples) |

## 1. Key Generation (Keygen)

Measured across 10 key pairs per algorithm. Operation is measured separately from signing and verification.

| Algorithm | Samples | Median |
|---|---|---|
| `rsa-pss-sha256` | 10 pairs | 265.61 ms |
| `ecdsa-p256-sha256` | 10 pairs | 36.68 µs |
| `ed25519` | 10 pairs | 34.17 µs |

## 2. Artifact Hashing (SHA-256)

Raw SHA-256 digest computation time over artifact bytes, independently from manifest creation and signature operations.| Artifact | Size (Bytes) | Median | P95 (Nearest-Rank) |
|---|---|---|---|
| 1KiB | 1024 | 5.18 µs | 6.33 µs |
| 1MiB | 1048576 | 1.07 ms | 1.25 ms |
| 64MiB | 67108864 | 72.92 ms | 74.56 ms |

## 3. Operations (Sign & Verify)

Cryptographic operations over canonical manifest bytes, including algorithm-internal hashing.| Algorithm | Artifact | Operation | Median | P95 (Nearest-Rank) |
|---|---|---|---|---|
| `rsa-pss-sha256` | 1KiB | sign | 3.95 ms | 4.29 ms |
| `rsa-pss-sha256` | 1KiB | verify | 200.43 µs | 252.12 µs |
| `rsa-pss-sha256` | 1MiB | sign | 3.90 ms | 4.13 ms |
| `rsa-pss-sha256` | 1MiB | verify | 189.96 µs | 227.21 µs |
| `rsa-pss-sha256` | 64MiB | sign | 3.94 ms | 4.51 ms |
| `rsa-pss-sha256` | 64MiB | verify | 194.99 µs | 224.53 µs |
| `ecdsa-p256-sha256` | 1KiB | sign | 49.23 µs | 62.88 µs |
| `ecdsa-p256-sha256` | 1KiB | verify | 110.14 µs | 143.90 µs |
| `ecdsa-p256-sha256` | 1MiB | sign | 49.30 µs | 79.61 µs |
| `ecdsa-p256-sha256` | 1MiB | verify | 110.86 µs | 123.03 µs |
| `ecdsa-p256-sha256` | 64MiB | sign | 49.73 µs | 71.41 µs |
| `ecdsa-p256-sha256` | 64MiB | verify | 110.71 µs | 122.76 µs |
| `ed25519` | 1KiB | sign | 31.29 µs | 32.51 µs |
| `ed25519` | 1KiB | verify | 71.54 µs | 83.47 µs |
| `ed25519` | 1MiB | sign | 32.24 µs | 85.92 µs |
| `ed25519` | 1MiB | verify | 69.94 µs | 81.20 µs |
| `ed25519` | 64MiB | sign | 31.52 µs | 44.07 µs |
| `ed25519` | 64MiB | verify | 71.44 µs | 82.94 µs |

## 4. End-to-End Latency

Full application execution latency  (sign and verify), including I/O, artifact hashing, manifest serialization, trust store validation, and output writing.| Algorithm | Artifact | Command | Median | P95 |
|---|---|---|---|---|
| `rsa-pss-sha256` | 1KiB | sign | 14.90 ms | 16.55 ms |
| `rsa-pss-sha256` | 1KiB | verify | 5.01 ms | 6.66 ms |
| `rsa-pss-sha256` | 1MiB | sign | 14.98 ms | 16.61 ms |
| `rsa-pss-sha256` | 1MiB | verify | 5.39 ms | 6.25 ms |
| `rsa-pss-sha256` | 64MiB | sign | 89.79 ms | 92.14 ms |
| `rsa-pss-sha256` | 64MiB | verify | 78.44 ms | 79.91 ms |
| `ecdsa-p256-sha256` | 1KiB | sign | 9.44 ms | 10.20 ms |
| `ecdsa-p256-sha256` | 1KiB | verify | 4.16 ms | 5.00 ms |
| `ecdsa-p256-sha256` | 1MiB | sign | 11.74 ms | 21.19 ms |
| `ecdsa-p256-sha256` | 1MiB | verify | 5.58 ms | 6.10 ms |
| `ecdsa-p256-sha256` | 64MiB | sign | 85.36 ms | 88.54 ms |
| `ecdsa-p256-sha256` | 64MiB | verify | 77.77 ms | 80.66 ms |
| `ed25519` | 1KiB | sign | 11.15 ms | 11.99 ms |
| `ed25519` | 1KiB | verify | 4.41 ms | 4.97 ms |
| `ed25519` | 1MiB | sign | 12.29 ms | 14.01 ms |
| `ed25519` | 1MiB | verify | 6.11 ms | 7.07 ms |
| `ed25519` | 64MiB | sign | 86.63 ms | 90.92 ms |
| `ed25519` | 64MiB | verify | 78.46 ms | 80.39 ms |

## 5. Key, Signature, and Bundle Sizes

Exact size in bytes per algorithm profile. Unencrypted public and private keys, raw signatures before Base64 encoding, and complete bundle JSON (with 1 KiB artifact manifest).

| Algorithm | Private Key (PKCS#8 DER) | Public Key (SPKI DER) | Raw Signature Bytes | Bundle JSON |
|---|---|---|---|---|
| `rsa-pss-sha256` | 1794 bytes | 422 bytes | 384 bytes | 1006 bytes |
| `ecdsa-p256-sha256` | 138 bytes | 91 bytes | 64 bytes | 586 bytes |
| `ed25519` | 48 bytes | 44 bytes | 64 bytes | 574 bytes |

