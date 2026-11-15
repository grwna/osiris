# osiris

`osiris` signs software release artifacts and verifies them before publication or
deployment. It supports RSA-PSS/SHA-256, ECDSA P-256/SHA-256, and Ed25519, with a
local trust store that controls which keys may sign each package.

## Technology and dependencies

- Go 1.26.1; cryptography uses the Go standard library.
- No third-party Go modules.
- Main packages: [`crypto/rsa`](https://pkg.go.dev/crypto/rsa),
  [`crypto/ecdsa`](https://pkg.go.dev/crypto/ecdsa),
  [`crypto/ed25519`](https://pkg.go.dev/crypto/ed25519),
  [`crypto/x509`](https://pkg.go.dev/crypto/x509),
  [`encoding/pem`](https://pkg.go.dev/encoding/pem),
  [`crypto/sha256`](https://pkg.go.dev/crypto/sha256),
  [`encoding/json`](https://pkg.go.dev/encoding/json), and
  [`encoding/base64`](https://pkg.go.dev/encoding/base64).
- Container: static Go binary (`CGO_ENABLED=0`) built in `golang:1.26-alpine`,
  running on `alpine:3.20`.

## Published image

Pull the image by tag or by digest:

```sh
docker pull ghcr.io/grwna/osiris:0.1.0
docker pull ghcr.io/grwna/osiris@sha256:46ea2d15e8dfc66ad4a960356f5d0068e6a08927a10efca25a4def037333dcd3
```

| Program version | GHCR image tag | Image digest |
|---|---|---|---|
| `0.1.0` | `0.1.0` | `sha256:46ea2d15e8dfc66ad4a960356f5d0068e6a08927a10efca25a4def037333dcd3` |

The image is published by running [`release.yml`](.github/workflows/release.yml)
manually (`workflow_dispatch`).

### Use from CI/CD

The consumer workflow [`.github/workflows/pipeline.yml`](.github/workflows/pipeline.yml)
runs on demand (`workflow_dispatch`), pulls this image, and runs it without a
TTY or network access. A minimal runner job, with the signing key passed
through a CI secret file (`SIGNING_KEY_FILE`):

```sh
IMAGE=ghcr.io/grwna/osiris@sha256:46ea2d15e8dfc66ad4a960356f5d0068e6a08927a10efca25a4def037333dcd3

set -eu
: "${SIGNING_KEY_FILE:?mandatory}"
trap 'rm -f "$SIGNING_KEY_FILE"' EXIT
docker pull "$IMAGE"
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" \
  -v "$SIGNING_KEY_FILE:/run/signing.key.pem:ro" "$IMAGE" \
  sign --file /input/app.zip --package contoh-app --version 1.0.0 \
  --key /run/signing.key.pem --out /output/app.bundle.json
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output:ro" \
  -v "$PWD/ci/trust.json:/trust.json:ro" "$IMAGE" \
  verify --file /input/app.zip --bundle /output/app.bundle.json \
  --trust-store /trust.json --package contoh-app --version 1.0.0 --json \
  > out/verification.json
```

## Commands

1. Generate a key pair. This writes `<prefix>.key.pem` (mode `0600`) and
`<prefix>.pub.pem`. Overwriting existing key files requires `--force`:

```sh
osiris keygen --algorithm ed25519 --out keys/release
```

2. Add a public key to a trust store after verifying its printed fingerprint out of band:

```sh
osiris trust add --store ci/trust.json --key keys/release.pub.pem --package contoh-app
osiris trust list --store ci/trust.json
osiris trust list --store ci/trust.json --json
osiris trust remove --store ci/trust.json --keyid <64-character-keyid>
```

3. Sign and verify a release artifact. Overwriting an existing bundle requires `--force`:

```sh
osiris sign --file app.zip --package contoh-app --version 1.0.0 \
  --key keys/release.key.pem --out app.bundle.json
osiris verify --file app.zip --bundle app.bundle.json --trust-store ci/trust.json \
  --package contoh-app --version 1.0.0 --json
```

4. Generate, sign, and verify a signed SBOM tied to the release artifact:

```sh
osiris sbom generate --file app.zip --package contoh-app --version 1.0.0 --out sbom.json
osiris sbom sign --sbom sbom.json --file app.zip --package contoh-app --version 1.0.0 \
  --key keys/release.key.pem --out sbom.bundle.json
osiris sbom verify --file app.zip --bundle app.bundle.json --sbom sbom.json \
  --sbom-bundle sbom.bundle.json --trust-store ci/trust.json \
  --package contoh-app --version 1.0.0 --json
```

Help and version:

```sh
osiris --help
osiris keygen --help
osiris --version
```

Exit codes: `0` success, `1` verification rejection or invalid format, `2` input,
usage, or I/O error. `verify --json` emits one JSON object on stdout; diagnostics go
to stderr.

## File formats

- **Keys:** private PKCS#8 PEM (`PRIVATE KEY`); public SubjectPublicKeyInfo PEM
  (`PUBLIC KEY`). RSA keys are 3072-bit with exponent 65537; ECDSA uses P-256;
  Ed25519 uses the standard 32-byte public key.
- **Manifest:** canonical JSON using schema `minisign-manifest/v1`, containing
  package, version, algorithm, key fingerprint, and artifact basename, byte size,
  and lowercase SHA-256.
- **Bundle:** JSON schema `minisign-bundle/v1` containing Base64 manifest and
  signature fields. The signature covers the canonical manifest bytes.
- **Trust store:** JSON schema `minisign-trust/v1`, with public key, matching
  fingerprint and algorithm, and an explicit package allowlist. Verification never
  adds keys to the store.
- **Signed SBOM:** a separate bundle using the same manifest, signature, and trust
  rules; the SBOM must reference the release artifact SHA-256.

## Algorithm to Go API mapping

| Profile | Go standard-library API | Signature representation |
|---|---|---|
| `rsa-pss-sha256` | `crypto/rsa.SignPSS` / `VerifyPSS`, SHA-256, MGF1-SHA-256, 32-byte salt | 384 bytes; RSA-3072, exponent 65537 |
| `ecdsa-p256-sha256` | `crypto/ecdsa.SignASN1` / `VerifyASN1`, SHA-256, nonce from `crypto/rand` | Fixed-width `r || s`, 32 bytes each (64 total) |
| `ed25519` | `crypto/ed25519.Sign` / `Verify` | 64 bytes; signs the manifest bytes directly |

## Run locally and repeat tests

Build and run from source:

```sh
go build -o bin/osiris ./cmd/osiris
./bin/osiris --version
```

Run the Go tests and integration scripts:

```sh
go test ./...
bash tests/run_negative.sh
bash tests/interop/run_interop.sh
```

Integration-test runs and their outputs are recorded in
[`tests/evidence/README.md`](tests/evidence/README.md); the workflow itself is
[`.github/workflows/pipeline.yml`](.github/workflows/pipeline.yml).

## API Documentation

Hosted on GitHub Pages: [https://grwna.github.io/osiris/](https://grwna.github.io/osiris/)  
Local source: [`docs/index.html`](docs/index.html)

## Credits

- Documentation site template: [iDocs - One Page Documentation HTML Template](https://themeforest.net/user/harnishdesign/portfolio) by [HarnishDesign](https://www.harnishdesign.net/).
- Built with [Bootstrap](https://getbootstrap.com/), [jQuery](https://jquery.com/), [highlight.js](https://highlightjs.org/), [Magnific Popup](https://dimsemenov.com/plugins/magnific-popup/), and [Font Awesome](https://fontawesome.com/).

