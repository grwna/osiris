#!/usr/bin/env bash
# Interoperability test: bundles produced by osiris are verified by independent
# implementations (python `cryptography` for all profiles, OpenSSL CLI for
# rsa-pss-sha256 and ed25519). OpenSSL is used ONLY as a test oracle.
#
# Usage (from repo root):  bash tests/interop/run_interop.sh [path/to/osiris]
set -eu

BIN="${1:-go run ./cmd/osiris}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
HERE="tests/interop"
KEYS="tests/keys"
printf 'interop artifact bytes\n' > "$WORK/app.bin"
fail=0

check() { # name command...
  name="$1"; shift
  if "$@" >"$WORK/out.txt" 2>&1; then echo "PASS  $name"; else echo "FAIL  $name"; cat "$WORK/out.txt"; fail=1; fi
}

for pair in rsa-pss-sha256:test-rsa ecdsa-p256-sha256:test-ecdsa ed25519:test-ed25519; do
  profile="${pair%%:*}"; prefix="${pair##*:}"
  bundle="$WORK/$profile.json"
  $BIN sign --file "$WORK/app.bin" --package interop-app --version 1.0.0 \
    --key "$KEYS/$prefix.key.pem" --out "$bundle" 2>/dev/null
  check "python-cryptography verifies $profile" \
    python3 "$HERE/interop.py" verify "$bundle" "$KEYS/$prefix.pub.pem"

  python3 "$HERE/interop.py" extract "$bundle" "$WORK/$profile.d"
  M="$WORK/$profile.d/manifest.bin"; S="$WORK/$profile.d/sig.bin"
  case "$profile" in
    rsa-pss-sha256)
      check "openssl verifies $profile (PSS, MGF1-SHA256, salt 32)" \
        openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
          -sigopt rsa_mgf1_md:sha256 -verify "$KEYS/$prefix.pub.pem" -signature "$S" "$M" ;;
    ed25519)
      check "openssl verifies $profile (raw message, no pre-hash)" \
        openssl pkeyutl -verify -pubin -inkey "$KEYS/$prefix.pub.pem" -rawin -in "$M" -sigfile "$S" ;;
  esac
done

# Reverse direction: signatures made by python-cryptography verify in osiris.
python3 "$HERE/interop.py" make-fixtures >/dev/null
check "osiris verifies signatures made by python-cryptography (go test)" \
  go test ./internal/crypto -run TestExternalSignatures -count=1

[ "$fail" -eq 0 ] && echo "ALL INTEROP CHECKS PASSED" || { echo "SOME INTEROP CHECKS FAILED"; exit 1; }
