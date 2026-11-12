#!/usr/bin/env bash
# bash tests/run_negative.sh
set -u
ROOT=$PWD
OSIRIS=$ROOT/bin/osiris$(go env GOEXE)
KEYS=$ROOT/tests/keys
go build -o "$OSIRIS" ./cmd/osiris || exit 2
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
pass=0
fail=0

setup() {
  rm -f ./*
  echo "hello release" > app.zip
  $OSIRIS sign --file app.zip --package app --version 1.0.0 --key "$KEYS/$1.key.pem" --out b.json 2>/dev/null
  $OSIRIS trust add --store t.json --key "$KEYS/$1.pub.pem" --package app > /dev/null 2>&1
}

check() {
  out=$($OSIRIS verify --file "${4:-app.zip}" --bundle b.json --trust-store t.json --package app --version "${5:-1.0.0}" --json 2>/dev/null)
  code=$?
  if [[ $out == *"\"status\":\"$2\""* && $code == "$3" ]]; then
    echo "PASS $1"; pass=$((pass + 1))
  else
    echo "FAIL $1 -> $out (exit $code)"; fail=$((fail + 1))
  fi
}

manifest() { grep -o '"manifest_b64": *"[^"]*"' b.json | cut -d'"' -f4; }
signature() { grep -o '"signature_b64": *"[^"]*"' b.json | cut -d'"' -f4; }
write_bundle() { echo "{\"schema\":\"minisign-bundle/v1\",\"manifest_b64\":\"$1\",\"signature_b64\":\"$2\"}" > b.json; }
edit_manifest() { write_bundle "$(manifest | base64 -d | sed "$1" | base64 -w0)" "$(signature)"; }

for key in test-rsa test-ecdsa test-ed25519; do
  setup $key; check "U01 $key teks" OK 0
  setup $key; printf '\x00\xff\x10' > app.zip; $OSIRIS sign --file app.zip --package app --version 1.0.0 --key "$KEYS/$key.key.pem" --out b.json --force 2>/dev/null
  check "U01 $key biner" OK 0
  setup $key; : > app.zip; $OSIRIS sign --file app.zip --package app --version 1.0.0 --key "$KEYS/$key.key.pem" --out b.json --force 2>/dev/null
  check "U01 $key kosong" OK 0
done

KEY=test-ed25519

setup $KEY; echo "hellO release" > app.zip
check "U02 ubah 1 byte artefak" ARTIFACT_MISMATCH 1

setup $KEY; echo "!" >> app.zip
check "U03 tambah byte artefak" ARTIFACT_MISMATCH 1

setup $KEY; edit_manifest 's/"version":"1.0.0"/"version":"1.0.1"/'
check "U04 ubah version di manifest" INVALID_SIGNATURE 1 app.zip 1.0.1

setup $KEY; signature | base64 -d > sig.bin
first=$(od -An -tu1 -N1 sig.bin)
{ printf "\\$(printf %o $((first ^ 1)))"; tail -c +2 sig.bin; } > sig2.bin
write_bundle "$(manifest)" "$(base64 -w0 sig2.bin)"
check "U05 flip 1 bit tanda tangan" INVALID_SIGNATURE 1

setup $KEY; echo '{"schema":"minisign-trust/v1","keys":[]}' > t.json
check "U06 trust store kosong" KEY_NOT_TRUSTED 1

setup $KEY; rm t.json; $OSIRIS trust add --store t.json --key "$KEYS/$KEY.pub.pem" --package other > /dev/null 2>&1
check "U07 kunci untuk paket lain" KEY_NOT_TRUSTED 1

setup $KEY
check "U08 versi berbeda" METADATA_MISMATCH 1 app.zip 2.0.0

setup $KEY; mv app.zip app2.zip
check "U09 rename artefak" METADATA_MISMATCH 1 app2.zip

setup $KEY; sed -i 's/"schema"/"schema": "x", "schema"/' b.json
check "U10 field duplikat" FORMAT_ERROR 1

setup $KEY; edit_manifest 's/"size":\([0-9]*\)/"size":"\1"/'
check "U10 tipe salah" FORMAT_ERROR 1

setup $KEY; write_bundle "$(manifest)" " $(signature)"
check "U10 Base64 invalid" FORMAT_ERROR 1

setup $KEY; write_bundle "$(head -c 17000 /dev/zero | tr '\0' a | base64 -w0)" "$(signature)"
check "U10 manifest > 16 KiB" FORMAT_ERROR 1

setup $KEY; edit_manifest 's/"algorithm":"ed25519"/"algorithm":"ed448"/'
check "U11 algoritma tidak dikenal" UNSUPPORTED_ALGORITHM 1

setup $KEY; $OSIRIS keygen --algorithm ed25519 --out other > /dev/null 2>&1
$OSIRIS sign --file app.zip --package app --version 1.0.0 --key other.key.pem --out b.json --force 2>/dev/null
check "U12 kunci lain tidak dipercaya" KEY_NOT_TRUSTED 1

setup $KEY; printf '{\n  "signature_b64": "%s",\n\n  "schema" : "minisign-bundle/v1", "manifest_b64":"%s"\n}\n' "$(signature)" "$(manifest)" > b.json
check "U13 whitespace dan urutan field" OK 0

echo "$pass lulus, $fail gagal"
[ $fail -eq 0 ]
