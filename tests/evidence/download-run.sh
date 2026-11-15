#!/bin/sh
set -eu

usage() {
  echo "usage: $0 https://github.com/grwna/osiris/actions/runs/<run-id>" >&2
  exit 2
}

[ "$#" -eq 1 ] || usage
case "$1" in
  https://github.com/grwna/osiris/actions/runs/[0-9]*) run_id=${1##*/} ;;
  *) usage ;;
esac
case "$run_id" in
  *[!0-9]*|'') usage ;;
esac

evidence_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination="$evidence_dir/$run_id"
[ ! -e "$destination" ] || {
  echo "evidence destination already exists: $destination" >&2
  exit 1
}

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
gh run download "$run_id" --repo grwna/osiris --dir "$tmp_dir"

mkdir -p "$destination/C01" "$destination/C02" "$destination/C03" "$destination/C04" "$destination/C05"
found=false
for artifact in "$tmp_dir"/*; do
  [ -e "$artifact" ] || continue
  artifact_name=${artifact##*/}
  case "$artifact_name" in
    C01-ecdsa-p256-sha256-evidence) target="$destination/C01/ecdsa-p256-sha256" ;;
    C01-ed25519-evidence) target="$destination/C01/ed25519" ;;
    C01-rsa-pss-sha256-evidence) target="$destination/C01/rsa-pss-sha256" ;;
    C02-evidence) target="$destination/C02" ;;
    C03-evidence) target="$destination/C03" ;;
    C04-evidence) target="$destination/C04" ;;
    *)
      echo "unrecognized artifact name: $artifact_name" >&2
      exit 1
      ;;
  esac
  mkdir -p "$target"
  mv "$artifact"/* "$target/"
  found=true
done
[ "$found" = true ] || {
  rm -rf "$destination"
  echo "run $run_id contained no downloadable artifacts" >&2
  exit 1
}

cat > "$destination/C05/README.md" <<EOF
# C05 evidence

Run: https://github.com/grwna/osiris/actions/runs/$run_id

C05 runs in each C01 algorithm job. The workflow invokes the pinned image with the
runner UID/GID and `--network none`. Succesful C01 runs means C05 is also succesful. 
EOF

echo "Extracted run $run_id artifacts into scenario directories at $destination"
