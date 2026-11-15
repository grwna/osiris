#!/bin/sh
set -eu

out=${1:-bench/artifacts}
mkdir -p "$out"
dd if=/dev/zero of="$out/artifact-1KiB.bin" bs=1024 count=1 status=none
dd if=/dev/zero of="$out/artifact-1MiB.bin" bs=1048576 count=1 status=none
dd if=/dev/zero of="$out/artifact-64MiB.bin" bs=1048576 count=64 status=none
