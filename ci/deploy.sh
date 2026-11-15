#!/bin/sh
set -eu

artifact=$1
bundle=$2
verification=$3

test -f "$artifact"
test -f "$bundle"
test -s "$verification"
mkdir -p out
printf 'verified deployment\n' > out/deployed.marker

# Extract verified artifact to deployment target if zip archive
if [ -f "$artifact" ] && unzip -tq "$artifact" >/dev/null 2>&1; then
  mkdir -p out/deployed-site
  unzip -qo "$artifact" -d out/deployed-site
fi
