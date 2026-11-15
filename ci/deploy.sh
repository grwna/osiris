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
