#!/bin/sh
set -eu
mkdir -p "$1"
printf 'ledger synchronised\\n' >> "$1/archive.log"
