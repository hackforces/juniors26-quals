#!/bin/sh
set -eu
machine_id=$(cat /etc/machine-id)
slot=$(cat /etc/treaty/slot)
printf '%s:%s' "$machine_id" "$slot" | sha256sum | cut -c1-20
