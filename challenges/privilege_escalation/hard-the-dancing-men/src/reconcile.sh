#!/bin/bash
set -euo pipefail
source /srv/ledger/runtime.conf
/usr/local/bin/archive-ledger "$ARCHIVE_TARGET"
echo "Morning reconciliation completed."
