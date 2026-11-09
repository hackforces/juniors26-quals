#!/bin/sh
# Blockpost entrypoint: генерирует хэндаут из CTF_FLAG на старте (не в build),
# проверяет его авторским солвером и только потом поднимает раздачу.
set -e

[ -n "${CTF_FLAG:-}" ] || { echo "entrypoint: CTF_FLAG must be set" >&2; exit 1; }

cd /app

# HARD — необязательные усложнения генератора, напр. "--axis z --lossy"
# shellcheck disable=SC2086
python3 -m mc_blockpost gen --flag "$CTF_FLAG" \
    --out-dir public --zip blockpost.zip $HARD

# self-check: авторский солвер обязан решить то, что мы раздаём
python3 solve.py blockpost.zip --expect "$CTF_FLAG"

exec python3 -u src/server.py
