#!/bin/sh
# prequals: refuse to start without a flag.
set -eu
: "${CTF_FLAG:?Set CTF_FLAG before starting}"
mkdir -p /app/data
exec uvicorn app.main:app --host 0.0.0.0 --port 8080
