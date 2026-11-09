#!/bin/sh
set -eu
: "${CTF_FLAG:?Set CTF_FLAG before starting}"
export CTF_FLAG
exec python /app/server.py
