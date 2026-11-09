#!/bin/sh
set -eu
: "${CTF_FLAG:?Set CTF_FLAG before starting}"
exec python /app/server.py
