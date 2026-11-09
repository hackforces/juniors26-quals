#!/bin/sh
export GLIBC_TUNABLES=glibc.malloc.tcache_count=0
cd /srv
exec timeout 180 ./chal
