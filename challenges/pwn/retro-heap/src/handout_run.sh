#!/bin/sh
# retro-heap local runner: place chal, libc.so.6, ld-linux-x86-64.so.2 next to this script
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
chmod +x "$dir/chal" "$dir/ld-linux-x86-64.so.2" 2>/dev/null
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 exec "$dir/ld-linux-x86-64.so.2" --library-path "$dir" "$dir/chal"
