#!/bin/sh
printf '\n' | socat -T1 - TCP:127.0.0.1:31337 >/dev/null 2>&1
