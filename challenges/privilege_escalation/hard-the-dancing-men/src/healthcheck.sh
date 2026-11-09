#!/bin/sh
/usr/sbin/sshd -t && test -w /srv/ledger/runtime.conf
