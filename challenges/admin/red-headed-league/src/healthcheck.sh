#!/bin/sh
/usr/sbin/sshd -t && /usr/bin/ss -lnt | grep -q ':4587'
