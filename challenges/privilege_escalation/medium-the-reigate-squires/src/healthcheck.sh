#!/bin/sh
/usr/sbin/sshd -t && /usr/sbin/getcap /usr/local/bin/case-reader | grep -q cap_dac_override
