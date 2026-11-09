# Дело о шести Наполеонах (privilege_escalation/easy)

- Порт: `13422` (переопределяется через `PORT`; внутри контейнера `22`/ssh)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
ssh player@127.0.0.1 -p 13422   # пароль: player
```

## Условие (для игроков)

**RU:** Шесть бюстов Наполеона, одна инвентарная книга — и картотека, которую
смотритель лаборатории держит при себе: читать её машина разрешает только
смотрителю. Дежурному доверяют меньше, чем ему кажется, — узнайте, чему
именно, и доберитесь до записи.

**EN:** Six busts of Napoleon, one inventory book — and the card file the keeper
keeps to himself: only the keeper may read it. The duty clerk is trusted with
less than he thinks — find out what exactly, and reach the record.

## Решение

Заходим по SSH опубликованной учёткой `player` и осматриваем разрешённые ей
команды обслуживания: `sudo -l` показывает, что полный `/usr/bin/find` запущен
от root без пароля (`/etc/sudoers.d/case`).

У `find` есть действие выполнения команд (`-exec`), поэтому поднимаем root- shell
точечно и читаем `/root/flag`:

```bash
sudo -n /usr/bin/find /usr -maxdepth 0 -exec /bin/sh -c 'cat /root/flag' \; -quit
```

Флага нет в образе — entrypoint создаёт `/root/flag` из env `CTF_FLAG` после
старта (root:root, 0600, с настоящим переводом строки в конце).

## Проверка решения

```bash
python3 solve.py            # цель по умолчанию 127.0.0.1:13422 (нужен sshpass)
python3 solve.py 127.0.0.1:13422
```
