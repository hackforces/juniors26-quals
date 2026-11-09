# The Naval Treaty (admin/hard)

- Порт: `13407` (переопределяется через `PORT`; внутри контейнера `22`, SSH)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
sshpass -p player ssh -p 13407 player@127.0.0.1   # логин player, пароль player
```

## Условие (для игроков)

**RU:** Архив Морского договора отвечает только доверенным служебным печатям.
На рабочей станции остались следы ночной ротации. Восстановите доступ к последнему бюллетеню.

**EN:** The Naval Treaty archive answers only trusted service seals.
The workstation retains traces of a night rotation. Restore access to the final bulletin.

Подключение: `ssh player@<host> -p <port>` (пароль `player`).

## Решение

Оболочка — `case-shell` с командами `ports, unit, journal, read, extract, connect`.

1. Разведка: `ports` (TLS-листенер только на `127.0.0.1:9443`), `unit`
   (`treaty-archive.service` — архив с mTLS-клиентской печатью),
   `journal` (ротация скопировала печать в `/var/backups/treaty-client.p12`,
   пароль печати выводится скриптом `/usr/local/bin/derive-pass.sh`, слот —
   `/etc/treaty/slot`; целевой бюллетень — эпоха `2050.06.17-04`).
   Упомянутый в юните `/etc/treaty/archive.env` не создаётся и для
   `read` недоступен — честный тупик: whitelist читаемого избирателен.
2. В whiteliste `read` — `/etc/machine-id`, `/etc/treaty/slot` и
   `/usr/local/bin/derive-pass.sh`. Скрипт деривации:
   `sha256("<machine-id>:<slot>")` → первые 20 hex-символов = пароль PKCS#12.
3. `extract <pass>` — расшифровывает `/var/backups/treaty-client.p12` в
   `/tmp/treaty-client.pem` («client seal restored»).
4. `connect` — mTLS-клиент к архиву; команда `LIST` показывает эпохи,
   `FETCH 2050.06.17-04` возвращает флаг (env `CTF_FLAG`).

Сертификаты статичны; персонален только ответ архива.

## Проверка решения

```bash
python3 solve.py          # нужен ssh + sshpass на хосте
# TLS-обёртка (ssh поверх 443):
SOLVE_SSH_OPTS='-o "ProxyCommand=openssl s_client -quiet -connect <host>:443 -servername <host>"' \
  python3 solve.py <host> 22
```
