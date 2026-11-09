# The Red-Headed League (admin/easy)

- Порт: `13409` (переопределяется через `PORT`; внутри контейнера `22`, SSH)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
sshpass -p player ssh -p 13409 player@127.0.0.1   # логин player, пароль player
```

## Условие (для игроков)

**RU:** После сбоя в конторе Союза рыжих дежурный оставил для Холмса закрытый
стол справок. Найдите способ передать ему номер дела и получите последний ответ.

**EN:** After an outage at the Red-Headed League office, the duty clerk left a
closed information desk for Holmes. Find how to present the case number and
obtain the final reply.

Подключение: `ssh player@<host> -p <port>` (пароль `player`).

## Решение

Оболочка — case-shell: `help` перечисляет только имена команд
(`help, ss, cat, nc, exit`), аргументы не подсказываются; команда с любыми
другими аргументами отвечает «argument is not available».

1. `ss` — единственная информативная диагностика; показывает loopback-only
   «стол справок» на `127.0.0.1:4587`.
2. `nc 127.0.0.1 4587` (хост и порт берём из вывода `ss`) — баннер стола
   называет `/etc/red/card`.
3. `cat /etc/red/card` — читаем пер-инстансовый номер дела
   (`sha256(CTF_FLAG)[:16]`, в образе отсутствует).
4. `nc 127.0.0.1 4587` — предъявляем номер; стол отвечает флагом.

Порт-скан, shell escape и инъекция команды не предполагаются: номер дела —
runtime-значение, производное от флага.

## Проверка решения

```bash
python3 solve.py          # нужен ssh + sshpass на хосте
```
