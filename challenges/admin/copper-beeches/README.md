# The Copper Beeches (admin/medium)

- Порт: `13406` (переопределяется через `PORT`; внутри контейнера `22`, SSH)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
sshpass -p player ssh -p 13406 player@127.0.0.1   # логин player, пароль player
```

## Условие (для игроков)

**RU:** В усадьбе Медных буков курьер перестал отвечать на обычные записки.
Восстановите порядок ночной доставки и получите его ответ.

**EN:** At the Copper Beeches estate, the courier no longer responds to ordinary notes.
Reconstruct the night-delivery procedure and obtain its reply.

Подключение: `ssh player@<host> -p <port>` (пароль `player`).

## Решение

Оболочка игрока — ограниченный `case-shell` с командами `help, read, listen, courier, exit`
(`help` сам раскрывает словарь доставки).

1. `read /etc/copper/token` — читаем токен ночной доставки (24 hex-символа,
   производное от флага).
2. Открываем **вторую** SSH-сессию: в первой `listen 23456` — локальный
   netcat-приёмник на loopback, сессию держим открытой.
3. Во второй сессии запускаем `courier 23456` — setuid-курьер подключается
   к слушателю и ждёт токен.
4. В первой сессии (stdin слушателя) вводим токен. Courier сверяет его с
   `/etc/copper/token`, делает `setuid(0)`, читает `/root/flag` и отправляет
   флаг обратно через loopback-соединение.

Обходов нет: без слушателя courier не подключится, токен не брутфорсится,
shell escape отсутствует.

## Проверка решения

```bash
python3 solve.py          # нужен ssh + sshpass на хосте
```
