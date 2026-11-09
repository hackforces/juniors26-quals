# Дело о скандале в нео-Богемия / A Scandal in Neo-Bohemia (web/easy)

- Порт: `13434` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG` (base64-кодируется в клиентский скрипт
  при каждом запросе)

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
open http://127.0.0.1:13434/
```

## Условие (для игроков)

**RU:** Ватсон получил страницу из личного архива Ирен. Найдите последнее
сообщение, оставленное для детективов.

**EN:** Watson received a page from Irene's private archive. Find the final
message left for the detectives.

## Решение

1. Открыть главную страницу: `<h1>Irene's private archive</h1>` и подсказка,
   что «клиент помнит больше, чем показывает»; страница подключает
   `/assets/client.js`.
2. Открыть исходник скрипта: в нём
   `window.caseMemo = '<base64>'` — значение рендерится из `CTF_FLAG`
   при запросе.
3. Декодировать base64 — это и есть флаг.

Однострочник:
`curl -s http://127.0.0.1:13434/assets/client.js | sed -n "s/.*'\([^']*\)'.*/\1/p" | base64 -d`

## Проверка решения

```bash
python3 solve.py   # скачивает client.js с 127.0.0.1:13434 и печатает флаг
```
