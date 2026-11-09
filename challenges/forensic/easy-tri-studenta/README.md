# Три студента (forensic/easy)

- Порт: `13413` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl http://127.0.0.1:13413/download/students.zip -o students.zip
```

## Условие (для игроков)

**RU:** После аварии лабораторного агента остались первичные выгрузки снимка памяти и закрытая записка.
Определите, какой процесс оставил её рабочий материал, и восстановите сообщение Холмса.

**EN:** After a laboratory agent's crash, raw exports of a memory snapshot and a sealed note remain.
Determine which process left its working material behind and recover Holmes's message.

## Решение

Архив `download/students.zip` содержит выгрузки Volatility 3 и запечатанную записку
`sealed-note.json`. В выгрузке процессов есть записи-приманки (`svchost.exe`,
`explorer.exe`, `RuntimeBroker.exe`), чьи окружения не содержат материала дела —
предположение об одиночном PID из pstree неверно.

1. Открываем `volatility/windows.envars.txt` и ищем окружение с переменной
   `CASE_SEAL_KEY` — она есть только у `case-agent.exe` (PID 4172): это процесс,
   оставивший рабочий материал.
2. Берём `CASE_SEAL_KEY` (hex) как ключ, читаем `sealed-note.json`.
3. Применяем задокументированную в записке конструкцию потока:
   гамма `SHA-256(key || nonce || counter_be_32)`, XOR с `ciphertext` — получаем флаг.

ZIP генерируется из CTF_FLAG при старте контейнера.

## Проверка решения

```bash
python3 solve.py              # скачает students.zip с http://127.0.0.1:13413
python3 solve.py students.zip # или локальный файл
```
