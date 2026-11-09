# The Empty House (reverse/easy)

- Порт: `13428` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG` — вживается в архив при старте контейнера
- Уровень: easy (tags: juniors, sherlock-2050)

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl -OJ http://127.0.0.1:13428/download/empty-house.zip
```

## Условие (для игроков)

**RU:** В пустующем доме на Бейкер-стрит найден карманный вычислитель.
Восстановите записку, которую он прячет.

**EN:** A pocket computer was recovered from an empty house on Baker Street.
Recover the note it is hiding.

## Решение

1. Скачать `empty-house.zip` (или открыть `/download/empty-house.zip`) и распаковать:
   внутри `pocket_computer.py` и `README.txt`.
2. `pocket_computer.py` содержит байтовую строку `blob` и однобайтовое
   преобразование с ключом `0x5A`.
3. Запустить программу как есть (она сама печатает расшифровку) или
   применить XOR вручную: `"".join(chr(x ^ 0x5A) for x in blob)` — это
   персональный флаг.
4. Архив генерируется при старте из текущего `CTF_FLAG`; в образе и
   репозитории флага нет.

## Проверка решения

```bash
python3 solve.py   # скачивает архив с 127.0.0.1:13428 и печатает флаг
```
