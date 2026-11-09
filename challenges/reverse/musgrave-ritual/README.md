# The Musgrave Ritual (reverse/hard)

- Порт: `13429` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG` — архив с верификатором генерируется при
  старте контейнера
- Уровень: hard (tags: juniors, sherlock-2050)

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl -OJ http://127.0.0.1:13429/download/musgrave-ritual.zip
```

## Условие (для игроков)

**RU:** В 2050 году старый ритуал сохранился в карманном архиваторе семьи
Масгрейвов. Восстановите его последнюю запись.

**EN:** In 2050, the old ritual survives in the Musgrave family's pocket
archivist. Restore its final entry.

## Решение

`ritual_device.py` полностью определяет верификатор, но отвечает только
accepted/rejected — флаг нужно восстановить анализом. Архив называется
`musgrave-ritual.zip`:

1. Извлечь из верификатора `SEED` (8 байт sha256 от флага) и `TARGET`
   (перемешанные преобразованные байты).
2. Воспроизвести hash-порядок `order = sorted(range(n), key=sha256(SEED ||
   i_be16))` и обратить перестановку `TARGET`: `stage[order[pos]] =
   TARGET[pos]`.
3. Обратить stateful-преобразование слева направо: для каждого байта
   `state = (previous_plain*13 + i*29 + 7) & 255`, затем
   `plain = ror(value, (i%5)+1) ^ SEED[i%8] ^ state`; `previous_plain`
   обновляется уже расшифрованным байтом.
4. Результат — персональный флаг (пунктуация в теле флага тоже
   обрабатывается корректно).

Артивакт генерируется при старте из текущего `CTF_FLAG`; в образе и
репозитории флага нет.

## Проверка решения

```bash
python3 solve.py   # скачивает архив с 127.0.0.1:13429 и печатает флаг
```
