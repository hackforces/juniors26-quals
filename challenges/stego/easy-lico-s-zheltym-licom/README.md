# Лицо с жёлтым лицом (stego/easy)

- Порт: `13431` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl http://127.0.0.1:13431/download/portrait.ppm -o portrait.ppm
```

## Условие (для игроков)

**RU:** Ватсон получил выцветший портрет неизвестного. Холмс считает, что его цвета говорят больше, чем кажется.
Личный снимок.

**EN:** Watson has received a faded portrait of an unknown person. Holmes believes its colours say more than they seem.
Personal snapshot.

## Решение

`download/portrait.ppm` — несжатый PPM (P6) 128×128, у всех пикселей выровненные
цвета (232, 194, 87|b). Сообщение спрятано в младших битах синего канала:

1. Разбираем заголовок PPM (`P6`, размер, maxval) — пиксельные данные начинаются
   после третьей строки.
2. Берём младший бит каждого синего значения (каждый 3-й байт), собираем биты в
   байты (MSB first).
3. Читаем поток байтов до терминатора NUL — это флаг.

Изображение генерируется из CTF_FLAG при старте контейнера.

## Проверка решения

```bash
python3 solve.py                # скачает portrait.ppm с http://127.0.0.1:13431
python3 solve.py portrait.ppm   # или локальный файл
```
