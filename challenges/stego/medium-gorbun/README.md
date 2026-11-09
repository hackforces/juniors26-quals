# Горбун (stego/medium)

- Порт: `13433` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl http://127.0.0.1:13433/download/bell.wav -o bell.wav
```

## Условие (для игроков)

**RU:** В старом фоноархиве нашёлся короткий сигнал. Его автор не доверял ни словам, ни тишине.
Файл вашей лаборатории.

**EN:** A short signal has turned up in an old sound archive. Its author trusted neither words nor silence.
Your laboratory file.

## Решение

`download/bell.wav` — моно WAV, 8 кГц, 16-битные PCM-семплы. Сообщение спрятано
в младших битах семплов:

1. Читаем кадры WAV, интерпретируем как little-endian int16.
2. Берём младший бит каждого семпла, собираем биты в байты (MSB first).
3. Читаем поток до NUL-терминатора — это флаг.

Файл генерируется из CTF_FLAG при старте контейнера.

## Проверка решения

```bash
python3 solve.py            # скачает bell.wav с http://127.0.0.1:13433
python3 solve.py bell.wav   # или локальный файл
```
