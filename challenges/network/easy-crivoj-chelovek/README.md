# Кривой человек / The Crooked Man (network/easy)

- Порт: `13416` (переопределяется через `PORT`; внутри контейнера `8080`, HTTP)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
open http://127.0.0.1:13416/download/scene.pcap
```

## Условие (для игроков)

**RU:** В кабинете Ватсона сохранился единственный снимок разговора с
роботом-курьером. Найдите запись, которую курьер пытался передать Холмсу.
Файл доступен в вашей личной лаборатории

**EN:** Watson's study keeps the only capture of a conversation with a courier
robot. Find the record the courier tried to pass to Holmes.
The file is available in your personal laboratory

## Решение

Дамп теперь выглядит как настоящая ночная сессия (~20 КБ, ~100 пакетов):
ARP, DNS, HTTP-панель дома на Бейкер-стрит (HTML/CSS/JSON), PNG с камеры,
TLS-подобный bulk-поток и несколько `POST /watson-note` — декой-напоминания
без ключевого материала. Чексуммы и seq/ack валидны: Wireshark ничего не
помечает битым, Follow TCP Stream собирается.

1. Wireshark → Statistics → Conversations: несколько HTTP-сессий к
   `baker.local` (10.42.0.15) и один HTTPS-подобный поток.
2. Перебираем HTTP-потоки (Follow TCP Stream): у курьерского бота
   (`User-Agent: CourierBot/2.3`) тело POST — `message=<флаг>`; это
   единственный payload с фигурными скобками во всём дампе.
3. Быстрая проверка «в лоб»: `strings scene.pcap | grep -E '\w+\{[^}]+\}'`.

## Проверка решения

```bash
python3 solve.py
```
