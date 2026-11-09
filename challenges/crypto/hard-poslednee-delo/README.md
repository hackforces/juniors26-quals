# Последнее дело (crypto/hard)

- Порт: `13411` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl http://127.0.0.1:13411/download/telemetry.json -o telemetry.json
```

## Условие (для игроков)

**RU:** В архиве Бейкер-стрит сохранилась телеметрия неисправного карманного подписчика и закрытое последнее сообщение.
Разберитесь в повторяющемся следе устройства и восстановите послание.

**EN:** The Baker Street archive keeps telemetry from a faulty pocket signer and the sealed final message.
Make sense of the device's recurring trace and recover the dispatch.

## Решение

Артефакт `download/telemetry.json` содержит 7 ECDSA-подписей (secp256k1) и зашифрованное
флагом сообщение. Для каждой подписи выполняется `s*k = z + r*d (mod n)`. Телеметрия
сообщает, что младшие 32 бита nonce («счётный регистр») у всех захватов одинаковые:
`k_i = nonce_high_i * 2^32 + tail`, где `nonce_high_i` известен, `tail` — нет.

Подставляем это в уравнения двух подписей, исключаем приватный ключ `d` и решаем одно
линейное сравнение относительно `tail`:

```
tail = (r1*a2 - r2*a1) * (r2*s1 - r1*s2)^(-1) mod N,  где a_i = s_i*h_i*2^32 - z_i
```

Подставив `tail` обратно в `d = (s1*k1 - z1) / r1 mod N`, получаем приватный ключ.
Ключ потока задокументирован в артефакте: `SHA-256(private_key_be_32)`, гамма —
`SHA-256(key || nonce || counter_be_32)`, XOR с шифртекстом. Общий хвост nonce заявлен
в телеметрии явно — его не нужно угадывать или брутфорсить; остальные захваты независимо
подтверждают восстановленный ключ.

## Проверка решения

```bash
python3 solve.py                 # скачает telemetry.json с http://127.0.0.1:13411
python3 solve.py telemetry.json  # или локальный файл
```
