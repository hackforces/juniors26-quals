# Убийство в Эбби-Грейндж (forensic/medium)

- Порт: `13415` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl http://127.0.0.1:13415/download/abbey.zip -o abbey.zip
```

## Условие (для игроков)

**RU:** Инспектор получил резервную копию телефона и сетевой след ночной отправки.
Восстановите, что именно было передано с устройства.

**EN:** The inspector has received a phone backup and the network trace of a night-time transfer.
Reconstruct exactly what was sent from the device.

## Решение

Артефакт `download/abbey.zip` — резервная копия Android (SQLite-база мессенджера,
shared preferences, settings_secure, bugreport с уведомлением, лог приложения и PCAP).

1. **Уведомление** (`bugreport/notifications.txt`) указывает диалог `abbey-47`.
2. **Корреляция по uuid.** В той же SQLite-базе лежат два диалога-приманки
   (`abbey-12`, `abbey-31`) со своими uuid вложений, а в PCAP есть две
   декойные `MOBILE/<uuid>/...` записи — одна из них стоит РАНЬШЕ настоящей,
   поэтому «взять первую запись» не работает. Из строки `abbey-47` в
   `databases/messages.db` берём её `attachment_uuid` и ищем в PCAP запись
   `MOBILE/<uuid>/<nonce>/<ciphertext>`, у которой поле uuid совпадает.
3. **Ключ.** `upload_seed` — из `shared_prefs/device.xml` (base64), `android_id` —
   из `settings_secure.xml`. По логу приложения:
   `key = SHA-256(upload_seed || android_id)`.
4. **Поток.** Конструкция задокументирована в `app-log.txt`:
   `SHA-256(key || nonce || counter_be_32)`, XOR — расшифровываем ciphertext
   найденной записи и получаем флаг.

Все идентификаторы, ключевой материал и шифртекст PCAP генерируются на инстанс.
Задача — мобильная форензика бэкапа, не реверс APK.

## Проверка решения

```bash
python3 solve.py            # скачает abbey.zip с http://127.0.0.1:13415
python3 solve.py abbey.zip  # или локальный файл
```
