# Дело о пропавшей квантовой книге / The Missing Quantum Ledger (web/hard)

- Порт: `13435` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG` (отдаётся `/vault` бейджу с ролью
  `inspector`)

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
open http://127.0.0.1:13435/
```

## Условие (для игроков)

**RU:** Доступ к хранилищу зарезервирован для сотрудников с особым допуском.
Докажите, что ваше дело срочное.

**EN:** Vault access is reserved for staff holding a special clearance.
Prove that your case is urgent.

## Решение

1. Главная страница подключает `/assets/terminal.js` — «совместимый клиент
   терминалов Скотленд-Ярда». Скрипт называет три эндпоинта: `/badge`,
   `/vault` и `/assets/old-manifest.json` — угадывать пути не нужно.
2. `/badge` выдаёт легитимный visitor-бейдж; его полезная нагрузка
   раскрывает формат токена: `base64url(json).base64url(hmac-sha256)`.
3. Отправить visitor-бейдж в `/vault` (cookie `badge=`) → 403 c телом
   `vault is inspector-grade; badge rejected` — отказ сам называет роль,
   которую должен нести куённый токен.
4. `/assets/old-manifest.json` — «манифест совместимости» с полем
   `legacy_signing_key`: в нём утёк ключ подписи (ключ — не флаг,
   флаг живёт только в env инстанса).
5. Куём токен: payload `base64url({"role":"inspector"})`, подпись
   HMAC-SHA256 от payload тем ключом, тоже base64url без `=`.
6. `GET /vault` с cookie `badge=<payload>.<sig>` → флаг.

Перебор каталогов не требуется и не является частью авторского решения.

## Проверка решения

```bash
python3 solve.py   # проходит весь киллчейн против 127.0.0.1:13435
```
