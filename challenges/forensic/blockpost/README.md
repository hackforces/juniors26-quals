# Блокпост / The Blockpost (forensic/hard)

## Условие (для игроков)

**RU:** Ночью на наш игровой сервер зашёл игрок Kolya, провёл там минуту и вышел. Утром у спавна
нашли стену с надписью, но мир откатили из бэкапа раньше, чем кто-то её сфотографировал.
Kolya уверяет, что ничего не строил, и в доказательство прислал свой `latest.log`.
Сетевой сенсор сервера записал его подключение. Прочитайте, что было написано на стене.

**EN:** Overnight, a player named Kolya joined our game server, spent a minute and left. In the
morning a wall with writing was found near the spawn, but the world was rolled back from
backup before anyone could photograph it. Kolya insists he built nothing and sent his
`latest.log` as proof. The server's network sensor recorded his connection. Read what was
written on the wall.

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl -o blockpost.zip http://127.0.0.1:13400/
```

При старте контейнер сам собирает хэндаут из `src/`: генерирует `blockpost.zip`
из `CTF_FLAG` (усложнения — через env `HARD`, например `HARD='--axis z --lossy'`),
затем авторский солвер решает получившийся архив с `--expect "$CTF_FLAG"` и валит
старт при несовпадении. В образе нет ни исходников хэндаута-артефактов, ни флага:
флаг существует только как координаты блоков внутри зашифрованного трафика и
передаётся исключительно через env.

Смена флага или усложнений — без пересборки:

```bash
CTF_FLAG='InnoCTF{...}' HARD='--axis z --lossy' docker compose up -d --force-recreate
```

## Выдать участникам

Ссылку `http://<host>:13400/`, по ней скачивается `blockpost.zip`:

- `challenge.pcap` — дамп трафика клиента `10.0.0.50` с сервером `10.0.0.10:25565`;
- `latest.log` — лог клиента Kolya (Fabric + отладочный мод `netdebug`).

Генерация детерминирована: при одинаковых `CTF_FLAG`/`HARD` повторные запуски дают
побайтно одинаковый архив.

## Проверка решения

```bash
python3 solve.py blockpost.zip                       # решить скачанный архив
python3 solve.py blockpost.zip --expect 'InnoCTF{...}'  # + сверка с ожидаемым флагом
```

## Описание

Злоумышленник зашёл на Minecraft-сервер (Java Edition 26.3, protocol 777, online mode) и
«принтером» выложил на каменной стене у спавна надпись красной шерстью: каждый символ — сетка
5×5, между символами один пустой столбец. Сервер рассылает клиенту каждое изменение мира пакетом
`block_update`, так что надпись целиком есть в записанном трафике. Но соединение настоящее:
после обмена ключами всё в обе стороны идёт через AES-128/CFB8 и zlib-компрессию.

В pcap два TCP-соединения. Первое — status ping из списка серверов, открытым текстом. Второе —
сама игра:

1. handshake и `Login Start`;
2. `Encryption Request` с RSA-ключом сервера и verify token;
3. `Encryption Response` с RSA-зашифрованным shared secret;
4. дальше шифртекст: `Set Compression (256)` → `Login Success` → configuration (реестры, теги)
   → play (чанки, перемещения, `Use Item On`, `block_update`, keep-alive).

Приватного ключа RSA нет, поэтому секрет добывается из второго артефакта. Отладочный мод в
клиенте Kolya пишет в `latest.log` verify token и shared secret каждой сессии. В логе четыре
сессии, три из них к тому же серверу, и у двух совпадает отпечаток ключа сервера. Нужная
находится по verify token, который виден в pcap открытым текстом.

Дальше прежняя линия: расшифровать поток сервера → нарезать кадры по VarInt-длине с учётом
компрессии → пройти фазы `login → configuration → play` → вытащить `block_update` (`0x08`) →
декодировать `Position` → спроецировать на плоскость стены → прочитать буквы 5×5.

## Решение

Подробно: [WALKTHROUGH.md](WALKTHROUGH.md) — полный райтап, лестница подсказок, разбор ложных следов.

1. Порт `25565`, handshake с версией `777` и status-JSON `{"name":"26.3","protocol":777}` →
   Minecraft Java Edition 26.3.
2. В login-соединении открытым текстом лежат `Encryption Request` (verify token виден в pcap)
   и `Encryption Response`. Всё после них — шифртекст.
3. В `latest.log` ищем `verify_token=<token>` → строка `cipher enabled: AES/CFB8/NoPadding
   secret=<hex>`. Время в логе МСК, в pcap — UTC, что тоже подтверждает выбор.
4. AES-128/CFB8, key = IV = secret, отдельный непрерывный поток на каждое направление, начиная
   с первого байта после `Encryption Response`/`Request`. Первый расшифрованный кадр сервера —
   `03 03 80 02` (Set Compression, порог 256).
5. Кадры в сжатом формате (`Packet Length | Data Length | zlib`), фазы по `Login Success (0x02)` и
   `Finish Configuration (0x03)`. В play ID `0x08` = `block_update`: `Position + VarInt state`.
6. Самая населённая плоскость — `z = 64`, на ней доминирует state `2107` (красная шерсть).
   Рисуем `(x, y)`, режем на ячейки 5×5 с шагом 6, читаем надпись.

Альтернатива для шага 5: расшифровать поток клиента и собрать его `Use Item On` (`0x42`):
цель + смещение по грани (`+Z`) дают те же блоки, уже без ложных следов.

Рабочий решатель: [solve.py](solve.py) — самостоятельный (не импортирует `src/`),
принимает zip или пару `challenge.pcap latest.log`, плюс негативные проверки честности.

## Усложнения (env `HARD`, можно комбинировать)

| Опция | Что меняет |
|---|---|
| `--axis z` | стена в плоскости `x = const`, текст идёт вдоль `-z`: читается только при правильной проекции и ориентации |
| `--lossy` | в потоке сервера ретрансмиссии и out-of-order: склейка payload'ов «по порядку в файле» ломает шифропоток |

## Защита от непредусмотренных решений

- `grep -i 'ctf{'` и `strings` по pcap и логу ничего не находят (проверяется при старте).
- Wireshark/tshark не разбирают протокол Minecraft, а play-трафик зашифрован. Без ключа не
  видно даже границ пакетов.
- RSA-1024 с честно сгенерированным ключом: восстановить секрет из `Encryption Response` нельзя.
  Единственный источник ключа — лог клиента, это форензика артефактов, а не криптоатака.
- Перебор секретов из лога работает, но и его надо уметь проверить: подходит ровно один из
  четырёх (тест). Ключ сервера у 2-й и 3-й сессий одинаковый, по отпечатку их не различить.
- После расшифровки остаются ложные следы: надпись `NOPE` лаймовой шерстью от другого игрока
  на соседней плоскости `z = 72`; копание и стройка вокруг; сотни служебных пакетов; чанки.
  Если нарисовать все `block_update` подряд, `NOPE` ляжет поверх флага.

## Структура и тесты

- `src/mc_blockpost/` — генератор и эталонный солвер (VarInt/Position/кадры, AES-128/CFB8,
  RSA-1024 PKCS#1 v1.5, writer/reader pcap с честным TCP, шрифт 5×5, CLI `gen|solve`).
- `src/tests/` — pytest: протокольные примитивы, AES/RSA по тестовым векторам, gen→solve
  для набора флагов и всех комбинаций усложнений, «ровно один секрет из лога подходит»,
  совпадение двух путей решения.

```bash
cd src && python3 -m pytest -q     # pytest (или unittest-fallback: см. pyproject)
```

Локальная сборка хэндаута без docker:

```bash
PYTHONPATH=src python3 -m mc_blockpost gen --flag 'InnoCTF{...}' --out-dir public --zip blockpost.zip
python3 solve.py blockpost.zip --expect 'InnoCTF{...}'
```
