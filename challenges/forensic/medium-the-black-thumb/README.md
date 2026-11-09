# Чёрный палец (forensic/medium)

- Порт: `13445` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl http://127.0.0.1:13445/ -o black-thumb.img.gz
```

## Условие (для игроков)

**RU:** В южном лондонском хранилище инспекторы нашли чёрную флешку, которую
курьер К. Кран сдал добровольно. Forensic-стол показывает на 256-мегабайтном
носителе одну 128-мегабайтную партицию — и стол врёт. В доме курьера на первой
партиции лежат заметки, но часть из них устарела. Найдите, что ещё на носителе,
откройте то, что Кран прятал, и прочтите оставленный им документ.

**EN:** Inspectors found a black USB stick the courier K. Crane surrendered
voluntarily at the south London depot. The forensics desk reports a single
128 MB partition on the 256 MB stick — and the desk is wrong. The courier's
home on the first partition has notes, but some of them are outdated. Find
what else is on the stick, open what Crane was hiding, and read the document
he left behind.

## Решение

Артефакт `black-thumb.img.gz` — raw-образ USB-носителя 256 MiB
(MBR + одна партиция ext4 + …).

1. **MBR** (`dd if=img bs=512 count=1` / `mmls` / `testdisk`): одна партиция
   0x83, `1 MiB .. 129 MiB` (262144 сектора). Образ 256 MiB — значит, 127 MiB
   хвоста MBR «не видит».
2. **Хвост** (`129 .. 256 MiB`): скан по сигнатурам ext2 (`0x53ef` в
   суперблоке) — `testdisk`, `foremost`, или руками по 1 MiB-границам.
3. **Первая сигнатура (129 MiB) — приманка**: суперблок «правдоподобен»
   (label `recovery`), но `mount`/`7-Zip` падают — том бит (state=0,
   blocks=0). Это тупик, не решение.
4. **Настоящий том — 145 MiB**: label `black-thumb-2050`, state=1,
   111 MiB (113664 × 1 KiB). Срез: `dd if=img bs=1M skip=145 count=111 of=vol`
   → `mount -o loop,ro` (Linux/WSL) или открыть образ в 7-Zip (Windows —
   ext2 читает).
5. **`note.txt`** в корне тома — записка курьера с кодом
   `black-thumb-2050` (тот же код дублируется в `notes/sticky.txt` на первой
   партиции; `old-drive.txt` — устаревший код-приманка).
6. **`sealed.bin`** (4 KiB) — ZIP (ZipCrypto), пароль = код из note.txt.
   7-Zip: password-диалог; Linux: `unzip -P black-thumb-2050 sealed.bin`.
   Внутри `letter.txt` (письмо) и `flag.txt` — флаг.

Примечание о декоре: папки `photos/`, `music/`, `video/` есть на обоих
томах (в доме курьера — первые 5 файлов каждой категории, во втором
отсеке — остальные 5; ~104 МБ). Это чистые декор-файлы с пиннед-списка
публичных источников (Wikimedia Commons — классические картины,
SoundHelix — канонические sample-mp3, test-videos.co.uk — клипы
Big Buck Bunny / Sintel / Jellyfish); стеганографии в них нет, на
цепочку решения они не влияют. Медиа скачивается на docker build
(`src/download_media.py`, сборке нужна сеть): одиночный сбой URL —
skip с warning, меньше 7 живых файлов в категории — падение сборки.
Из-за медиа образ гзипится runtime-ом на уровне 1 (иначе старт не
успевает до healthcheck), а итоговое скачивание для игрока — ~110 МБ.

Примечание: внутри настоящего тома лежат backup-копии суперблока (153/169/185/
201/217 MiB) — они тоже выглядят как кандидаты, но это копии ОДНОГО тома
(те же UUID/размер, state=0): настоящий — тот, что монтируется первым
в порядке восходящего скана и согласен с длиной образа.

## Проверка решения

```bash
python3 solve.py            # скачает образ с http://127.0.0.1:13445
python3 solve.py black-thumb.img.gz  # или локальный файл
```
