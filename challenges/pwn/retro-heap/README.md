# Заметки из архива / Notes from the Archive (pwn/medium)

## Условие (для игроков)

**RU:** Служба заметок из 2000-х вернулась из архива. Сисадмин на всякий случай
отключил «ненадёжные новые оптимизации аллокатора», а devops потерял
исходники деплоя. Заберите бинарник и покажите, что старая школа жива.

**EN:** A note-taking service from the 2000s is back from the archive. The sysadmin
preemptively disabled the "unreliable new allocator optimizations", and devops
lost the deployment sources. Grab the binary and show them the old school lives.

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl -O -J http://127.0.0.1:13401/    # retro-heap-files.zip
nc 127.0.0.1 13402
```

Смена флага — только перезапуск, без пересборки:

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --force-recreate
```

## Проверка решения

```bash
python3 solve.py 127.0.0.1 13402   # нужен pwntools; оффсеты из attachments/libc.so.6
```

## Описание

Note-manager (Add/View/Edit/Delete) на glibc 2.39 (Ubuntu 24.04) с полным
набором защит (PIE, Full RELRO, NX, canary). Три отличия от «обычной»
кучевой задачи:

* `tcache` отключён на сервере принудительно
  (`GLIBC_TUNABLES=glibc.malloc.tcache_count=0`) — вся современная школа
  (tcache poisoning и автопилоты) не работает, решать нужно через
  fastbin/unsorted bin;
* массив заметок `notes[16]` — это heap-чанк (META), выделенный при
  старте: fake-чанк можно построить прямо внутри массива структур;
* единственный баг — UAF: `Delete` проверяет флаг `used` (double-free
  невозможен), но не обнуляет указатель — `View`/`Edit` работают с
  освобождённым чанком.

## Решение

1. **Два лика одним View**: `free(C1); free(C2)` — оба чанка 0x420 идут в
   unsorted bin (tcache нет). `View(C2)` отдаёт `fd = C1` (heap leak) и
   `bk = main_arena+0x60` (libc leak) — unsorted bin не использует
   safe-linking.
2. **Fastbin poisoning в META**: у заметки `K` (чётный индекс, чтобы
   `&notes[K]` был 16-выровнен) хранимый size = 0x50 — валидный размер
   fastbin-чанка. `Edit(A)` (UAF) пишет в fd освобождённого чанка
   safe-linked указатель на `&notes[K]`: тогда `notes[K].size` служит
   size-полем фейкового чанка, и проверки `fastbin_index(size)==idx` и
   выравнивания в `malloc` проходят.
3. **Arbitrary R/W**: вторая `malloc(0x48)` возвращает `&notes[K].used`;
   `Add` сразу читает в неё данные — прямо в промпте перезаписываем
   `notes[K+1].data = &_IO_2_1_stdout_` и получаем произвольные
   чтение/запись.
4. **House of Apple 2**: arb-read `_IO_2_1_stdout_`, в куче строим
   `_wide_data` + фейковый wide-vtable с `__doallocate = system`;
   копия FILE с `vtable = _IO_wfile_jumps`, `flags = "  sh;"`,
   `write_ptr > write_base` пишется обратно. `Exit` → `_IO_flush_all` →
   `_IO_wfile_overflow` → `_IO_WDOALLOCATE` → `system("  sh;")` →
   `cat /flag.txt`.

Подробный разбор: [WALKTHROUGH.md](WALKTHROUGH.md). Рабочий эксплойт:
[solve.py](solve.py) (оффсеты libc — `attachments/libc.so.6`, тот же
бинарник, что в handout и в контейнере).

## Структура

- `src/chal.c` — исходник сервиса; `src/run_chal.sh` — обёртка запуска
  (tcache off + timeout 180); `src/handout_run.sh` — run.sh внутри handout;
  `src/server.py` — stdlib-раздача retro-heap-files.zip; `src/entrypoint.sh`.
- `attachments/` — `chal`, `libc.so.6`, `ld-linux-x86-64.so.2` (копии того,
  что собирается в образ, для локального прогона эксплойта).
