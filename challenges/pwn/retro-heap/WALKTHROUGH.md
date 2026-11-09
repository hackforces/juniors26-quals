# retro-heap — полное решение

## 0. Разведка

Участнику отдаются `chal` (PIE, Full RELRO, NX, canary), `libc.so.6`,
`ld-linux-x86-64.so.2` и `run.sh`. В `run.sh` видно главное отличие от
«обычной» кучевой задачи:

```sh
GLIBC_TUNABLES=glibc.malloc.tcache_count=0
```

tcache отключён — вся современная школа (tcache poisoning, автопилоты)
не работает. Остаётся старый мир: fastbin'ы с safe-linking и unsorted bin.

Программа — note-manager. При старте `main` выделяет одну кучу под весь
массив структур:

```c
struct note { char *data; size_t size; int used; int pad; };  // 24 байта
notes = malloc(16 * 24);   // чанк 0x190 — дальше «META»
```

Меню:

| Команда | Проверки | Баг |
|---|---|---|
| Add    | индекс, `used`, размер 0x18–0x500 | — |
| View   | индекс | **нет проверки `used` → UAF read** |
| Edit   | индекс | **нет проверки `used` → UAF write** |
| Delete | индекс, `used` (double-free невозможен) | **указатель не обнуляется** |

Единственный баг — полноценный UAF: после `Delete` слот можно читать
(`View`) и перезаписывать (`Edit`) целиком, на `size` байт.

## 1. Два лика одним View

tcache нет, поэтому освобождение чанков 0x420 уходит в unsorted bin.
Освобождаем два больших чанка подряд: `free(C1); free(C2)`. Вставка в
unsorted идёт в голову списка, и поля чанка C2 становятся:

```
C2.fd = C1   (сырой указатель на чанк — unsorted bin не использует safe-linking)
C2.bk = main_arena + 0x60   (голова unsorted bin в libc)
```

`View(C2)` отдаёт оба лика сразу. Один нюанс: за C2 должен стоять
занятый чанк-«гарда» (G), иначе C2 сольётся с top chunk'ом и не попадёт
в unsorted bin.

Layout кучи детерминирован (tcache-структура 0x290 всё равно выделяется
в начале кучи даже при `tcache_count=0`, затем META 0x190 и наши чанки):

```
heap+0x000  tcache_perthread_struct   0x290
heap+0x290  META (chunk 0x190)  -> data = heap+0x2a0
heap+0x420  A   0x50   (idx 0, request 0x48)
heap+0x470  C1  0x420  (idx 1)
heap+0x890  K   0x60   (idx 2, request 0x50)
heap+0x8f0  C2  0x420  (idx 3)
heap+0xd10  G   0x20   (idx 4, гарда)
heap+0xd30  S   0x410  (idx 5, свалка для фейков)
```

Отсюда: `heap = fd - 0x470`, `libc = bk - 0x60 - main_arena_off`
(`main_arena = 0x204ac0` для этой сборки glibc 2.39).

## 2. Fastbin poisoning внутрь META

Чанк A (0x50) освобождаем — fastbin[0x50]. `Edit(A)` (UAF!) заменяет его
fd на адрес **внутри массива структур** `notes[]`. Куда именно?

У fastbin-маллока две проверки жертвы:

* `fastbin_index(chunksize(victim)) == idx` — по полю size по адресу
  `victim+8`;
* `misaligned_chunk(victim)` — 16-байтовое выравнивание.

Структура заметки — 24 байта, поэтому `&notes[i]` 16-выровнен только при
чётных `i`. Берём `K = notes[2]`: тогда фейковый чанк `X = &notes[2]`, а
`X+8 = &notes[2].size` — и это поле мы контролируем созданием заметки!
`Add(2, 0x50)` записал туда `0x50` — валидный размер fastbin-чанка,
совпадающий с отравляемой корзиной.

Safe-linking: fd хранится как `(pos >> 12) ^ target`, где `pos` — адрес
самого поля fd (data чанка A). Оба адреса известны из лика кучи:

```python
enc = ((heap + 0x430) >> 12) ^ (heap + 0x2a0 + 0x30)   # A.data >> 12 ^ &notes[2]
Edit(0, p64(enc))
```

## 3. Из overlapping-чанка — произвольные чтение/запись

`malloc(0x48)` дважды:

1. первый вызов возвращает настоящий A (голова fastbin становится
   `&notes[2]`);
2. второй вызов снимает фейковый чанк: проверки проходят
   (`size = notes[2].size = 0x50`, выравнивание ок), malloc возвращает
   `X + 0x10 = &notes[2].used`.

`Add(7, 0x48, ...)` сразу читает в возвращённый указатель 0x48 байт
данных — то есть прямо поверх структур `notes[2..5]`:

```
+0x00  notes[2].used/pad     мусор
+0x08  notes[3].data         <- &_IO_2_1_stdout_
+0x10  notes[3].size         <- 0xe0
+0x18  notes[3].used/pad     <- 1
+0x20  notes[4].*            <- восстанавливаем настоящие значения (гард!)
+0x38  notes[5].data         <- восстанавливаем (свалка S понадобится)
+0x40  notes[5].size         <- 0x400
```

Теперь `View(3)` / `Edit(3)` — произвольные чтение и запись по любому
адресу.

## 4. House of Apple 2 (FSOP без хуков)

Хуков (`__free_hook`/`__malloc_hook`) в glibc 2.39 нет, но осталась
широкая vtable-механика stdio. Классическая House of Apple 2:

1. **Свалка S** (чанк idx 5) превращается в `_wide_data` + фейковый
   wide-vtable:
   * `S+0xe0 = S+0x100` — поле `_wide_data->_wide_vtable`;
   * `S+0x100+0x68 = system` — слот `__doallocate` wide-vtable.
2. **`_IO_2_1_stdout_`** сначала читаем (`View(3)`) — нужна копия с
   живыми `_chain` и `_lock`. В копии патчим:

| Поле | Значение | Зачем |
|---|---|---|
| `_flags` (0x00) | `"  sh;\0"` | без `_IO_NO_WRITES`/`_IO_CURRENTLY_PUTTING`; аргумент для `system` |
| `_IO_write_base` (0x20) | 0 | условие flush |
| `_IO_write_ptr` (0x28) | 1 | `write_ptr > write_base` → файл попадёт во flush |
| `_wide_data` (0xa0) | `S` | наш wide_data |
| `vtable` (0xd8) | `_IO_wfile_jumps` | легальная vtable — `_IO_vtable_check` проходит |

3. **Триггер** — пункт меню `Exit`: `exit()` → `_IO_cleanup` →
   `_IO_flush_all` проходит по `_IO_list_all`, видит у stdout
   `write_ptr > write_base` и зовёт `_IO_OVERFLOW` → слот `__overflow`
   vtable `_IO_wfile_jumps` = `_IO_wfile_overflow`:

```
_IO_wfile_overflow(f):
    f->_flags без _IO_NO_WRITES, без _IO_CURRENTLY_PUTTING  -> ок
    f->_wide_data->_IO_write_base == NULL                   -> ок
    _IO_wdoallocbuf(f):
        f->_wide_data->_IO_buf_base == NULL                 -> ок
        _IO_WDOALLOCATE(f) = f->_wide_data->_wide_vtable->__doallocate(f)
                            = system("  sh;")
```

`system("  sh;")` запускает `/bin/sh -c "  sh;"` — шелл на сокете,
`cat /flag.txt`.

Почему программа не ломается раньше от подменённого stdout: весь вывод
chal делает сырыми `write()`, stdio не используется до самого `exit()`.

## Альтернативные концовки (тоже засчитываются)

С произвольной записью вместо FSOP можно:

* прочитать `__environ` (libc) → адрес стека → найти сохранённый RIP
  кадра main/служебных функций → перезаписать ROP-цепочкой
  `system("/bin/sh")`;
* переписать `__exit_funcs`/`_IO_list_all` (последнее — та же идея
  Apple 2, но со своим FILE в куче).

## Цепочка одним взглядом

```
UAF write -> fastbin fd poisoning (safe-linking)
          -> фейк-чанк внутри notes[] (size-поле = notes[2].size = 0x50)
          -> malloc возвращает &notes[2].used
          -> перезапись notes[3].data -> arbitrary R/W
          -> House of Apple 2 на _IO_2_1_stdout_
          -> Exit -> _IO_flush_all -> system("  sh;")
```

Ключевая идея, ради которой всё затевалось: с выключенным tcache
«просто отравить tcache next» нельзя — приходится искать место, где
байты по фиксированному адресу притворяются size-полем чанка, и массив
структур заметок сам даёт такой байт (`notes[K].size`).
