# Дело о долине ужаса / The Valley of Fear (pwn/hard)

- Порты: `13426` (nc, интерактив; `PORT`) и `13440` (http, хэндаут; `PORT_HTTP`)
- Флаг: только из env `CTF_FLAG` (кладётся в `/run/case/flag`, читается
  только функцией `genuine_ending`)
- Хэндаут: `http://<host>:13440/hard-the-valley-of-fear-files.zip` — тот же PIE-ELF, что в сервисе

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
nc 127.0.0.1 13426
```

## Условие (для игроков)

**RU:** Связной из Долины ужаса оставил голосовое сообщение в терминале закрытого
братства. Восстановите подлинный финал записи.

**EN:** A Valley of Fear contact left a voice message in a closed brotherhood
terminal. Restore the recording's genuine ending.

## Решение

Бинар собран `-O0 -fno-omit-frame-pointer -fPIE -pie
-fstack-protector-all -Wl,-z,relro,-z,now`: PIE + full RELRO + canary,
поэтому нужен трёхзвенный киллчейн.

1. **Leak базы PIE**: сервис сам печатает `recording marker: %p` — адрес
   функции `recording`. База загрузки = адрес − 0x1257 (оффсет из
   `hard-the-valley-of-fear-files.zip` → `valley`, совпадает с сервисным ELF).
2. **Leak canary через format string**: первый ввод (`observation`, 128
   байт через `fgets`) передаётся целиком в `printf(observation)`.
   Canary лежит на стеке в vararg-слоте `%33$p` — читаем его одним
   запросом и запоминаем для второго этапа (то же соединение, тот же
   процесс — canary не меняется).
3. **Переполнение transcript**: второй ввод — `read(240)` в
   `char transcript[72]`. Пейлоад: 216 байт паддинга (72 transcript +
   observation-хвост/выравнивание) → canary (сохранённый) → 8 байт
   сохранённый rbp → адрес `genuine_ending` = база + 0x11b9 поверх
   адреса возврата.
4. `genuine_ending` открывает `/run/case/flag` и печатает флаг.

Соединение per-connection (`socat ... fork`), сервис под непривилегированным
`ctf`; флаг недоступен напрямую, только через вызов winning-функции.

## Непредусмотренные решения и потенциальные проблемы

1. Форматная строка в `observation` даёт произвольное чтение (`%p`-цепочки)
   и, при утечке указателя на стек, запись через `%n`: теоретически можно
   обойтись без переполнения `transcript` (перезаписать адрес возврата
   `%hn`-цепочкой) или слить libc из GOT (full RELRO чтению не мешает) и
   уйти в ret2libc. Все пути остаются внутри класса «форматная строка +
   переполнение», PIE-маркер и канарейка по-прежнему обязательны —
   отдельного закрытия не требует.
2. Смещение канарейки `CANARY_OFFSET = 216` (transcript 72 + observation
   128 + выравнивание) продиктовано раскладкой локалов конкретного GCC;
   при пересборке другим компилятором сверять оффсет по хэндауту в gdb.
3. `read(240)` возвращает сколько пришло за раз: пейлоад 240 байт должен
   уходить одним сегментом (240 < MSS — на практике стабильно).
4. Утечки флага без pwn и DoS на других игроков нет: `/run/case/flag` —
   `0400 ctf:ctf`, флаг читается только внутри `genuine_ending`, соединение
   per-connection.

## Проверка решения

```bash
python3 solve.py            # 127.0.0.1:13426
python3 solve.py host port  # другой инстанс
```
