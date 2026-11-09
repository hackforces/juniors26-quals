# Дело о голубом карбункуле / The Blue Carbuncle (pwn/easy)

- Порты: `13425` (nc, интерактив; `PORT`) и `13439` (http, хэндаут; `PORT_HTTP`)
- Флаг: только из env `CTF_FLAG` (кладётся в `/run/case/flag`, читается
  привилегированной функцией `final_note`)
- Хэндаут: `http://<host>:13439/easy-the-blue-carbuncle-files.zip` — тот же ELF, что в сервисе
  (без него оффсет и адрес — гадание)

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
nc 127.0.0.1 13425
```

## Условие (для игроков)

**RU:** В пневмопочте отеля найден карбункул и очень старый терминал приёма находок.
Узнайте, кому он адресовал последнее сообщение.

**EN:** A carbuncle and an old lost-property terminal were found in the hotel's
pneumatic mail. Learn whom it addressed in its last message.

## Решение

1. В `desk()` ввод читается `gets()` в `char note[48]` — безграничная
   перезапись стека.
2. Бинар собран `-O0 -fno-stack-protector -no-pie -Wl,-z,norelro`: адреса
   фиксированы, canary нет.
3. В хэндауте (`easy-the-blue-carbuncle-files.zip` → `carbuncle`) находим адрес `final_note`
   (`nm` → `0x401186`) — она читает `/run/case/flag` и печатает его.
4. Пейлоад: 48 байт буфера + 8 байт сохранённого rbp + адрес `final_note`
   в little-endian поверх адреса возврата.
5. Соединение обслуживается per-connection (`socat ... fork`), сервис
   работает под непривилегированным `ctf`; флаг доступен только через сам
   бинар.

## Непредусмотренные решения и потенциальные проблемы

1. Альтернативные техники той же уязвимости: `gets()` безграничен, canary
   нет — помимо ret2win возможен полный ROP (утечка `puts@got` через PLT →
   ret2libc). Все пути остаются внутри класса «переполнение стека»;
   NX включён (GNU_STACK RW), шеллкод на стеке не сработает — только ROP.
   Отдельного закрытия не требует.
2. Выравнивание стека на входе в `final_note` корректное — SSE-код `fopen`
   (movaps) не падает; проверено на живом инстансе.
3. Утечки флага без pwn нет: `/run/case/flag` — `0400 ctf:ctf`, процесс от
   `ctf`; флаг читается только внутри `final_note` и до того в памяти не
   лежит; busybox httpd раздаёт только zip с ELF.

## Проверка решения

```bash
python3 solve.py            # 127.0.0.1:13425
python3 solve.py host port  # другой инстанс
```
