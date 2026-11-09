# Дело о рейгейтских сквайрах (privilege_escalation/medium)

- Порт: `13424` (переопределяется через `PORT`; внутри контейнера `22`/ssh)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
ssh player@127.0.0.1 -p 13424   # пароль: player
```

## Условие (для игроков)

**RU:** У сквайров Рейгейта пропала ночная сводка. На их рабочей станции остался один служебный просмотрщик.

**EN:** The Reigate squires' night report has disappeared. One service viewer remains on their workstation.

## Решение

После входа перечисляем необычные метаданные исполняемых файлов:
`getcap -r /` (или `getcap /usr/local/bin/case-reader`) показывает, что у
`/usr/local/bin/case-reader` установлена файловая capability
`cap_dac_override+ep` — право обходить обычные проверки чтения файлов.

Просмотрщик принимает путь к отчёту аргументом (`usage: case-reader <report>`),
поэтому читаем им защищённый файл:

```bash
/usr/local/bin/case-reader /root/flag
```

Флага нет в образе — entrypoint создаёт `/root/flag` из env `CTF_FLAG` после
старта (root:root, 0600, с настоящим переводом строки в конце).

## Проверка решения

```bash
python3 solve.py            # цель по умолчанию 127.0.0.1:13424 (нужен sshpass)
python3 solve.py 127.0.0.1:13424
```
