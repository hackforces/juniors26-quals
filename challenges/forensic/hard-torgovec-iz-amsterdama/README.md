# Торговец из Амстердама (forensic/hard)

- Порт: `13414` (переопределяется через `PORT`; внутри контейнера `8080`)
- Флаг: только из env `CTF_FLAG`

## Запуск

```bash
CTF_FLAG='InnoCTF{...}' docker compose up -d --build
curl http://127.0.0.1:13414/download/amsterdam.tar.gz -o amsterdam.tar.gz
```

## Условие (для игроков)

**RU:** У торговца изъяли выгрузки расследования одной ночи: следы памяти, журнал запуска и сетевую запись.
Восстановите фразу, которую он успел передать сообщнику.

**EN:** The merchant's exports from one night of the investigation were seized: memory traces, a launch journal and a network record.
Recover the phrase he managed to pass to his accomplice.

## Решение

Артефакт `download/amsterdam.tar.gz`: выгрузки Volatility 3, журнал Sysmon
(`logs/sysmon.jsonl`) и запись трафика (`network/amsterdam.pcap` + `nonce.txt`).

1. **Корреляция процессов.** Целевой процесс — `ledger-sync.exe` (PID 4172,
   виден в `pslist`/`psscan`, соединение в `netscan` ведёт на 203.0.113.9:4433).
   `malfind` больше не содержит ключ сессии: там только идентификатор сессии,
   конструкция потока и `ProcessGuid` (`{4A7E-4172}`).
2. **Ключ в Sysmon.** Берём GUID в `logs/sysmon.jsonl` и читаем `--session-key`
   из CommandLine соответствующей записи EventID 1. Три процесса-приманки
   (`telemetry-agent.exe`, `backup-sync.exe`, `indexer.exe`) имеют свои GUID без
   ключевого материала — корреляция по GUID обязательна.
3. **PCAP.** Фреймы вида `IR/<session>/<seq>/<slot>/<shard-hex>`: три слота данных
   (`0,1,2`) по 3 байта и `P` — XOR-чётность. В каждой группе одного шарда не
   хватает (отсутствует слот `seq % 3`); восстанавливаем его как
   `shard = P XOR present0 XOR present1`.
4. **Сборка.** Конкатенируем слоты `0,1,2` каждой группы по возрастанию `seq`,
   убираем нулевой паддинг и расшифровываем документированным потоком
   `SHA-256(key || nonce || counter_be_32)` (XOR) с nonce из `network/nonce.txt`.

PCAP, идентификатор сессии, ключ и шифртекст генерируются из CTF_FLAG при старте контейнера;
запускать Volatility на реальной памяти не нужно — все поля синтетические.

## Проверка решения

```bash
python3 solve.py                     # скачает архив с http://127.0.0.1:13414
python3 solve.py amsterdam.tar.gz    # или локальный файл
```
