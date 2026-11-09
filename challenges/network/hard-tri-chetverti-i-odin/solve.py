#!/usr/bin/env python3
"""Решение «Три четверти и один» (network/hard).

Скачиваем quarters.pcap с живого инстанса и восстанавливаем фрагментированную
передачу HQ: управляющие датаграммы CASE/SPEC задают формат (3 блока данных +
XOR-чётность, base64, маска sha256(case:seq:slot)[0]); в каждой группе
отсутствует блок seq mod 3 — недостающий восстанавливаем через XOR с P.

Идея решения по шагам:
1. В pcap — фон полигона (ARP, DNS, NTP, ICMP, mDNS-анонсы, broadcast-лог,
   статус коллектора, TLS-аплинки), внутри перемешаны датаграммы HQ.
   Датаграммы перетасованы сидом от case-id — порядок восстанавливаем по
   номерам seq, а не по позиции в файле.
2. HQ/CASE/<id> даёт идентификатор дела; HQ/SPEC/v1 полностью описывает
   протокол: группа = три 4-байтовых блока данных (слоты 0,1,2) плюс
   XOR-блок чётности P.
3. Каждый блок передаётся base64 и закрыт однобайтовой маской
   sha256(case:seq:slot)[0] — снимаем её XOR-ом после декодирования.
4. В каждой группе дошло ровно два блока данных + P: слот seq mod 3 потерян
   намеренно, избыточность — обязательная часть протокола.
5. Недостающий блок = P XOR known0 XOR known1: чётность построена как XOR
   всех блоков, поэтому любой из них выражается через остальные три.
6. Склеиваем слоты 0,1,2 по возрастанию seq, срезаем нулевое дополнение —
   получается флаг.

Запуск:  python3 solve.py [base_url]    (по умолчанию http://127.0.0.1:13417)
"""

import base64
import hashlib
import re
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13417"


def mask(case_id: str, sequence: int, slot: str) -> int:
    # Однобайтовая маска из SPEC: первый байт SHA-256("<case>:<seq>:<slot>").
    # Аргументы входят в хэш по отдельности — salted, поэтому без case_id из
    # управляющей датаграммы маску не воспроизвести.
    return hashlib.sha256(f"{case_id}:{sequence}:{slot}".encode()).digest()[0]


def main() -> int:
    data = urllib.request.urlopen(f"{BASE}/download/quarters.pcap", timeout=15).read()
    # Управляющая датаграмма CASE — идентификатор дела; он же сид перетасовки
    # и параметр маски, поэтому извлекаем первым.
    case_id = re.search(rb"HQ/CASE/([0-9a-f]{12})", data).group(1).decode()
    groups: dict[int, dict[str, bytes]] = {}
    # Группа данных: HQ/<seq:3 цифры>/<слот 0|1|2|P>/<base64-блок>. Порядок
    # вхождений в файле перемешан — раскладываем по seq, а не по порядку.
    for match in re.finditer(rb"HQ/(\d{3})/([012P])/([A-Za-z0-9+/=]+)", data):
        sequence = int(match.group(1))
        slot = match.group(2).decode()
        # base64-декодирование и снятие маски идут парой: до декодирования
        # маска наложена на сырые байты блока.
        encrypted = base64.b64decode(match.group(3))
        groups.setdefault(sequence, {})[slot] = bytes(
            value ^ mask(case_id, sequence, slot) for value in encrypted
        )

    result = bytearray()
    for sequence, shards in sorted(groups.items()):
        # Потерянный слот задан протоколом (SPEC: missing=seq-mod-3) — его
        # не ищем перебором, а вычисляем; дошедшие два блока берём по списку.
        missing = str(sequence % 3)
        known = [shards[str(slot)] for slot in range(3) if str(slot) != missing]
        # XOR-чётность: P = b0 ^ b1 ^ b2, отсюда любой блок = P ^ остальные.
        shards[missing] = bytes(a ^ b ^ c for a, b, c in zip(shards["P"], known[0], known[1]))
        # Слоты склеиваем в естественном порядке 0,1,2 — группы уже по seq.
        result.extend(b"".join(shards[str(slot)] for slot in range(3)))
    # Нулевое дополнение последнего блока (выравнивание до 4 байт) срезаем.
    flag = result.rstrip(b"\0").decode()
    if not re.fullmatch(r"(?i)[a-z0-9_]{2,32}\{[^{}\s]{4,}\}", flag):
        print(f"[-] восстановлено нечто некорректное: {flag!r}", file=sys.stderr)
        return 1
    print(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
