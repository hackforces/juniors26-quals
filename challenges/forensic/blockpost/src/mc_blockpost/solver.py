"""pcap + latest.log -> поиск ключа -> расшифровка -> разбор кадров -> стена -> флаг."""

import json
import re
from collections import Counter

from .crypto import CFB8
from .font import GLYPH_H, GLYPH_TO_CHAR, GLYPH_W, STEP
from .pcap import read_tcp_segments, reassemble, tcp_streams
from .protocol import ID, SERVER_PORT, decode_position, read_varint, unframe

FACE_OFFSET = {0: (0, -1, 0), 1: (0, 1, 0), 2: (0, 0, -1), 3: (0, 0, 1), 4: (-1, 0, 0), 5: (1, 0, 0)}


def _string(buf, off):
    n, off = read_varint(buf, off)
    return buf[off:off + n], off + n


# ---------------------------------------------------------------------------
# Ключи из лога клиента
# ---------------------------------------------------------------------------
LOG_HELLO = re.compile(r"verify_token=([0-9a-f]+)")
LOG_SECRET = re.compile(r"secret=([0-9a-f]{32})")


def log_secrets(log_text: str):
    """[(verify_token_hex, secret_bytes)] в порядке появления в логе."""
    out, token = [], None
    for line in log_text.splitlines():
        m = LOG_HELLO.search(line)
        if m:
            token = m.group(1)
        m = LOG_SECRET.search(line)
        if m:
            out.append((token, bytes.fromhex(m.group(1))))
    return out


# ---------------------------------------------------------------------------
# Соединения
# ---------------------------------------------------------------------------
def connections(pcap: bytes):
    """По каждому TCP-соединению: client_port, c2s, s2c (собраны по seq), intent."""
    out = []
    for cport, segs in sorted(tcp_streams(read_tcp_segments(pcap)).items()):
        c2s = reassemble(segs, sport=cport)
        s2c = reassemble(segs, sport=SERVER_PORT)
        pid, data, _ = unframe(c2s, 0)
        if pid != ID.H_SB_INTENTION:
            continue
        proto, off = read_varint(data, 0)
        addr, off = _string(data, off)
        intent, _ = read_varint(data, off + 2)
        out.append({"client_port": cport, "c2s": c2s, "s2c": s2c, "intent": intent,
                    "protocol": proto, "address": addr.decode(), "ts": segs[0]["ts"]})
    return out


def status_info(conn):
    pid, data, _ = unframe(conn["s2c"], 0)
    return json.loads(_string(data, 0)[0])


def login_handshake(conn):
    """Открытая часть логина: Encryption Request / Response и смещения начала шифртекста."""
    s2c, c2s = conn["s2c"], conn["c2s"]
    off = 0
    while True:
        pid, data, off = unframe(s2c, off)
        if pid == ID.L_CB_ENCRYPTION_REQUEST:
            server_id, o = _string(data, 0)
            pub, o = _string(data, o)
            token, o = _string(data, o)
            req = {"server_id": server_id, "public_key": pub, "verify_token": token,
                   "should_authenticate": bool(data[o]), "s2c_enc_off": off}
            break
    off = 0
    while True:
        pid, data, off = unframe(c2s, off)
        if pid == ID.L_SB_ENCRYPTION_RESPONSE:
            req["c2s_enc_off"] = off
            return req


def looks_decrypted(s2c_plain: bytes) -> bool:
    """Первый зашифрованный кадр сервера — Set Compression (0x03) с разумным порогом."""
    try:
        pid, data, _ = unframe(s2c_plain, 0)
        return pid == ID.L_CB_SET_COMPRESSION and 0 <= read_varint(data, 0)[0] < 1 << 20
    except (IndexError, ValueError):
        return False


def find_secret(conn, hs, log_text):
    """Ключ из лога: сперва по verify token, иначе перебором кандидатов с проверкой."""
    cands = log_secrets(log_text)
    ct = conn["s2c"][hs["s2c_enc_off"]:hs["s2c_enc_off"] + 64]
    by_token = [sec for tok, sec in cands if tok == hs["verify_token"].hex()]
    for sec in by_token + [sec for _, sec in cands]:
        if looks_decrypted(CFB8(sec, decrypt=True).update(ct)):
            return sec
    raise ValueError("ни один секрет из лога не подходит к сессии")


def decrypt(conn, hs, secret):
    s2c = CFB8(secret, decrypt=True).update(conn["s2c"][hs["s2c_enc_off"]:])
    c2s = CFB8(secret, decrypt=True).update(conn["c2s"][hs["c2s_enc_off"]:])
    return s2c, c2s


# ---------------------------------------------------------------------------
# Разбор расшифрованных потоков (конечный автомат login -> configuration -> play)
# ---------------------------------------------------------------------------
def iter_s2c(stream: bytes):
    """(state, pid, data) для потока сервера, начиная с первого зашифрованного кадра."""
    state, threshold, off = "login", None, 0
    while off < len(stream):
        try:
            pid, data, off = unframe(stream, off, threshold)
        except (IndexError, ValueError):
            break
        yield state, pid, data
        if state == "login" and pid == ID.L_CB_SET_COMPRESSION:
            t, _ = read_varint(data, 0)
            threshold = t if t >= 0 else None
        elif state == "login" and pid == ID.L_CB_LOGIN_SUCCESS:
            state = "configuration"
        elif state == "configuration" and pid == ID.C_CB_FINISH:
            state = "play"


def iter_c2s(stream: bytes, threshold):
    state, off = "login", 0
    while off < len(stream):
        try:
            pid, data, off = unframe(stream, off, threshold)
        except (IndexError, ValueError):
            break
        yield state, pid, data
        if state == "login" and pid == ID.L_SB_LOGIN_ACK:
            state = "configuration"
        elif state == "configuration" and pid == ID.C_SB_FINISH_ACK:
            state = "play"


def block_updates(s2c_plain: bytes):
    out = []
    for state, pid, data in iter_s2c(s2c_plain):
        if state == "play" and pid == ID.P_CB_BLOCK_UPDATE:
            x, y, z = decode_position(data[:8])
            out.append((x, y, z, read_varint(data, 8)[0]))
    return out


def placements(c2s_plain: bytes, threshold):
    """Второй путь: Use Item On клиента -> куда встал блок (цель + смещение по грани)."""
    out = []
    for state, pid, data in iter_c2s(c2s_plain, threshold):
        if state == "play" and pid == ID.P_SB_USE_ITEM_ON:
            _, o = read_varint(data, 0)
            x, y, z = decode_position(data[o:o + 8])
            face, _ = read_varint(data, o + 8)
            dx, dy, dz = FACE_OFFSET[face]
            out.append((x + dx, y + dy, z + dz))
    return out


def compression_threshold(s2c_plain: bytes):
    for state, pid, data in iter_s2c(s2c_plain):
        if pid == ID.L_CB_SET_COMPRESSION:
            return read_varint(data, 0)[0]
    return None


# ---------------------------------------------------------------------------
# Реконструкция надписи -> текст
# ---------------------------------------------------------------------------
def _decode_grid(grid, width, shift):
    """Режет сетку (строка 0 — верх) на глифы 5x5 с шагом 6, начиная с колонки -shift."""
    text = []
    # округляем вверх: у крайнего глифа (напр. '}') правый столбец может быть
    # пустым, из-за чего bounding box короче сетки — иначе теряем последний слот
    n_glyphs = (width + shift + STEP - 1) // STEP
    for gi in range(n_glyphs):
        cx = gi * STEP - shift
        rows = []
        for ry in range(GLYPH_H):
            row = ""
            for rx in range(GLYPH_W):
                gx = cx + rx
                row += grid[ry][gx] if (ry < len(grid) and 0 <= gx < width) else "."
            rows.append(row)
        text.append(GLYPH_TO_CHAR.get(tuple(rows), "?"))
    return "".join(text)


def reconstruct(blocks):
    """Возвращает (ascii_wall, text). Устойчив к ложным следам и ориентации стены."""
    if not blocks:
        return None, ""

    # 1) плоскость стены: самая населённая из плоскостей z=const и x=const
    planes = Counter()
    for (x, _, z, _) in blocks:
        planes[("z", z)] += 1
        planes[("x", x)] += 1
    (axis, value), _ = planes.most_common(1)[0]
    if axis == "z":   # стена z=const, горизонталь — x
        on_plane = [(x, y, s) for (x, y, z, s) in blocks if z == value]
    else:             # стена x=const, горизонталь — z
        on_plane = [(z, y, s) for (x, y, z, s) in blocks if x == value]

    # 2) доминирующий block-state на этой плоскости = "передний план"
    fg = Counter(s for (_, _, s) in on_plane).most_common(1)[0][0]
    pts = {(h, y) for (h, y, s) in on_plane if s == fg}

    min_h = min(p[0] for p in pts)
    max_h = max(p[0] for p in pts)
    max_y = max(p[1] for p in pts)
    min_y = min(p[1] for p in pts)
    width = max_h - min_h + 1
    height = max_y - min_y + 1

    # 3) ASCII-стену строим в обеих ориентациях (зритель может стоять с любой стороны)
    best = None
    for mirrored in (False, True):
        grid = [["." for _ in range(width)] for _ in range(height)]
        for (h, y) in pts:
            col = (max_h - h) if mirrored else (h - min_h)
            grid[max_y - y][col] = "#"
        # 4) режем на глифы; сдвиг нужен, если у первого глифа пустые левые столбцы
        for shift in range(STEP):
            text = _decode_grid(grid, width, shift)
            score = (text.count("?"), shift, mirrored)
            if best is None or score < best[0]:
                best = (score, "\n".join("".join(r) for r in grid), text)
    return best[1], best[2]


# ---------------------------------------------------------------------------
def solve_bytes(pcap: bytes, log_text: str, verbose: bool = False):
    """Полный путь решения. Возвращает dict с промежуточными результатами и текстом."""
    conns = connections(pcap)
    logins = [c for c in conns if c["intent"] == 2]
    if len(logins) != 1:
        raise ValueError(f"ожидалось одно login-соединение, найдено {len(logins)}")
    conn = logins[0]
    hs = login_handshake(conn)
    secret = find_secret(conn, hs, log_text)
    s2c, c2s = decrypt(conn, hs, secret)
    blocks = block_updates(s2c)
    wall, text = reconstruct(blocks)
    res = {"connections": conns, "handshake": hs, "secret": secret, "s2c": s2c, "c2s": c2s,
           "blocks": blocks, "wall": wall, "text": text}
    if verbose:
        for c in conns:
            kind = {1: "status", 2: "login"}.get(c["intent"], c["intent"])
            print(f"[+] TCP :{c['client_port']} -> :{SERVER_PORT}  intent={kind}  "
                  f"c2s={len(c['c2s'])} B  s2c={len(c['s2c'])} B")
            if c["intent"] == 1:
                print(f"    status: {status_info(c)['version']}")
        print(f"[+] verify token {hs['verify_token'].hex()} -> secret {secret.hex()}")
        print(f"[+] block_update в play: {len(blocks)}")
        print("\n--- Стена (реконструкция) ---")
        print(wall)
        print(f"\n[+] Надпись: {text}")
        print(f"[+] ФЛАГ: {text.lower()}")
    return res


def solve(pcap_path: str, log_path: str):
    with open(pcap_path, "rb") as f:
        pcap = f.read()
    with open(log_path, encoding="utf-8") as f:
        log = f.read()
    return solve_bytes(pcap, log, verbose=True)["text"]
