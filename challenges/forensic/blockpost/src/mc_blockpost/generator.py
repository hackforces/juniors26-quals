"""Сборка хэндаута: challenge.pcap (реалистичная online-mode сессия) + latest.log клиента.

Сессия: status ping отдельным соединением, затем handshake -> login с шифрованием
(RSA-1024 + AES/CFB8) и компрессией (порог 256) -> configuration -> play. В play игрок
Kolya идёт вдоль каменной стены у спавна и «принтером» выкладывает на ней флаг шерстью
(Use Item On по стене -> сервер рассылает Block Update). Параллельно другой игрок строит
ложную надпись NOPE на соседней плоскости, кто-то копает и строит в округе.

Всё детерминировано: RSA-ключи, секреты, шум и таймстемпы выводятся из фиксированных seed'ов.
"""

import datetime as dt
import hashlib
import io
import math
import random
import uuid as uuidlib
import zipfile

from . import clientlog, world
from .crypto import CFB8, generate_rsa, minecraft_server_hash, rsa_pkcs1v15_encrypt, rsa_public_der
from .font import FONT, GLYPH_H, GLYPH_W, STEP
from .mctypes import (
    boolean, byte, byte_array, f32, f64, identifier, long, prefixed, string, ubyte, uuid,
)
from .pcap import PcapWriter
from .protocol import (
    COMPRESSION_THRESHOLD, ID, PROTOCOL_VERSION, SERVER_PORT, encode_position, frame,
    write_varint,
)

DEFAULT_FLAG = "InnoCTF{a}"   # dummy для локальных прогонов/тестов; боевой флаг — только env CTF_FLAG
USERNAME = "Kolya"

# Плоскость стены и точка отсчёта для раскладки текста
X0, Y0, Z0 = 120, 70, 64        # левый-нижний угол надписи (y=70 — сразу над травой)
DECOY_OFFSET = 8                 # ложная надпись — на соседней плоскости, через 8 блоков
DECOY_TEXT = "NOPE"
WALL_HEIGHT = 6                  # каменная стена-подложка у спавна: y = 70..75

FG_STATE = world.RED_WOOL        # блок надписи
DECOY_STATE = world.LIME_WOOL    # ложная надпись
NOISE_STATES = (world.AIR, world.AIR, world.COBBLESTONE, world.OAK_PLANKS, world.DIRT)

SEED = 1337
START_UTC = dt.datetime(2026, 10, 3, 19, 47, 5, 118000, tzinfo=dt.timezone.utc).timestamp()
VIEW_DISTANCE = 3
TICK = 0.05
REACH = 4                        # принтер ставит блоки в пределах 4 блоков вдоль стены
PLACE_PER_TICK = 2
WALK_PER_TICK = 0.2
NOISE_EVENTS = 70
KEEP_ALIVE_TICKS = 300
LOSSY_RETRANS = 6
LOSSY_SWAPS = 6


# ---------------------------------------------------------------------------
# Геометрия
# ---------------------------------------------------------------------------
class Wall:
    """Стена с надписью. axis="x": плоскость z=Z0, текст вдоль +x (зритель с юга, смотрит
    на север). axis="z": плоскость x=X0, текст вдоль -z (зритель с востока, смотрит на запад)."""

    def __init__(self, axis):
        if axis not in ("x", "z"):
            raise ValueError(f"axis должен быть 'x' или 'z', а не {axis!r}")
        self.axis = axis

    def at(self, h, y, depth=0):
        """Мировые координаты точки стены: h — вдоль текста, depth — по нормали к зрителю."""
        if self.axis == "x":
            return (X0 + h, y, Z0 + depth)
        return (X0 + depth, y, Z0 - h)

    @property
    def face(self):              # грань подложки, смотрящая на зрителя: +Z (3) или +X (5)
        return 3 if self.axis == "x" else 5

    @property
    def yaw(self):               # куда смотрит игрок: на север (180) или на запад (90)
        return 180.0 if self.axis == "x" else 90.0


def layout_text(text, wall, depth=0):
    """Список ((x, y, z), h) блоков надписи; h — координата вдоль текста."""
    out = []
    for i, ch in enumerate(text):
        glyph = FONT.get(ch)
        if glyph is None:
            raise ValueError(f"В шрифте нет символа {ch!r}")
        for row in range(GLYPH_H):          # row 0 — верх
            for col in range(GLYPH_W):
                if glyph[row][col] == "#":
                    h = i * STEP + col
                    out.append((wall.at(h, Y0 + GLYPH_H - 1 - row, depth), h))
    return out


# ---------------------------------------------------------------------------
# Протокольный «канал» одного направления: фрейм -> [компрессия] -> [AES/CFB8]
# ---------------------------------------------------------------------------
class Pipe:
    def __init__(self):
        self.threshold = None
        self.cipher = None
        self.buf = bytearray()

    def put(self, pid, data=b""):
        raw = frame(pid, data, self.threshold)
        self.buf += self.cipher.update(raw) if self.cipher else raw

    def take(self):
        b = bytes(self.buf)
        self.buf.clear()
        return b


class Session:
    def __init__(self, w: PcapWriter, cport):
        self.w = w
        self.tcp = w.stream(cport)
        self.c2s, self.s2c = Pipe(), Pipe()

    def flush(self, d, **kw):
        pipe = self.c2s if d == "c2s" else self.s2c
        data = pipe.take()
        if data:
            self.tcp.send(d, data, **kw)


def _uuid4(rng):
    return uuidlib.UUID(bytes=bytes(rng.randrange(256) for _ in range(16)), version=4)


# ---------------------------------------------------------------------------
# Сборка
# ---------------------------------------------------------------------------
def build(flag: str = DEFAULT_FLAG, axis: str = "x", lossy: bool = False):
    """Возвращает dict(pcap=bytes, log=str, stats=dict, secret=bytes, verify_token=bytes)."""
    text = flag.upper()
    wall = Wall(axis)
    flag_blocks = layout_text(text, wall)
    decoy_blocks = layout_text(DECOY_TEXT, wall, depth=DECOY_OFFSET)
    if len(flag_blocks) <= len(decoy_blocks):
        raise ValueError(f"флаг слишком короткий: {len(flag_blocks)} блоков против "
                         f"{len(decoy_blocks)} у ложной надписи {DECOY_TEXT!r}")

    rng = random.Random(SEED)
    w = PcapWriter(START_UTC, seed=SEED + 1)

    player_uuid = _uuid4(rng)
    others = [("Vasya_Builder", _uuid4(rng)), ("petya2011", _uuid4(rng))]
    n, e, d = generate_rsa(1024, seed=SEED + 2)
    pub = rsa_public_der(n, e)
    secret = bytes(rng.randrange(256) for _ in range(16))
    verify_token = bytes(rng.randrange(256) for _ in range(4))

    # стена-подложка (уже стояла у спавна): на ней будет надпись
    width = len(text) * STEP + 2 * REACH
    wall_blocks = {wall.at(h, y, -1) for h in range(-REACH - 4, width)
                   for y in range(Y0, Y0 + WALL_HEIGHT)}

    # ---------------- 1. status ping (список серверов) ----------------
    st = Session(w, 51034)
    st.tcp.open()
    w.tick(0.0004)
    st.c2s.put(ID.H_SB_INTENTION, write_varint(PROTOCOL_VERSION) + string("10.0.0.10")
               + SERVER_PORT.to_bytes(2, "big") + write_varint(1))
    st.c2s.put(ID.S_SB_STATUS_REQUEST)
    st.flush("c2s")
    w.tick(0.0011, 0.0019)
    st.s2c.put(ID.S_CB_STATUS_RESPONSE, world.status_json(others))
    st.flush("s2c")
    w.tick(0.0005, 0.0009)
    ping_ms = int(w.now * 1000)
    st.c2s.put(ID.S_SB_PING, long(ping_ms))
    st.flush("c2s")
    w.tick(0.0004, 0.0008)
    st.s2c.put(ID.S_CB_PONG, long(ping_ms))
    st.flush("s2c")
    w.tick(0.0002)
    st.tcp.close(by="s2c")

    # ---------------- 2. login ----------------
    w.tick(7.9, 8.4)                      # игрок нажал «Подключиться»
    s = Session(w, 51036)
    s.tcp.open()
    session_start = w.now
    w.tick(0.0004)
    s.c2s.put(ID.H_SB_INTENTION, write_varint(PROTOCOL_VERSION) + string("10.0.0.10")
              + SERVER_PORT.to_bytes(2, "big") + write_varint(2))
    s.c2s.put(ID.L_SB_LOGIN_START, string(USERNAME) + uuid(player_uuid))
    s.flush("c2s")
    w.tick(0.0012, 0.0021)
    s.s2c.put(ID.L_CB_ENCRYPTION_REQUEST, string("") + byte_array(pub)
              + byte_array(verify_token) + boolean(True))
    s.flush("s2c")
    s.tcp.flush_acks()
    w.tick(0.21, 0.29)                    # клиент: POST sessionserver.mojang.com/session/minecraft/join
    enc_rng = random.Random(SEED + 3)
    s.c2s.put(ID.L_SB_ENCRYPTION_RESPONSE,
              byte_array(rsa_pkcs1v15_encrypt(n, e, secret, enc_rng))
              + byte_array(rsa_pkcs1v15_encrypt(n, e, verify_token, enc_rng)))
    s.flush("c2s")
    s.c2s.cipher = CFB8(secret)           # клиент шифрует всё после Encryption Response
    w.tick(0.14, 0.2)                     # сервер: GET .../session/minecraft/hasJoined
    s.s2c.cipher = CFB8(secret)           # сервер включает шифрование до Set Compression
    s.s2c.put(ID.L_CB_SET_COMPRESSION, write_varint(COMPRESSION_THRESHOLD))
    s.s2c.threshold = COMPRESSION_THRESHOLD
    s.s2c.put(ID.L_CB_LOGIN_SUCCESS, world.game_profile(player_uuid, USERNAME, rng)
              + uuid(_uuid4(rng)))
    s.flush("s2c")
    s.c2s.threshold = COMPRESSION_THRESHOLD
    w.tick(0.0008, 0.0015)
    s.c2s.put(ID.L_SB_LOGIN_ACK)

    # ---------------- 3. configuration ----------------
    s.c2s.put(ID.C_SB_PLUGIN_MESSAGE, identifier("minecraft:brand") + string("fabric"))
    s.c2s.put(ID.C_SB_CLIENT_INFORMATION, string("ru_ru") + byte(12) + write_varint(0)
              + boolean(True) + ubyte(0x7F) + write_varint(1) + boolean(False)
              + boolean(True) + write_varint(0))
    s.flush("c2s")
    w.tick(0.0009, 0.0016)
    s.s2c.put(ID.C_CB_PLUGIN_MESSAGE, identifier("minecraft:brand") + string("vanilla"))
    s.s2c.put(ID.C_CB_FEATURE_FLAGS, prefixed(["minecraft:vanilla"], identifier))
    s.s2c.put(ID.C_CB_KNOWN_PACKS, world.known_packs())
    s.flush("s2c")
    w.tick(0.0012, 0.002)
    s.c2s.put(ID.C_SB_KNOWN_PACKS, world.known_packs())
    s.flush("c2s")
    w.tick(0.002, 0.004)
    for reg in world.REGISTRIES:
        s.s2c.put(ID.C_CB_REGISTRY_DATA, world.registry_data(reg))
    s.s2c.put(ID.C_CB_UPDATE_TAGS, world.update_tags())
    s.s2c.put(ID.C_CB_FINISH)
    s.flush("s2c")
    w.tick(0.004, 0.009)
    s.c2s.put(ID.C_SB_FINISH_ACK)
    s.flush("c2s")

    # ---------------- 4. play: вход в мир ----------------
    pos = list(wall.at(-REACH - 1.5, Y0, 4.5))
    pos[0] += 0.5 if axis == "x" else 0
    pos[2] += 0.5 if axis == "z" else 0
    eid = rng.randrange(150, 900)
    w.tick(0.003, 0.006)
    s.s2c.put(ID.P_CB_LOGIN, world.login_play(eid, VIEW_DISTANCE, rng.getrandbits(63)))
    s.s2c.put(ID.P_CB_CHANGE_DIFFICULTY, ubyte(2) + boolean(False))
    s.s2c.put(ID.P_CB_PLAYER_ABILITIES, byte(0x0D) + f32(0.05) + f32(0.1))
    s.s2c.put(ID.P_CB_SET_HELD_ITEM, write_varint(0))
    s.s2c.put(ID.P_CB_PLAYER_POSITION, write_varint(1) + f64(pos[0]) + f64(pos[1]) + f64(pos[2])
              + f64(0) * 3 + f32(wall.yaw) + f32(8.5) + b"\x00\x00\x00\x00")
    s.flush("s2c")
    w.tick(0.004, 0.008)
    s.c2s.put(ID.P_SB_ACCEPT_TELEPORT, write_varint(1) + f64(pos[0]) + f64(pos[1]) + f64(pos[2])
              + f32(wall.yaw) + f32(8.5))
    s.c2s.put(ID.P_SB_MOVE_POS_ROT, f64(pos[0]) + f64(pos[1]) + f64(pos[2])
              + f32(wall.yaw) + f32(8.5) + byte(0x01))
    s.flush("c2s")

    def chunk_of(p):
        return math.floor(p[0]) >> 4, math.floor(p[2]) >> 4

    loaded = set()

    def send_chunks(center):
        cx0, cz0 = center
        new = sorted(((cx, cz) for cx in range(cx0 - VIEW_DISTANCE, cx0 + VIEW_DISTANCE + 1)
                      for cz in range(cz0 - VIEW_DISTANCE, cz0 + VIEW_DISTANCE + 1)
                      if (cx, cz) not in loaded),
                     key=lambda c: (c[0] - cx0) ** 2 + (c[1] - cz0) ** 2)
        s.s2c.put(ID.P_CB_SET_CENTER_CHUNK, write_varint(cx0) + write_varint(cz0))
        if new:
            s.s2c.put(ID.P_CB_CHUNK_BATCH_START)
            for c in new:
                s.s2c.put(ID.P_CB_CHUNK_DATA, world.chunk_data(c[0], c[1], wall_blocks))
                loaded.add(c)
            s.s2c.put(ID.P_CB_CHUNK_BATCH_FINISHED, write_varint(len(new)))
        return len(new)

    spawn = wall.at(-REACH - 2, Y0, 6)
    w.tick(0.002, 0.004)
    s.s2c.put(ID.P_CB_SET_DEFAULT_SPAWN, world.default_spawn(*spawn))
    s.s2c.put(ID.P_CB_GAME_EVENT, ubyte(13) + f32(0.0))
    center = chunk_of(pos)
    send_chunks(center)
    s.s2c.put(ID.P_CB_SYSTEM_CHAT, world.system_chat(f"{USERNAME} joined the game", "yellow"))
    s.flush("s2c")
    w.tick(0.03, 0.06)
    s.c2s.put(ID.P_SB_CHUNK_BATCH_RECEIVED, f32(9.2))
    s.flush("c2s")
    w.tick(0.4, 0.7)
    s.c2s.put(ID.P_SB_PLAYER_LOADED)
    s.c2s.put(ID.P_SB_CLIENT_TICK_END)
    s.flush("c2s")

    # ---------------- 5. play: гриф ----------------
    noise_rng = random.Random(SEED + 4)
    occupied = {p for p, _ in flag_blocks} | {p for p, _ in decoy_blocks} | wall_blocks
    todo = sorted(flag_blocks, key=lambda b: (b[1], noise_rng.random()))
    decoy_todo = sorted(decoy_blocks, key=lambda b: (b[1], noise_rng.random()))
    seq = 0
    tick = 0
    walk_h = -REACH - 1.5
    keepalive_due = None
    pending_batch = False
    idle_before, idle_after = 45, 30
    end_tick = None

    while True:
        tick += 1
        w.tick(TICK * 0.9, TICK * 1.1)

        # --- клиентский тик ---
        moved = False
        placed = []
        if tick > idle_before and todo:
            for b in list(todo):
                if len(placed) == PLACE_PER_TICK:
                    break
                if abs(b[1] - walk_h) <= REACH:
                    placed.append(b)
                    todo.remove(b)
            if not placed or len(placed) < PLACE_PER_TICK:
                walk_h += WALK_PER_TICK
                moved = True
        elif end_tick is None and not todo:
            end_tick = tick + idle_after
        if moved:
            pos = list(wall.at(walk_h, Y0, 4.5))
            pos[0] += 0.5 if axis == "x" else 0
            pos[2] += 0.5 if axis == "z" else 0
            s.c2s.put(ID.P_SB_MOVE_POS, f64(pos[0]) + f64(pos[1]) + f64(pos[2]) + byte(0x01))
        elif tick % 20 == 0:
            s.c2s.put(ID.P_SB_MOVE_POS, f64(pos[0]) + f64(pos[1]) + f64(pos[2]) + byte(0x01))
        for (bx, by, bz), _ in placed:
            seq += 1
            tx, ty, tz = (bx, by, bz - 1) if axis == "x" else (bx - 1, by, bz)
            cur = (noise_rng.uniform(0.05, 0.95), noise_rng.uniform(0.05, 0.95))
            cx, cy, cz = (cur[0], cur[1], 1.0) if axis == "x" else (1.0, cur[1], cur[0])
            s.c2s.put(ID.P_SB_USE_ITEM_ON, write_varint(0) + encode_position(tx, ty, tz)
                      + write_varint(wall.face) + f32(cx) + f32(cy) + f32(cz)
                      + boolean(False) + boolean(False) + write_varint(seq))
        if keepalive_due is not None:
            s.c2s.put(ID.P_SB_KEEP_ALIVE, long(keepalive_due))
            keepalive_due = None
        if pending_batch:
            s.c2s.put(ID.P_SB_CHUNK_BATCH_RECEIVED, f32(noise_rng.uniform(7.5, 11.0)))
            pending_batch = False
        s.c2s.put(ID.P_SB_CLIENT_TICK_END)
        s.flush("c2s")

        # --- серверный тик ---
        w.tick(0.003, 0.012)
        for (bx, by, bz), _ in placed:
            s.s2c.put(ID.P_CB_BLOCK_UPDATE, encode_position(bx, by, bz) + write_varint(FG_STATE))
        if placed:
            s.s2c.put(ID.P_CB_BLOCK_CHANGED_ACK, write_varint(seq))
        # Vasya_Builder неспешно выкладывает NOPE на соседней плоскости
        if decoy_todo and tick > 20 and tick % 3 == 0:
            (bx, by, bz), _ = decoy_todo.pop(0)
            s.s2c.put(ID.P_CB_BLOCK_UPDATE, encode_position(bx, by, bz) + write_varint(DECOY_STATE))
        # кто-то копает/строит неподалёку
        if noise_rng.random() < NOISE_EVENTS / 900:
            while True:
                p = (int(pos[0]) + noise_rng.randint(-40, 40), noise_rng.randint(60, 80),
                     int(pos[2]) + noise_rng.randint(-40, 40))
                if p not in occupied:
                    break
            s.s2c.put(ID.P_CB_BLOCK_UPDATE, encode_position(*p)
                      + write_varint(noise_rng.choice(NOISE_STATES)))
        if tick % KEEP_ALIVE_TICKS == 0:
            keepalive_due = int(w.now * 1000) - 1_740_000_000_000
            s.s2c.put(ID.P_CB_KEEP_ALIVE, long(keepalive_due))
        new_center = chunk_of(pos)
        if new_center != center:
            center = new_center
            pending_batch = send_chunks(center) > 0
        s.flush("s2c")
        s.tcp.flush_acks(0.0, sides=("c2s",))

        if end_tick is not None and tick >= end_tick and not decoy_todo:
            break

    # ---------------- 6. выход ----------------
    w.tick(0.3, 0.6)
    s.tcp.close(by="c2s")
    session_end = w.now

    if lossy:
        _make_lossy(s.tcp, random.Random(SEED + 5))

    log = _client_log(rng, n, e, pub, secret, verify_token, session_start, session_end)
    return {
        "pcap": w.to_bytes(),
        "log": log,
        "secret": secret,
        "verify_token": verify_token,
        "stats": {
            "flag_blocks": len(flag_blocks),
            "decoy_blocks": len(decoy_blocks),
            "frames": len(w.records),
            "chunks": len(loaded),
            "ticks": tick,
        },
    }


def _make_lossy(tcp, rng):
    """Ретрансмиссии и out-of-order в направлении сервер -> клиент."""
    w = tcp.w
    s2c = [k for k, (d, _, p, _) in enumerate(tcp.sent) if d == "s2c" and len(p) > 40]
    for k in rng.sample(s2c, min(LOSSY_RETRANS, len(s2c))):
        idx = tcp.sent[k][3]
        ts, frame_bytes = w.records[idx]
        w.records.append((ts + rng.uniform(0.2, 0.3), frame_bytes))   # повтор по RTO
    # переставляем только соседние в файле сегменты данных сервера (внутри одной пачки)
    pairs = [(tcp.sent[k][3], tcp.sent[k + 1][3]) for k in range(len(tcp.sent) - 1)
             if tcp.sent[k][0] == tcp.sent[k + 1][0] == "s2c"
             and tcp.sent[k + 1][3] == tcp.sent[k][3] + 1]
    for a, b in rng.sample(pairs, min(LOSSY_SWAPS, len(pairs))):
        (ta, fa), (tb, fb) = w.records[a], w.records[b]
        w.records[a], w.records[b] = (ta, fb), (tb, fa)
    w.records.sort(key=lambda r: r[0])


def _client_log(rng, n, e, pub, secret, token, start, end):
    """latest.log: 4 сессии, захвачена третья. Ключ сервера 10.0.0.10 один и тот же у
    2-й и 3-й сессий (сервер не перезапускался), после отката — новый."""
    def fp(der):
        return hashlib.sha1(der).hexdigest()

    other_pub = rsa_public_der(*generate_rsa(1024, seed=SEED + 10)[:2])
    rebooted_pub = rsa_public_der(*generate_rsa(1024, seed=SEED + 11)[:2])

    def rnd(k):
        return bytes(rng.randrange(256) for _ in range(k))

    def sess(t, host, pubkey, sec, tok, outcome, end_t, io):
        return clientlog.Session(t, host, SERVER_PORT, tok, fp(pubkey), sec,
                                 minecraft_server_hash(b"", sec, pubkey), outcome, end_t, io)

    boot = start - 17 * 60 - 21.4
    s1_t = boot + 78.2
    s1_sec, s2_sec, s4_sec = rnd(16), rnd(16), rnd(16)
    s2_t = start - 193.7
    s4_t = end + 14 * 60 + 37.9
    sessions = [
        sess(s1_t, "203.0.113.37", other_pub, s1_sec, rnd(4), [
            (1.4, "Render thread", "INFO", "Loaded 1484 advancements"),
            (1.6, "Render thread", "INFO", "[System] [CHAT] Добро пожаловать на CraftLand! Напиши /rtp"),
            (402.0, "Render thread", "INFO", "[System] [CHAT] [Сервер] Рестарт через 5 минут"),
            (523.5, "Render thread", "INFO", "Disconnecting from server"),
        ], s1_t + 523.5, 0),
        sess(s2_t, "10.0.0.10", pub, s2_sec, rnd(4), [
            (1.3, "Render thread", "INFO", "Loaded 1484 advancements"),
            (1.5, "Render thread", "INFO", f"[System] [CHAT] {USERNAME} joined the game"),
            (41.9, "Netty Client IO #{io}", "WARN", "Client disconnected with reason: Timed out"),
        ], s2_t + 41.9, 3),
        sess(start, "10.0.0.10", pub, secret, token, [
            (1.3, "Render thread", "INFO", "Loaded 1484 advancements"),
            (1.5, "Render thread", "INFO", f"[System] [CHAT] {USERNAME} joined the game"),
            (end - start, "Render thread", "INFO", "Disconnecting from server"),
        ], end, 5),
        sess(s4_t, "10.0.0.10", rebooted_pub, s4_sec, rnd(4), [
            (0.4, "Render thread", "INFO", "Disconnected from server: You are banned from this "
                                           "server. Reason: гриф у спавна, откат 23:05"),
        ], s4_t + 0.4, 7),
    ]
    return clientlog.render(boot, USERNAME, sessions, s4_t + 95.0)


# ---------------------------------------------------------------------------
# Хэндаут
# ---------------------------------------------------------------------------
ZIP_DATE = (2026, 10, 4, 9, 12, 0)


def make_zip(files) -> bytes:
    """Детерминированный zip: фиксированная дата, порядок и права."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            info = zipfile.ZipInfo(f"blockpost/{name}", ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    return buf.getvalue()


def gen(flag: str, out_dir: str, axis: str = "x", lossy: bool = False, zip_path: str = None):
    import os
    res = build(flag, axis=axis, lossy=lossy)
    os.makedirs(out_dir, exist_ok=True)
    pcap_path = os.path.join(out_dir, "challenge.pcap")
    log_path = os.path.join(out_dir, "latest.log")
    with open(pcap_path, "wb") as f:
        f.write(res["pcap"])
    with open(log_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(res["log"])
    if zip_path:
        with open(zip_path, "wb") as f:
            f.write(make_zip([("challenge.pcap", res["pcap"]),
                              ("latest.log", res["log"].encode("utf-8"))]))
    st = res["stats"]
    mode = [m for m, on in (("lossy", lossy), (f"axis={axis}", axis != "x")) if on]
    print(f"[+] Записаны {pcap_path}, {log_path}" + (f", {zip_path}" if zip_path else "")
          + (f" (hard: {', '.join(mode)})" if mode else ""))
    print(f"[+] Флаг (скрыт в блоках): {flag}")
    print(f"[+] Блоков надписи: {st['flag_blocks']}, ложной надписи: {st['decoy_blocks']}, "
          f"чанков: {st['chunks']}, тиков play: {st['ticks']}")
    print(f"[+] Кадров в pcap: {st['frames']}, {len(res['pcap'])} байт; "
          f"verify token {res['verify_token'].hex()}, secret {res['secret'].hex()}")
    return res
