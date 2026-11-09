"""Срез протокола Minecraft Java Edition 26.3 (protocol 777): VarInt, Position, фрейм пакета.

Все версионно-зависимые ID пакетов собраны здесь, в одной таблице констант
(источник: minecraft.wiki/w/Java_Edition_protocol/Packets, ревизия от 2026-10-07).
"""

import zlib

PROTOCOL_VERSION = 777
GAME_VERSION = "26.3"
SERVER_PORT = 25565
COMPRESSION_THRESHOLD = 256   # network-compression-threshold по умолчанию


class ID:
    """Packet IDs, protocol 777. Префикс: H/S/L/C/P = handshake/status/login/configuration/play,
    CB/SB = clientbound/serverbound."""

    # handshake
    H_SB_INTENTION = 0x00
    # status
    S_SB_STATUS_REQUEST = 0x00
    S_SB_PING = 0x01
    S_CB_STATUS_RESPONSE = 0x00
    S_CB_PONG = 0x01
    # login
    L_CB_DISCONNECT = 0x00
    L_CB_ENCRYPTION_REQUEST = 0x01      # hello
    L_CB_LOGIN_SUCCESS = 0x02           # login_finished
    L_CB_SET_COMPRESSION = 0x03         # login_compression
    L_SB_LOGIN_START = 0x00             # hello
    L_SB_ENCRYPTION_RESPONSE = 0x01     # key
    L_SB_LOGIN_ACK = 0x03               # login_acknowledged
    # configuration
    C_CB_PLUGIN_MESSAGE = 0x01
    C_CB_FINISH = 0x03
    C_CB_KEEP_ALIVE = 0x04
    C_CB_REGISTRY_DATA = 0x07
    C_CB_FEATURE_FLAGS = 0x0D
    C_CB_UPDATE_TAGS = 0x0E
    C_CB_KNOWN_PACKS = 0x0F
    C_SB_CLIENT_INFORMATION = 0x00
    C_SB_PLUGIN_MESSAGE = 0x02
    C_SB_FINISH_ACK = 0x03
    C_SB_KNOWN_PACKS = 0x07
    # play, clientbound
    P_CB_BLOCK_CHANGED_ACK = 0x04
    P_CB_BLOCK_UPDATE = 0x08
    P_CB_CHANGE_DIFFICULTY = 0x0A
    P_CB_CHUNK_BATCH_FINISHED = 0x0B
    P_CB_CHUNK_BATCH_START = 0x0C
    P_CB_GAME_EVENT = 0x27
    P_CB_KEEP_ALIVE = 0x2D
    P_CB_CHUNK_DATA = 0x2E              # level_chunk_with_light
    P_CB_LOGIN = 0x32
    P_CB_PLAYER_ABILITIES = 0x41
    P_CB_PLAYER_POSITION = 0x49         # synchronize player position
    P_CB_SET_CENTER_CHUNK = 0x60
    P_CB_SET_DEFAULT_SPAWN = 0x63
    P_CB_SET_HELD_ITEM = 0x6B
    P_CB_SYSTEM_CHAT = 0x7C
    # play, serverbound
    P_SB_ACCEPT_TELEPORT = 0x00
    P_SB_CHUNK_BATCH_RECEIVED = 0x0B
    P_SB_CLIENT_TICK_END = 0x0D
    P_SB_KEEP_ALIVE = 0x1C
    P_SB_MOVE_POS = 0x1E
    P_SB_MOVE_POS_ROT = 0x1F
    P_SB_PLAYER_LOADED = 0x2C
    P_SB_USE_ITEM_ON = 0x42


# ---------------------------------------------------------------------------
# VarInt
# ---------------------------------------------------------------------------
def write_varint(value: int) -> bytes:
    """VarInt: 7 бит на группу, старший бит = "есть продолжение"."""
    out = bytearray()
    v = value & 0xFFFFFFFF
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_varint(buf: bytes, off: int):
    """Читает VarInt из buf с позиции off. Возвращает (value, new_off)."""
    val = 0
    pos = 0
    while True:
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << pos
        if not (b & 0x80):
            # знаковое 32-битное two's complement
            if val & 0x80000000:
                val -= 0x100000000
            return val, off
        pos += 7
        if pos >= 35:
            raise ValueError("VarInt too big")


# ---------------------------------------------------------------------------
# Position
# ---------------------------------------------------------------------------
def encode_position(x: int, y: int, z: int) -> bytes:
    """Position: x(26) << 38 | z(26) << 12 | y(12), big-endian 8 байт."""
    v = ((x & 0x3FFFFFF) << 38) | ((z & 0x3FFFFFF) << 12) | (y & 0xFFF)
    return v.to_bytes(8, "big")


def decode_position(b: bytes):
    """Обратное преобразование Position -> (x, y, z) со знаком."""
    v = int.from_bytes(b, "big")
    x = v >> 38
    z = (v >> 12) & 0x3FFFFFF
    y = v & 0xFFF
    if x & (1 << 25):
        x -= (1 << 26)
    if z & (1 << 25):
        z -= (1 << 26)
    if y & (1 << 11):
        y -= (1 << 12)
    return x, y, z


# ---------------------------------------------------------------------------
# Фрейм пакета
# ---------------------------------------------------------------------------
def frame(packet_id: int, data: bytes, threshold=None) -> bytes:
    """Кадр пакета.

    threshold=None — без компрессии: VarInt(len) | VarInt(id) | data.
    threshold=N    — после Set Compression: VarInt(len) | VarInt(data_len) | payload,
                     где payload = zlib(id|data) и data_len = len(id|data), если
                     len(id|data) >= N, иначе payload = id|data и data_len = 0.
    """
    body = write_varint(packet_id) + data
    if threshold is None:
        return write_varint(len(body)) + body
    if len(body) >= threshold:
        inner = write_varint(len(body)) + zlib.compress(body)
    else:
        inner = write_varint(0) + body
    return write_varint(len(inner)) + inner


def unframe(stream: bytes, off: int, threshold=None):
    """Читает один кадр с позиции off. Возвращает (packet_id, data, new_off).

    Бросает IndexError/ValueError, если кадр обрезан или битый.
    """
    length, o2 = read_varint(stream, off)
    end = o2 + length
    if length < 1 or end > len(stream):
        raise IndexError("кадр обрезан")
    body = stream[o2:end]
    if threshold is not None:
        data_len, o3 = read_varint(body, 0)
        if data_len:
            body = zlib.decompress(body[o3:])
            if len(body) != data_len:
                raise ValueError("Data Length не совпадает с распакованным размером")
        else:
            body = body[o3:]
    pid, o4 = read_varint(body, 0)
    return pid, body[o4:], end


def block_update(x: int, y: int, z: int, state: int, threshold=None) -> bytes:
    return frame(ID.P_CB_BLOCK_UPDATE, encode_position(x, y, z) + write_varint(state),
                 threshold)
