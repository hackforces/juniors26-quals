"""Содержимое мира и тела «служебных» пакетов: чанки, реестры, теги, статус сервера.

Это фон для правдоподобия: участнику не нужно его разбирать, но после расшифровки
поток выглядит как настоящая сессия (configuration с реестрами, чанки с светом и т. д.).
Block-state ID зависят от версии; здесь — правдоподобные значения, согласованные внутри задания.
"""

import base64
import json
import math

from .mctypes import (
    boolean, f32, identifier, int32, json_text, long, nbt_text, optional, prefixed,
    short, string, ubyte, uuid,
)
from .protocol import GAME_VERSION, PROTOCOL_VERSION, encode_position, write_varint

# --- block states -----------------------------------------------------------
AIR = 0
STONE = 1
GRASS_BLOCK = 9
DIRT = 10
COBBLESTONE = 14
OAK_PLANKS = 15
BEDROCK = 85
LIME_WOOL = 2099
RED_WOOL = 2107
STONE_BRICKS = 6543
DEEPSLATE = 25965

MIN_Y, HEIGHT = -64, 384
SECTIONS = HEIGHT // 16
GROUND_Y = 69                 # верхний блок травы; на нём стоят игроки (ноги на y=70)

# --- реестры (порядок записей задаёт числовые ID) ---------------------------
REGISTRIES = {
    "minecraft:dimension_type": ["overworld", "overworld_caves", "the_end", "the_nether"],
    "minecraft:worldgen/biome": [
        "badlands", "bamboo_jungle", "beach", "birch_forest", "cherry_grove", "cold_ocean",
        "dark_forest", "deep_dark", "desert", "dripstone_caves", "forest", "frozen_river",
        "grove", "jagged_peaks", "jungle", "lush_caves", "mangrove_swamp", "meadow",
        "mushroom_fields", "nether_wastes", "ocean", "old_growth_birch_forest", "pale_garden",
        "plains", "river", "savanna", "snowy_plains", "sunflower_plains", "swamp", "taiga",
        "the_end", "the_void", "warm_ocean", "windswept_hills",
    ],
    "minecraft:chat_type": [
        "chat", "emote_command", "msg_command_incoming", "msg_command_outgoing",
        "say_command", "team_msg_command_incoming", "team_msg_command_outgoing",
    ],
    "minecraft:damage_type": [
        "arrow", "bad_respawn_point", "cactus", "campfire", "cramming", "dragon_breath",
        "drown", "dry_out", "ender_pearl", "explosion", "fall", "falling_anvil",
        "falling_block", "fireball", "fireworks", "fly_into_wall", "freeze", "generic",
        "generic_kill", "hot_floor", "in_fire", "in_wall", "lava", "lightning_bolt",
        "magic", "mob_attack", "on_fire", "out_of_world", "player_attack", "player_explosion",
        "starve", "sting", "sweet_berry_bush", "thorns", "thrown", "trident", "wither",
    ],
    "minecraft:painting_variant": [
        "alban", "aztec", "aztec2", "backyard", "bomb", "bouquet", "burning_skull", "bust",
        "cavebird", "changing", "cotan", "courbet", "creebet", "donkey_kong", "earth",
        "fern", "fighters", "finding", "fire", "graham", "humble", "kebab", "lowmist",
        "match", "meditative", "orb", "owlemons", "passage", "pigscene", "plant",
    ],
    "minecraft:wolf_variant": ["ashen", "black", "chestnut", "pale", "rusty", "snowy",
                               "spotted", "striped", "woods"],
    "minecraft:trim_material": ["amethyst", "copper", "diamond", "emerald", "gold", "iron",
                                "lapis", "netherite", "quartz", "redstone", "resin"],
    "minecraft:trim_pattern": ["bolt", "coast", "dune", "eye", "flow", "host", "raiser",
                               "rib", "sentry", "shaper", "silence", "snout", "spire",
                               "tide", "vex", "ward", "wayfinder", "wild"],
    "minecraft:banner_pattern": ["base", "border", "bricks", "circle", "creeper", "cross",
                                 "curly_border", "diagonal_left", "flower", "globe",
                                 "mojang", "piglin", "skull", "stripe_bottom"],
    "minecraft:jukebox_song": ["11", "13", "5", "blocks", "cat", "chirp", "creator", "far",
                               "mall", "mellohi", "otherside", "pigstep", "relic", "stal",
                               "strad", "wait", "ward"],
    "minecraft:instrument": ["admire_goat_horn", "call_goat_horn", "dream_goat_horn",
                             "feel_goat_horn", "ponder_goat_horn", "seek_goat_horn",
                             "sing_goat_horn", "yearn_goat_horn"],
}
PLAINS = REGISTRIES["minecraft:worldgen/biome"].index("plains")

TAGS = {
    "minecraft:block": {
        "minecraft:wool": list(range(140, 156)),
        "minecraft:planks": [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
        "minecraft:dirt": [9, 10, 11, 12, 1203, 1204],
        "minecraft:base_stone_overworld": [1, 2, 4, 6, 1080, 1101],
        "minecraft:climbable": [194, 286, 1137, 1138, 1213],
        "minecraft:mineable/pickaxe": [1, 2, 3, 4, 5, 6, 7, 14, 85, 1080],
    },
    "minecraft:item": {
        "minecraft:wool": list(range(206, 222)),
        "minecraft:planks": list(range(36, 48)),
    },
    "minecraft:fluid": {"minecraft:water": [1, 2], "minecraft:lava": [3, 4]},
}


def registry_data(name):
    """Тело Registry Data: записи без данных (данные клиент берёт из known pack minecraft:core)."""
    return identifier(name) + prefixed(REGISTRIES[name],
                                       lambda e: identifier(e) + optional(None))


def update_tags():
    def tag(item):
        name, ids = item
        return identifier(name) + prefixed(ids, write_varint)
    return prefixed(TAGS.items(),
                    lambda r: identifier(r[0]) + prefixed(r[1].items(), tag))


def known_packs():
    return prefixed([("minecraft", "core", GAME_VERSION)],
                    lambda p: string(p[0]) + string(p[1]) + string(p[2]))


def status_json(online_sample):
    return json_text({
        "version": {"name": GAME_VERSION, "protocol": PROTOCOL_VERSION},
        "players": {"max": 20, "online": len(online_sample),
                    "sample": [{"name": n, "id": str(u)} for n, u in online_sample]},
        "description": {"text": "§2Blockpost §7SMP §8| §7только по вайтлисту"},
        "enforcesSecureChat": True,
    })


def game_profile(player_uuid, name, rng):
    textures = {
        "timestamp": 1790000000000 + rng.randrange(10 ** 9),
        "profileId": player_uuid.hex, "profileName": name, "signatureRequired": True,
        "textures": {"SKIN": {"url": "http://textures.minecraft.net/texture/"
                              + bytes(rng.randrange(256) for _ in range(32)).hex()}},
    }
    value = base64.b64encode(json.dumps(textures).encode()).decode()
    sig = base64.b64encode(bytes(rng.randrange(256) for _ in range(512))).decode()
    prop = string("textures") + string(value) + optional(sig, string)
    return uuid(player_uuid) + string(name) + prefixed([prop])


# --- чанки -------------------------------------------------------------------
def _bitset(bits):
    n = (max(bits) // 64 + 1) if bits else 0
    words = [0] * n
    for b in bits:
        words[b // 64] |= 1 << (b % 64)
    return write_varint(n) + b"".join(long(w - (1 << 64) if w >> 63 else w) for w in words)


def _pack(values, bpe):
    per = 64 // bpe
    out = []
    for i in range(0, len(values), per):
        w = 0
        for j, v in enumerate(values[i:i + per]):
            w |= v << (j * bpe)
        out.append(long(w - (1 << 64) if w >> 63 else w))
    return b"".join(out)


def _single(value):
    return ubyte(0) + write_varint(value)


def _indirect(grid):
    """Paletted container на 4096 записей (индекс = (y*16 + z)*16 + x)."""
    palette = sorted(set(grid))
    if len(palette) == 1:
        return _single(palette[0])
    bpe = max(4, math.ceil(math.log2(len(palette))))
    idx = {v: i for i, v in enumerate(palette)}
    return ubyte(bpe) + prefixed(palette, write_varint) + _pack([idx[v] for v in grid], bpe)


def _section(grid):
    count = sum(1 for v in grid if v != AIR)
    return short(count) + short(0) + _indirect(grid) + _single(PLAINS)


def chunk_data(cx, cz, wall_blocks):
    """Chunk Data and Update Light: бедрок, глубинный сланец, камень, земля, трава и
    каменная стена у спавна (wall_blocks — множество (x, y, z), на которое кладут шерсть)."""
    sections = []
    local_wall = [(x & 15, y, z & 15) for (x, y, z) in wall_blocks
                  if x >> 4 == cx and z >> 4 == cz]
    top = [[GROUND_Y] * 16 for _ in range(16)]
    for s in range(SECTIONS):
        y0 = MIN_Y + s * 16
        if y0 + 15 < GROUND_Y - 8 and y0 > MIN_Y:
            sections.append(short(4096) + short(0) + _single(DEEPSLATE if y0 < 0 else STONE)
                            + _single(PLAINS))
            continue
        if y0 > GROUND_Y and not any(y0 <= y < y0 + 16 for _, y, _ in local_wall):
            sections.append(short(0) + short(0) + _single(AIR) + _single(PLAINS))
            continue
        grid = []
        for ly in range(16):
            y = y0 + ly
            for z in range(16):
                for x in range(16):
                    if y == MIN_Y:
                        v = BEDROCK
                    elif y < GROUND_Y - 4:
                        v = DEEPSLATE if y < 0 else STONE
                    elif y < GROUND_Y:
                        v = DIRT
                    elif y == GROUND_Y:
                        v = GRASS_BLOCK
                    else:
                        v = AIR
                    grid.append(v)
        for (x, y, z) in local_wall:
            if y0 <= y < y0 + 16:
                grid[((y - y0) * 16 + z) * 16 + x] = STONE_BRICKS
                top[z][x] = max(top[z][x], y)
        sections.append(_section(grid))
    data = b"".join(sections)

    hm = [top[z][x] + 1 - MIN_Y for z in range(16) for x in range(16)]
    heightmaps = prefixed([1, 4], lambda t: write_varint(t) + write_varint(37) + _pack(hm, 9))

    # свет: небо полностью освещено над землёй, под землёй — пусто
    ground_light_sec = (GROUND_Y - MIN_Y) // 16 + 1          # +1: секция под миром
    sky = list(range(ground_light_sec + 1, SECTIONS + 2))
    light = (_bitset(sky) + _bitset([]) + _bitset(list(range(0, ground_light_sec + 1)))
             + _bitset(list(range(SECTIONS + 2)))
             + prefixed(sky, lambda _: write_varint(2048) + b"\xff" * 2048)
             + prefixed([]))
    return (int32(cx) + int32(cz) + heightmaps + write_varint(len(data)) + data
            + prefixed([]) + light)


# --- play: стартовые пакеты --------------------------------------------------
def login_play(entity_id, view_distance, hashed_seed):
    return (int32(entity_id) + boolean(False)
            + prefixed(["minecraft:overworld", "minecraft:the_nether", "minecraft:the_end"],
                       identifier)
            + write_varint(20) + write_varint(view_distance) + write_varint(view_distance)
            + boolean(False) + boolean(True) + boolean(False)
            + write_varint(0) + identifier("minecraft:overworld") + long(hashed_seed)
            + write_varint(1)              # game mode: creative
            + write_varint(0)              # previous game mode: undefined
            + boolean(False) + boolean(False) + boolean(False)
            + write_varint(0) + write_varint(63)
            + boolean(True) + boolean(True))


def default_spawn(x, y, z):
    return identifier("minecraft:overworld") + encode_position(x, y, z) + f32(0.0) + f32(0.0)


def system_chat(text, color=None):
    return nbt_text(text, color) + boolean(False)
