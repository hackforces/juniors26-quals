"""latest.log модифицированного клиента (Fabric + отладочный мод netdebug).

Мод пишет в DEBUG параметры шифрования каждой сессии: verify token из Encryption
Request, отпечаток ключа сервера и сам shared secret. В логе несколько сессий;
к записанному соединению относится та, чей verify token виден в pcap открытым текстом.
"""

import datetime as dt

LOG_TZ = dt.timezone(dt.timedelta(hours=3))   # часы клиента — МСК, pcap — UTC
MOD = "netdebug"


class Session:
    def __init__(self, start_utc: float, host: str, port: int, verify_token: bytes,
                 key_fp: str, secret: bytes, server_hash: str, outcome: list,
                 end_utc: float, io_thread: int):
        self.start = start_utc
        self.host, self.port = host, port
        self.verify_token = verify_token
        self.key_fp = key_fp
        self.secret = secret
        self.server_hash = server_hash
        self.outcome = outcome            # [(dt_секунд от старта, поток, уровень, текст)]
        self.end = end_utc
        self.io_thread = io_thread


def _t(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, LOG_TZ).strftime("%H:%M:%S")


def render(boot_utc: float, username: str, sessions, shutdown_utc: float) -> str:
    L = []

    def log(ts, thread, level, msg):
        L.append(f"[{_t(ts)}] [{thread}/{level}]: {msg}")

    def mod(ts, io, msg):
        L.append(f"[{_t(ts)}] [Netty Client IO #{io}/DEBUG] ({MOD}) {msg}")

    t = boot_utc
    log(t, "main", "INFO", "Loading Minecraft 26.3 with Fabric Loader 0.17.3")
    L.append("[{}] [main/INFO]: Loading 6 mods:\n"
             "\t- fabric-api 0.134.1+26.3\n"
             "\t- fabricloader 0.17.3\n"
             "\t- java 21\n"
             "\t- minecraft 26.3\n"
             "\t- netdebug 0.3.1-SNAPSHOT\n"
             "\t- sodium 0.7.2+mc26.3".format(_t(t)))
    log(t + 1, "main", "INFO", "SpongePowered MIXIN Subsystem Version=0.8.7 Source=union:/home/kolya/.minecraft/libraries/net/fabricmc/sponge-mixin/0.16.4+mixin.0.8.7/sponge-mixin-0.16.4+mixin.0.8.7.jar Service=Knot/Fabric Env=CLIENT")
    log(t + 3, "Datafixer Bootstrap", "INFO", "263 Datafixer optimizations took 512 milliseconds")
    log(t + 4, "Render thread", "INFO", "Environment: Environment[sessionHost=https://sessionserver.mojang.com, servicesHost=https://api.minecraftservices.com, name=PROD]")
    log(t + 4, "Render thread", "INFO", f"Setting user: {username}")
    log(t + 5, "Render thread", "INFO", f"[{MOD}] netdebug 0.3.1-SNAPSHOT loaded, verbose=true, dump=handshake")
    log(t + 6, "Render thread", "INFO", "Backend library: LWJGL version 3.3.3-snapshot")
    log(t + 7, "Render thread", "INFO", "Reloading ResourceManager: vanilla, fabric, sodium")
    log(t + 9, "Render thread", "INFO", "OpenAL initialized on device OpenAL Soft")
    log(t + 9, "Render thread", "INFO", "Sound engine started")
    log(t + 10, "Render thread", "INFO", "Created: 2048x1024x4 minecraft:textures/atlas/blocks.png-atlas")

    for s in sessions:
        io = s.io_thread
        log(s.start, "Render thread", "INFO", f"Connecting to {s.host}, {s.port}")
        mod(s.start + 0.05, io, f">> intention protocol=777 address={s.host}:{s.port} intent=LOGIN")
        mod(s.start + 0.05, io, f">> hello name={username}")
        mod(s.start + 0.09, io, f"<< hello server_id=\"\" public_key=RSA-1024 fp=sha1:{s.key_fp} "
                                f"verify_token={s.verify_token.hex()} should_authenticate=true")
        mod(s.start + 0.09, io, f"session join: server_hash={s.server_hash}")
        mod(s.start + 0.31, io, f">> key (shared_secret=128B, verify_token=128B, RSA/ECB/PKCS1Padding)")
        mod(s.start + 0.31, io, f"cipher enabled: AES/CFB8/NoPadding secret={s.secret.hex()}")
        for dt_s, thread, level, msg in s.outcome:
            log(s.start + dt_s, thread.format(io=io), level, msg)

    log(shutdown_utc, "Render thread", "INFO", "Stopping!")
    return "\n".join(L) + "\n"
