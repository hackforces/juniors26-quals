
from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import socket
import struct
import tempfile
import threading
import time
import zlib
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request, send_file

STATE_DIR = Path(os.environ.get("STATE_DIR", "/var/lib/fastcalc"))
ACTIVE_PATH = STATE_DIR / "firmware.bin"
DEFAULT_PATH = Path(os.environ.get("DEFAULT_FIRMWARE", "/app/default.fw"))
LOCK_PATH = STATE_DIR / ".firmware.lock"
VM_SOCKET = os.environ.get("VM_SOCKET", "/run/fastcalc/vm.sock")

IMAGE_HEADER = struct.Struct("<4sHHIIIIIII")
REQUEST_HEADER = struct.Struct("<IIqqB7x")
RESPONSE_HEADER = struct.Struct("<III")
IMAGE_MAGIC = b"FWM2"
IMAGE_VERSION = 2
IMAGE_FLAGS = 1
MAX_CODE = 1024
MAX_CONST = 512
MAX_IMAGE = IMAGE_HEADER.size + MAX_CODE + MAX_CONST
MAX_OUTPUT = 512
REQUEST_MAGIC = 0x31564D52
RESPONSE_MAGIC = 0x31564D53
JWT_TTL = 3600
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_urlsafe(32)).encode()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", secrets.token_urlsafe(24))



OPERATIONS = {
    "+": 0,
    "-": 1,
    "*": 2,
    "/": 3,
    "%": 4,
    "|": 5,
    "&": 6,
    "^": 7,
}
BASES = {2, 8, 10, 16}
VALID_INT_MIN = -(1 << 31)
VALID_INT_MAX = (1 << 31) - 1
DECIMAL_OUTPUT = re.compile(r"^[+-]?[0-9]+$")
LOGIN_FIELDS = frozenset({"username", "password"})
CALCULATE_FIELDS = frozenset({"a", "b", "op", "input_base", "output_base"})

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE + 128
_io_lock = threading.RLock()


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _make_token(subject: str, role: str) -> str:
    header = {"typ": "JWT", "alg": "HS256"}
    payload = {
        "sub": subject,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_TTL,
    }
    encoded_header = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64_encode(signature)}"


def _decode_token(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header = json.loads(_b64_decode(parts[0]))
    payload = json.loads(_b64_decode(parts[1]))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("malformed token")

    algorithm = header.get("alg")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    if algorithm == "HS256":
        expected = hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()
        supplied = _b64_decode(parts[2])
        if not hmac.compare_digest(expected, supplied):
            raise ValueError("invalid signature")
    elif algorithm == "none":
        
        pass
    else:
        raise ValueError("unsupported algorithm")

    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise ValueError("invalid subject")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("expired token")
    return payload


def _request_claims() -> dict[str, Any] | None:
    token = request.cookies.get("fastcalc_token")
    if not token:
        authorization = request.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            token = authorization[7:]
    if not token:
        return None
    try:
        return _decode_token(token)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, binascii.Error, UnicodeDecodeError, OverflowError):
        return None


def _require_login() -> dict[str, Any] | tuple[Any, int]:
    claims = _request_claims()
    if claims is None:
        return jsonify({"ok": False, "error": "login required"}), 401
    return claims


def _require_admin() -> dict[str, Any] | tuple[Any, int]:
    claims = _request_claims()
    if claims is None:
        return jsonify({"ok": False, "error": "login required"}), 401
    if claims.get("role") != "admin":
        return jsonify({"ok": False, "error": "administrator role required"}), 403
    return claims


def _mask_byte(key: int, index: int) -> int:
    lane = (key >> ((index & 3) * 8)) & 0xFF
    return (lane + index * 0x3D + (index // 4) * 0x17) & 0xFF


def _decode_payload(payload: bytes, key: int) -> bytes:
    return bytes(value ^ _mask_byte(key, i) for i, value in enumerate(payload))


def _validate_image(data: bytes) -> None:
    if len(data) < IMAGE_HEADER.size or len(data) > MAX_IMAGE:
        raise ValueError("firmware size is outside the service limit")
    magic, version, header_size, code_len, const_len, entry, flags, crc, key, reserved = (
        IMAGE_HEADER.unpack_from(data)
    )
    if (
        magic != IMAGE_MAGIC
        or version != IMAGE_VERSION
        or header_size != IMAGE_HEADER.size
        or flags != IMAGE_FLAGS
        or reserved != 0
        or code_len == 0
        or code_len > MAX_CODE
        or const_len > MAX_CONST
        or entry >= code_len
        or header_size + code_len + const_len != len(data)
    ):
        raise ValueError("firmware header is not accepted")
    plain = _decode_payload(data[header_size:], key)
    if zlib.crc32(plain) & 0xFFFFFFFF != crc:
        raise ValueError("firmware checksum mismatch")


def _read_active() -> bytes:
    with LOCK_PATH.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
        try:
            return ACTIVE_PATH.read_bytes()
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _write_active(data: bytes) -> None:
    _validate_image(data)
    with LOCK_PATH.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        fd, temporary = tempfile.mkstemp(prefix=".firmware.", dir=STATE_DIR)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, ACTIVE_PATH)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _ensure_state() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not DEFAULT_PATH.is_file():
        raise RuntimeError("default firmware is missing")
    if ACTIVE_PATH.is_file():
        try:
            _validate_image(ACTIVE_PATH.read_bytes())
            return
        except ValueError:
            pass
    _write_active(DEFAULT_PATH.read_bytes())


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        piece = sock.recv(length - len(chunks))
        if not piece:
            raise ConnectionError("VM service closed the connection")
        chunks.extend(piece)
    return bytes(chunks)


def _run_vm(image: bytes, a: int, b: int, operation: int) -> tuple[int, str]:
    packet = REQUEST_HEADER.pack(REQUEST_MAGIC, len(image), a, b, operation) + image
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(2.0)
        sock.connect(VM_SOCKET)
        sock.sendall(packet)
        response = _recv_exact(sock, RESPONSE_HEADER.size)
        magic, status, output_len = RESPONSE_HEADER.unpack(response)
        if magic != RESPONSE_MAGIC or output_len > MAX_OUTPUT:
            raise ConnectionError("malformed VM response")
        output = _recv_exact(sock, output_len)
    return status, output.decode("utf-8", "replace")


def _json_input() -> dict[str, Any]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("JSON object expected")
    return data


def _check_fields(data: dict[str, Any], allowed: frozenset[str]) -> None:
    missing = allowed - data.keys()
    extra = data.keys() - allowed
    if missing:
        raise ValueError("missing fields: " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("unknown fields: " + ", ".join(sorted(extra)))


def _get_base(data: dict[str, Any], name: str) -> int:
    raw = data[name]
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        raise ValueError(f"{name} must be one of 2, 8, 10, 16")
    try:
        base = int(raw, 10) if isinstance(raw, str) else raw
    except ValueError as exc:
        raise ValueError(f"{name} must be one of 2, 8, 10, 16") from exc
    if base not in BASES:
        raise ValueError(f"{name} must be one of 2, 8, 10, 16")
    return base


def _parse_number(value: Any, base: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("numbers must be strings or integers")
    if isinstance(value, int) and base != 10:
        raise ValueError("non-decimal numbers must be strings")
    text = str(value).strip().lower()
    if not text:
        raise ValueError("numbers cannot be empty")

    sign = ""
    if text[0] in "+-":
        sign, text = text[0], text[1:]
    prefixes = {2: "0b", 8: "0o", 16: "0x"}
    if base in prefixes and text.startswith(prefixes[base]):
        text = text[2:]
    elif text.startswith(("0b", "0o", "0x")):
        raise ValueError("number prefix does not match the selected base")
    if not text:
        raise ValueError("numbers cannot be empty")
    try:
        return int(sign + text, base)
    except ValueError as exc:
        raise ValueError(f"{value!r} is not a valid base-{base} number") from exc


def _format_value(value: str, base: int) -> str:
    
    
    if base == 10 or not DECIMAL_OUTPUT.fullmatch(value):
        return value
    number = int(value, 10)
    sign = "-" if number < 0 else ""
    digits = format(abs(number), {2: "b", 8: "o", 16: "x"}[base])
    return f"{sign}{'0b' if base == 2 else '0o' if base == 8 else '0x'}{digits}"


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/login")
def login():
    try:
        data = _json_input()
        _check_fields(data, LOGIN_FIELDS)
        username = data["username"]
        password = data["password"]
        if (
            isinstance(username, bool)
            or not isinstance(username, str)
            or isinstance(password, bool)
            or not isinstance(password, str)
        ):
            raise ValueError("username and password must be strings")
        username = username.strip().lower()
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "invalid login request"}), 400

    role = None
    if username == "guest" and password == "":
        role = "guest"
    elif username == "admin" and hmac.compare_digest(password, ADMIN_PASSWORD):
        role = "admin"
    if role is None:
        return jsonify({"ok": False, "error": "wrong username or password"}), 401

    token = _make_token(username, role)
    response = jsonify({"ok": True, "role": role, "token": token})
    response.set_cookie(
        "fastcalc_token", token, max_age=JWT_TTL, httponly=True, samesite="Lax"
    )
    return response


@app.post("/api/logout")
def logout():
    response = jsonify({"ok": True})
    response.delete_cookie("fastcalc_token")
    return response


@app.get("/api/me")
def me():
    claims = _require_login()
    if isinstance(claims, tuple):
        return claims
    return jsonify({"ok": True, "role": claims["role"], "username": claims["sub"]})


@app.post("/api/calculate")
def calculate():
    claims = _require_login()
    if isinstance(claims, tuple):
        return claims
    try:
        data = _json_input()
        _check_fields(data, CALCULATE_FIELDS)
        input_base = _get_base(data, "input_base")
        output_base = _get_base(data, "output_base")
        a = _parse_number(data["a"], input_base)
        b = _parse_number(data["b"], input_base)
        operation_name = data["op"]
        if not isinstance(operation_name, str):
            raise ValueError("op must be a string")
        if not VALID_INT_MIN <= a <= VALID_INT_MAX or not VALID_INT_MIN <= b <= VALID_INT_MAX:
            raise ValueError("numbers are outside the calculator range")
        if operation_name not in OPERATIONS:
            raise ValueError("unknown operation")

        image = _read_active()
        status, value = _run_vm(image, a, b, OPERATIONS[operation_name])
        if status != 0:
            return jsonify({"ok": False, "error": value}), 400
        return jsonify({"ok": True, "value": _format_value(value, output_base)})
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except (ConnectionError, OSError):
        return jsonify({"ok": False, "error": "calculator backend is restarting"}), 503


@app.get("/api/firmware")
def api_firmware():
    claims = _require_admin()
    if isinstance(claims, tuple):
        return claims
    with _io_lock:
        image = _read_active()
    response = send_file(
        io.BytesIO(image),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name="firmware.bin",
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/upload")
def api_upload():
    claims = _require_admin()
    if isinstance(claims, tuple):
        return claims
    if request.mimetype != "application/octet-stream":
        return jsonify({"ok": False, "error": "application/octet-stream required"}), 415
    data = request.get_data(cache=False)
    try:
        _write_active(data)
    except (OSError, ValueError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "bytes": len(data)})


@app.post("/api/reset")
def api_reset():
    claims = _require_admin()
    if isinstance(claims, tuple):
        return claims
    if request.get_data(cache=False):
        return jsonify({"ok": False, "error": "reset does not accept a body"}), 400
    try:
        _write_active(DEFAULT_PATH.read_bytes())
    except (OSError, ValueError):
        return jsonify({"ok": False, "error": "factory image is unavailable"}), 500
    return jsonify({"ok": True})


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"ok": False, "error": "not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"ok": False, "error": "method not allowed"}), 405


_ensure_state()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
