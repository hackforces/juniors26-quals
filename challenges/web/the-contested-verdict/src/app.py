import functools
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from flask import (
    Flask, request, render_template, Response,
    session, redirect, url_for,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())

# Personal dynamic target: the flag comes from the environment at container
# start — CTF_FLAG only. No default, ever.
FLAG = os.environ.get("CTF_FLAG")
if not FLAG:
    raise RuntimeError("CTF_FLAG env is required — refusing to start without a flag")

LOGIN = "admin"
# Deliberately weak: the login step is meant to fall to a rockyou-style
# dictionary attack (the word is inside rockyou's top slice).
PASSWORD = os.environ.get("PASSWORD", "matrix")

# The judge runs Lua in a child process (src/judge_worker.py) with a hard
# wall-clock limit: an infinite loop in a submission cannot wedge the lock
# or the worker threads. The page copy promises "up to a minute".
JUDGE_TIMEOUT = 30
WORKER = Path(__file__).resolve().parent / "judge_worker.py"

PORT = int(os.environ.get("PORT", "8080"))
BASE = f"http://127.0.0.1:{PORT}"


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


_judge_lock = threading.Lock()
_ctx = {"data1": 0, "data2": 0, "out": None}


@app.route("/system/data1")
def system_data1():
    return str(_ctx["data1"])


@app.route("/system/data2")
def system_data2():
    return str(_ctx["data2"])


@app.route("/system/out", methods=["POST"])
def system_out():
    _ctx["out"] = request.get_data(as_text=True)
    return "ok"


@app.route("/admin/flag")
def admin_flag():
    return Response("nothing here\n", mimetype="text/plain")


TESTS = [
    (2, 4),
]


def run_lua_bounded(code: str) -> str:
    """Run the submission in the sandboxed worker process, time-limited."""
    try:
        proc = subprocess.run(
            [sys.executable, str(WORKER)],
            input=code,
            capture_output=True,
            text=True,
            timeout=JUDGE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "Time limit exceeded"
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["unknown error"]
        return "Judge error: %s" % tail[0]
    try:
        return json.loads(proc.stdout or "{}").get("output", "")
    except json.JSONDecodeError:
        return "Judge error"


def judge(code: str):
    rows = []
    verdict = "Accepted"
    last_output = ""
    with _judge_lock:
        for i, (a, b) in enumerate(TESTS, 1):
            _ctx["data1"] = a
            _ctx["data2"] = b
            _ctx["out"] = None

            last_output = run_lua_bounded(code)

            expected = (a + b) / 2
            got = _ctx["out"]
            ok = False
            try:
                ok = got is not None and abs(float(got) - expected) < 1e-6
            except (TypeError, ValueError):
                ok = False

            rows.append({
                "n": i,
                "data1": a,
                "data2": b,
                "expected": expected,
                "got": got,
                "ok": ok,
            })

            if not ok:
                verdict = "Wrong answer on test %d" % i
                break
    return verdict, rows, last_output


SAMPLE = """local d1 = tonumber(fetch("{base}/system/data1"))
local d2 = tonumber(fetch("{base}/system/data2"))
local avg = 67
fetch("{base}/system/out", "POST", tostring(avg))
""".format(base=BASE)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("login") == LOGIN and request.form.get("password") == PASSWORD:
            session["auth"] = True
            return redirect(url_for("index"))
        error = "Неверный логин или пароль"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
def index():
    if not session.get("auth"):
        # Пробы оркестратора бьют в GET / и ждут 2xx: анонимам рендерим
        # страницу входа напрямую (без 302-редиректа на /login).
        if request.method == "POST":
            return redirect(url_for("login"))
        return render_template("login.html", error=None)
    code = SAMPLE
    verdict = None
    rows = []
    last_output = ""
    if request.method == "POST":
        code = request.form.get("code", "")
        verdict, rows, last_output = judge(code)
    return render_template(
        "index.html", code=code, verdict=verdict, rows=rows,
        last_output=last_output, base=BASE
    )


@app.route("/help")
@login_required
def help_page():
    return render_template("help.html", base=BASE)


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host=host, port=PORT, debug=debug)
