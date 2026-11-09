#!/usr/bin/env python3
"""Lua judge worker.

Reads the submission on stdin, runs it inside the lupa sandbox, prints
JSON {"output": ...} on stdout. Two independent containment layers:

- a CPU-time quota (see HOOK_INSTALL): any CPU burn — including
  pcall-wrapped, coroutine-based and C-heavy spin — is hard-stopped at
  ~CPU_LIMIT_SECONDS of process CPU time via os.exit(137);
- the parent's hard wall-clock limit (JUDGE_TIMEOUT) plus this process's
  RLIMIT_AS as the memory backstop for one-shot C-level allocations.

The flag lives in the environment and only ever leaves through the X-Flag
header that py_fetch attaches to outgoing requests.
"""
import json
import os
import resource
import sys
from urllib.parse import unquote

import lupa
from lupa import LuaRuntime
import requests

ALLOWED_PREFIX = "127.0.0.1"
FETCH_TIMEOUT = 5

# CPU quota for submitted Lua. A debug.sethook with mask "l" fires on every
# executed line and checks process CPU time (os.clock, captured as an
# upvalue before the sandbox prologue nils the globals) against
# CPU_LIMIT_SECONDS. Line granularity (not instruction counts — see below)
# is what makes this airtight:
#   - a plain spin trips it on the loop's single line;
#   - a pcall-wrapped spin cannot swallow the hard os.exit(137);
#   - "under the radar" games are impossible: an instruction-count hook
#     fires only at multiples of N, so fresh coroutines that each run
#     N-1 instructions (or loops doing one 10 MB memcpy per instruction)
#     never fire it at all — CPU *time* has no such blind spot, because
#     it is process-wide and survives resumes;
#   - coroutine.create/wrap/resume are replaced with hook-arming wrappers
#     because Lua 5.5 hooks are per-thread and NOT inherited (verified).
# The intended solution costs 21 VM instructions and sub-millisecond CPU,
# so a 2.5 s CPU budget is ~10**4x headroom for anything legitimate.
CPU_LIMIT_SECONDS = 2.5

# Address-space cap for the worker: one-shot C-level allocations (e.g.
# ("x"):rep(2^31) happily mallocs 2 GB and no hook can fire inside a C
# call). RLIMIT_AS makes those fail as Lua "not enough memory" errors
# instead of pressuring the host. Set per-process, so it works
# regardless of deployer-level container limits.
WORKER_AS_LIMIT = 512 * 1024 * 1024


def _apply_rlimit() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_AS, (WORKER_AS_LIMIT, WORKER_AS_LIMIT))
    except (ValueError, OSError):
        pass  # unsupported platform: wall-clock timeout remains the backstop


_session = requests.Session()

FLAG = os.environ.get("CTF_FLAG")


def check_url(url: str) -> bool:
    url = url.strip()
    if ".." in unquote(url):
        return False
    for scheme in ("http://", "https://"):
        if url.startswith(scheme):
            rest = url[len(scheme):]
            return rest.startswith(ALLOWED_PREFIX)
    return False


def py_fetch(url, method="GET", body=None):
    url = str(url)
    if not check_url(url):
        return "ERROR: url must start with http://%s" % ALLOWED_PREFIX
    method = str(method or "GET").upper()
    headers = {"X-Fetch": "1", "X-Flag": FLAG}
    try:
        if method == "POST":
            data = "" if body is None else str(body)
            resp = _session.post(url, data=data, timeout=FETCH_TIMEOUT, headers=headers)
        else:
            resp = _session.get(url, timeout=FETCH_TIMEOUT, headers=headers)
        return resp.text
    except Exception as exc:
        return "ERROR: %s" % exc


def filter_attribute_access(obj, attr_name, is_setting):
    if isinstance(attr_name, str):
        if not attr_name.startswith('_'):
            return attr_name
    raise AttributeError('access denied')


SANDBOX_PROLOGUE = """
io = nil
os = nil
dofile = nil
loadfile = nil
load = nil
loadstring = nil
package = nil
require = nil
debug = nil
getfenv = nil
setfenv = nil
newproxy = nil
collectgarbage = nil
python = nil
"""

# Installed BEFORE the sandbox prologue, while debug/os/io still exist: the
# hook keeps os.exit, os.clock and io.stderr as upvalues, so nil-ing the
# globals afterwards cannot disarm it. Every thread a submission can start
# (main, coroutine.create, coroutine.wrap, re-armed on every resume) runs
# the same check against the same process-CPU baseline.
HOOK_INSTALL = """
local sethook, os_exit, ctime = debug.sethook, os.exit, os.clock
local stderr = io.stderr
local t0 = ctime()
local function quota_hook()
    if ctime() - t0 > {cpu_limit} then
        stderr:write("cpu budget exceeded (hard stop)\\n")
        os_exit(137)
    end
end
sethook(quota_hook, "l")

local rawcreate, rawresume = coroutine.create, coroutine.resume
local function arm(co)
    sethook(co, quota_hook, "l")
end
coroutine.create = function(f)
    local co = rawcreate(f)
    arm(co)
    return co
end
coroutine.resume = function(co, ...)
    arm(co)
    return rawresume(co, ...)
end
coroutine.wrap = function(f)
    local co = coroutine.create(f)
    return function(...)
        local r = table.pack(coroutine.resume(co, ...))
        if r[1] then
            return table.unpack(r, 2, r.n)
        else
            error(r[2], 0)
        end
    end
end
""".format(cpu_limit=CPU_LIMIT_SECONDS)


def run_lua(code: str) -> str:
    lua = LuaRuntime(
        unpack_returned_tuples=True,
        register_eval=False,
        register_builtins=False,
        attribute_filter=filter_attribute_access,
    )

    output_chunks = []

    def lua_print(*args):
        output_chunks.append("\t".join(str(a) for a in args))

    lua.globals().fetch = py_fetch
    lua.globals().print = lua_print

    lua.execute(HOOK_INSTALL)
    lua.execute(SANDBOX_PROLOGUE)

    try:
        result = lua.execute(code)
        if result is not None:
            output_chunks.append("=> %s" % result)
    except lupa.LuaError as exc:
        output_chunks.append("Lua error: %s" % exc)
    except Exception as exc:
        output_chunks.append("Error: %s" % exc)

    return "\n".join(output_chunks)


def main() -> None:
    _apply_rlimit()
    code = sys.stdin.read()
    try:
        output = run_lua(code)
    except Exception as exc:  # never crash without a JSON answer
        output = "Judge error: %s" % exc
    json.dump({"output": output}, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
