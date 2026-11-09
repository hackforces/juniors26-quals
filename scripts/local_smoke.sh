#!/usr/bin/env bash
# Local end-to-end test for one challenge package: compose up with a random
# flag, wait until the image HEALTHCHECK reports healthy, run the package
# solver (solve.py) and assert it recovers exactly that flag, then tear down.
#
#   local_smoke.sh <pkg_dir> [solver args...]
#
# The service runs on the package's default port (unique per repo), so the
# solver's default target works without arguments. For pwntools-based
# solvers point SOLVE_PYTHON at an interpreter that has it.
#
# Examples:
#   scripts/local_smoke.sh challenges/web/the-fortune-shop
#   scripts/local_smoke.sh challenges/web/bonus-club
#   SOLVE_PYTHON=~/venvs/pwn/bin/python scripts/local_smoke.sh challenges/pwn/retro-heap
set -euo pipefail

dir=${1:?usage: local_smoke.sh <pkg_dir> [solver args...]}
shift || true

# Flag prefix is randomized (override via SMOKE_PREFIX=flag) so smokes catch
# any solver/service assumption about the flag format.
prefixes=(InnoCTF flag ctf)
prefix=${SMOKE_PREFIX:-${prefixes[$((RANDOM % ${#prefixes[@]}))]}}
flag="${prefix}{smoke_${RANDOM}_$(date +%s)}"
project="lsmoke_$(basename "$(dirname "$dir")")_$(basename "$dir")"
solver="${SOLVE_PYTHON:-python3}"

cd "$dir"
# CTF_FLAG guard (:? in compose) applies to every compose subcommand
cleanup() { CTF_FLAG=x docker compose -p "$project" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

CTF_FLAG="$flag" docker compose -p "$project" up -d --build >/dev/null

cid() { CTF_FLAG=x docker compose -p "$project" ps -q challenge; }
for _ in $(seq 1 90); do
  [ "$(docker inspect --format '{{.State.Health.Status}}' "$(cid)" 2>/dev/null)" = healthy ] && break
  sleep 2
done
status=$(docker inspect --format '{{.State.Health.Status}}' "$(cid)")
if [ "$status" != healthy ]; then
  echo "FAIL $dir: health=$status after 180s" >&2
  docker logs "$(cid)" >&2 || true
  exit 1
fi

out=$("$solver" solve.py "$@" 2>&1)
echo "$out"
# -i: отдельные задачи восстанавливают флаг только в нижнем регистре
# (blockpost: стена кодирует верхний, флаг сдаётся в нижнем)
if ! grep -qiF "$flag" <<<"$out"; then
  echo "FAIL $dir: solver did not recover the random flag" >&2
  exit 1
fi
echo "PASS $dir"
