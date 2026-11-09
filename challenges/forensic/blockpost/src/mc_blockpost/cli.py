"""CLI: python3 -m mc_blockpost gen|solve."""

import argparse
import sys

from .generator import DEFAULT_FLAG, gen
from .solver import solve


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mc_blockpost",
                                 description="Minecraft block-flag forensics CTF")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="сгенерировать challenge.pcap + latest.log")
    g.add_argument("--flag", default=DEFAULT_FLAG)
    g.add_argument("--out-dir", default="public")
    g.add_argument("--zip", help="дополнительно собрать детерминированный zip-хэндаут")
    g.add_argument("--axis", "--hard-axis", choices=("x", "z"), default="x",
                   help="ось, вдоль которой идёт надпись (z — стена x=const, текст вдоль -z)")
    g.add_argument("--lossy", "--hard-lossy", "--chunked", action="store_true",
                   help="ретрансмиссии и out-of-order в потоке сервера")

    s = sub.add_parser("solve", help="решить/проверить хэндаут")
    s.add_argument("pcap")
    s.add_argument("log")

    args = ap.parse_args(argv)
    if args.cmd == "gen":
        gen(args.flag, args.out_dir, axis=args.axis, lossy=args.lossy, zip_path=args.zip)
    elif args.cmd == "solve":
        solve(args.pcap, args.log)


def gen_main():
    main(["gen", *sys.argv[1:]])


def solve_main():
    main(["solve", *sys.argv[1:]])


if __name__ == "__main__":
    main()
