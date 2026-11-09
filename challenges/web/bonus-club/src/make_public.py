#!/usr/bin/env python3
"""Сборка public/ хендаута: исходники сервиса для участников.

Копирует src/app в public/src (без node_modules) и добавляет README.txt.
Проверяет, что флага в хендауте нет (любого формата prefix{payload}).

Запуск:  python3 src/make_public.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "src" / "app"
PUBLIC = ROOT / "public"



def main() -> None:
    PUBLIC.mkdir(exist_ok=True)

    for p in PUBLIC.iterdir():
        if p.name == ".gitkeep":
            continue
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()

    dst = PUBLIC / "src"
    shutil.copytree(
        APP,
        dst,
        ignore=shutil.ignore_patterns("node_modules", "package-lock.json", "__pycache__"),
    )

    # Паттерн реального флага любого формата: prefix{payload} (не плейсхолдеры).
    grep = subprocess.run(
        ["grep", "-rInEi", r"[a-z0-9_]{2,32}\{[^{}[:space:]]{4,}\}", str(PUBLIC)],
        capture_output=True,
        text=True,
    )
    if grep.stdout.strip():
        print("[!] ОБНАРУЖЕН флаг в public/:")
        print(grep.stdout)
        sys.exit(1)

    print("[+] public/ собран: src/ + README.txt (флага в хендауте нет)")


if __name__ == "__main__":
    main()
