/*
 * mini-vm challenge binary - a forward oracle for a custom 128-bit
 * permutation P.
 *
 * Reads one 16-byte block as 32 hex chars (argv[1] or stdin), prints P(block)
 * as 32 hex chars. There is no flag and no secret here: the whole point is to
 * reverse P and build an inverter. P is computed by a small stack VM whose
 * real program is (a) rolling-XOR encrypted, (b) hidden behind a self-modifying
 * UNPACK layer, and (c) encoded with a per-build-permuted opcode table. Any
 * patch to the image silently corrupts the S-box lookups, so the output is
 * wrong without any visible error.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "sha256.h"
#include "vm_blob.h"

#define STACK_MAX 64
#define INSTR_BUDGET 20000000ULL
#define BLOCK 16

/* canonical opcodes (must match gen/gen_vm.py; on-wire bytes are permuted) */
enum {
    OP_NOP = 0, OP_PUSH, OP_POP, OP_DUP, OP_SWAP,
    OP_LOADIN, OP_LDB, OP_STB,
    OP_ADD, OP_SUB, OP_XOR, OP_AND, OP_SHL, OP_SHR, OP_EQ,
    OP_UNPACK, OP_PRINT, OP_EXIT
};

typedef struct {
    uint8_t       *code;
    uint64_t       clen;
    uint8_t       *mem;
    uint64_t       memlen;
    const uint8_t *in;
    uint64_t       inlen;
    uint64_t       sp;
    uint64_t       stk[STACK_MAX];
    const uint8_t *opdec;      /* on-wire byte -> canonical opcode (0xFF bad) */
    int            broken;
    int            fault;
    int            exit_code;
} vm_t;

static uint64_t mix64(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void push(vm_t *v, uint64_t x)
{
    if (v->sp >= STACK_MAX) { v->fault = 1; return; }
    v->stk[v->sp++] = x;
}

static uint64_t pop(vm_t *v)
{
    if (v->sp == 0) { v->fault = 1; return 0; }
    return v->stk[--v->sp];
}

static uint8_t fetch8(vm_t *v, uint64_t *pc)
{
    if (*pc >= v->clen) { v->fault = 1; return 0; }
    return v->code[(*pc)++];
}

static uint16_t fetch16(vm_t *v, uint64_t *pc)
{
    uint16_t x = fetch8(v, pc);
    x |= (uint16_t)fetch8(v, pc) << 8;
    return x;
}

static uint64_t fetch64(vm_t *v, uint64_t *pc)
{
    uint64_t x = 0;
    for (int i = 0; i < 8; i++)
        x |= (uint64_t)fetch8(v, pc) << (8 * i);
    return x;
}

static int vm_run(vm_t *v)
{
    uint64_t pc = 0;
    uint64_t budget = INSTR_BUDGET;

    while (!v->fault && pc < v->clen) {
        if (budget-- == 0) { v->fault = 1; break; }

        uint8_t raw = fetch8(v, &pc);
        uint8_t op = v->opdec[raw];
        if (op == 0xFF) { v->fault = 1; break; }

        switch (op) {
        case OP_NOP:
            break;
        case OP_PUSH:
            push(v, fetch64(v, &pc));
            break;
        case OP_POP:
            (void)pop(v);
            break;
        case OP_DUP: {
            uint64_t x = pop(v);
            push(v, x); push(v, x);
            break;
        }
        case OP_SWAP: {
            uint64_t a = pop(v), b = pop(v);
            push(v, a); push(v, b);
            break;
        }
        case OP_LOADIN: {
            uint8_t idx = fetch8(v, &pc);
            push(v, idx < v->inlen ? v->in[idx] : 0);
            break;
        }
        case OP_LDB: {
            uint64_t a = pop(v);
            if (a >= v->memlen) { v->fault = 1; break; }
            uint8_t val = v->mem[a];
            /* silent retaliation: tampering flips the S-box lookups */
            if (v->broken && a >= SBOX_OFF && a < SBOX_OFF + 256)
                val ^= 1;
            push(v, val);
            break;
        }
        case OP_STB: {
            uint64_t a = pop(v), val = pop(v);
            if (a >= v->memlen) { v->fault = 1; break; }
            v->mem[a] = (uint8_t)val;
            break;
        }
        case OP_ADD: { uint64_t b = pop(v), a = pop(v); push(v, a + b); break; }
        case OP_SUB: { uint64_t b = pop(v), a = pop(v); push(v, a - b); break; }
        case OP_XOR: { uint64_t b = pop(v), a = pop(v); push(v, a ^ b); break; }
        case OP_AND: { uint64_t b = pop(v), a = pop(v); push(v, a & b); break; }
        case OP_SHL: { uint64_t b = pop(v), a = pop(v); push(v, b < 64 ? a << b : 0); break; }
        case OP_SHR: { uint64_t b = pop(v), a = pop(v); push(v, b < 64 ? a >> b : 0); break; }
        case OP_EQ:  { uint64_t b = pop(v), a = pop(v); push(v, a == b ? 1 : 0); break; }
        case OP_UNPACK: {
            uint16_t pk = fetch16(v, &pc);
            uint16_t co = fetch16(v, &pc);
            uint16_t ln = fetch16(v, &pc);
            if ((uint64_t)pk + ln > v->memlen ||
                (uint64_t)co + ln > v->clen) { v->fault = 1; break; }
            uint64_t st = UNPACK_SEED;
            for (uint32_t i = 0; i < ln; i++) {
                if ((i & 7) == 0)
                    st = mix64(st);
                uint8_t ks = (uint8_t)(st >> (8 * (i & 7)));
                v->code[co + i] = (uint8_t)(v->mem[pk + i] ^ ks);
            }
            break;
        }
        case OP_PRINT: {
            uint16_t o = fetch16(v, &pc);
            uint16_t l = fetch16(v, &pc);
            if ((uint64_t)o + l > v->memlen) { v->fault = 1; break; }
            fwrite(v->mem + o, 1, l, stdout);
            fflush(stdout);
            break;
        }
        case OP_EXIT: {
            uint8_t code = fetch8(v, &pc);
            v->exit_code = code;
            return code;
        }
        default:
            v->fault = 1;
            break;
        }
    }
    if (v->fault)
        return 4;
    return v->exit_code;
}

/* parse exactly 32 hex chars into 16 bytes; return 0 on success */
static int parse_block(const char *s, uint8_t out[BLOCK])
{
    int n = 0;
    while (s[n] && s[n] != '\n' && s[n] != '\r')
        n++;
    if (n != 2 * BLOCK)
        return -1;
    for (int i = 0; i < BLOCK; i++) {
        int hi = s[2 * i], lo = s[2 * i + 1];
        if (!isxdigit(hi) || !isxdigit(lo))
            return -1;
        char b[3] = { (char)hi, (char)lo, 0 };
        out[i] = (uint8_t)strtol(b, NULL, 16);
    }
    return 0;
}

static void print_x(const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        putchar(s[i] ^ 0x5A);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    static uint8_t code[VM_CODE_SIZE];
    static uint8_t mem[VM_MEM_SIZE];
    static uint8_t opdec[256];
    static char line[256];
    uint8_t in[BLOCK];
    uint8_t dig[32];

    const char *src;
    if (argc > 1) {
        src = argv[1];
    } else {
        if (!fgets(line, sizeof(line), stdin)) {
            print_x(xs_err, sizeof(xs_err));
            return 1;
        }
        src = line;
    }
    if (parse_block(src, in) != 0) {
        print_x(xs_err, sizeof(xs_err));
        return 1;
    }

    /* layer 1: rolling-XOR decrypt the code image */
    memcpy(code, vm_code_enc, VM_CODE_SIZE);
    uint8_t k = 0x5A;
    for (size_t i = 0; i < VM_CODE_SIZE; i++) {
        uint8_t c = code[i] ^ k;
        code[i] = c;
        k = (uint8_t)(k * 31 + 0x9E);
    }
    memcpy(mem, vm_mem_init, VM_MEM_SIZE);
    for (int i = 0; i < 256; i++)
        opdec[i] = vm_op_dec[i] ^ 0x5A;

    /* anti-tamper: digest of the decrypted code image + data memory.
     * Read the stored digest through a volatile pointer so the comparison is
     * a real memory load (not folded to immediates at -O2) and a patch to the
     * image actually trips it. */
    sha256_ctx sc;
    sha256_init(&sc);
    sha256_update(&sc, code, VM_CODE_SIZE);
    sha256_update(&sc, mem, VM_MEM_SIZE);
    sha256_final(&sc, dig);
    const volatile uint8_t *stored = vm_code_sha;
    int tamper = 0;
    for (int i = 0; i < 32; i++)
        tamper |= dig[i] ^ stored[i];

    vm_t vm;
    memset(&vm, 0, sizeof(vm));
    vm.code = code;
    vm.clen = VM_CODE_SIZE;
    vm.mem = mem;
    vm.memlen = VM_MEM_SIZE;
    vm.in = in;
    vm.inlen = BLOCK;
    vm.opdec = opdec;
    vm.broken = (tamper != 0);

    int rc = vm_run(&vm);
    if (rc == 0)
        return 0;
    print_x(xs_err, sizeof(xs_err));
    return 1;
}
