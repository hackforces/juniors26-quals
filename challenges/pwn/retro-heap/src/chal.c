#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define MAX_NOTES 16
#define MIN_SIZE 0x18
#define MAX_SIZE 0x500

struct note {
    char *data;
    size_t size;
    int used;
    int pad;
};

static struct note *notes;

static void out(const char *s)
{
    write(1, s, strlen(s));
}

static void read_exact(char *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(0, buf + got, n - got);
        if (r <= 0)
            _exit(0);
        got += (size_t)r;
    }
}

static long read_num(const char *prompt)
{
    char line[32];
    size_t n = 0;
    out(prompt);
    for (;;) {
        char c;
        ssize_t r = read(0, &c, 1);
        if (r <= 0)
            _exit(0);
        if (c == '\n')
            break;
        if (n < sizeof(line) - 1)
            line[n++] = c;
    }
    line[n] = '\0';
    return strtol(line, NULL, 10);
}

static int get_idx(void)
{
    long i = read_num("index: ");
    if (i < 0 || i >= MAX_NOTES) {
        out("[-] bad index\n");
        return -1;
    }
    return (int)i;
}

static void menu(void)
{
    out("\n=== RETRO HEAP ===\n"
        " 1) Add\n"
        " 2) View\n"
        " 3) Edit\n"
        " 4) Delete\n"
        " 5) Exit\n"
        "> ");
}

static void do_add(void)
{
    int i = get_idx();
    if (i < 0)
        return;
    if (notes[i].used) {
        out("[-] slot busy\n");
        return;
    }
    long sz = read_num("size: ");
    if (sz < MIN_SIZE || sz > MAX_SIZE) {
        out("[-] bad size\n");
        return;
    }
    char *p = malloc((size_t)sz);
    if (!p) {
        out("[-] oom\n");
        return;
    }
    notes[i].data = p;
    notes[i].size = (size_t)sz;
    notes[i].used = 1;
    out("data: ");
    read_exact(p, (size_t)sz);
    out("[+] added\n");
}

static void do_view(void)
{
    int i = get_idx();
    if (i < 0)
        return;
    write(1, notes[i].data, notes[i].size);
    out("\n[+] done\n");
}

static void do_edit(void)
{
    int i = get_idx();
    if (i < 0)
        return;
    out("data: ");
    read_exact(notes[i].data, notes[i].size);
    out("[+] edited\n");
}

static void do_del(void)
{
    int i = get_idx();
    if (i < 0)
        return;
    if (!notes[i].used) {
        out("[-] empty\n");
        return;
    }
    free(notes[i].data);
    notes[i].used = 0;
    out("[+] deleted\n");
}

int main(void)
{
    notes = malloc(MAX_NOTES * sizeof(struct note));
    if (!notes)
        return 1;
    memset(notes, 0, MAX_NOTES * sizeof(struct note));
    for (;;) {
        menu();
        long c = read_num("");
        switch (c) {
        case 1:
            do_add();
            break;
        case 2:
            do_view();
            break;
        case 3:
            do_edit();
            break;
        case 4:
            do_del();
            break;
        case 5:
            out("bye\n");
            return 0;
        default:
            out("[-] ?\n");
            break;
        }
    }
}
