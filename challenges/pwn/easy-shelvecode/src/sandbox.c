#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LISTEN_PORT 6767
#ifndef FLAG_PATH
#define FLAG_PATH "/run/case/flag"
#endif
#define CODE_SIZE 0x1005u
#define FLAG_SIZE 64u
#define MAX_PAYLOAD 64u
#define TIMEOUT_MS 150u

typedef struct {
    unsigned char code[CODE_SIZE];
    char flag[FLAG_SIZE];
} sandbox_memory_t;

static sandbox_memory_t arena __attribute__((aligned(0x1000)));

_Static_assert(offsetof(sandbox_memory_t, flag) == CODE_SIZE, "layout");

static int write_all(int fd, const void *data, size_t size) {
    const unsigned char *cursor = data;
    while (size != 0) {
        ssize_t written = write(fd, cursor, size);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        cursor += written;
        size -= (size_t)written;
    }
    return 0;
}

static int read_line(int fd, char *buffer, size_t capacity) {
    size_t used = 0;
    while (used + 1 < capacity) {
        char byte;
        ssize_t count = read(fd, &byte, 1);
        if (count == 0) {
            return -1;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (byte == '\n') {
            break;
        }
        if (byte != '\r') {
            buffer[used++] = byte;
        }
    }
    buffer[used] = '\0';
    return used == capacity - 1 ? -1 : 0;
}

static int hex_value(char byte) {
    if (byte >= '0' && byte <= '9') {
        return byte - '0';
    }
    if (byte >= 'a' && byte <= 'f') {
        return byte - 'a' + 10;
    }
    if (byte >= 'A' && byte <= 'F') {
        return byte - 'A' + 10;
    }
    return -1;
}

static int parse_payload(int fd, unsigned char *payload, size_t *payload_size) {
    char line[32];
    if (write_all(fd, "Shelvecode shellcode monitor\nlength> ", sizeof("Shelvecode shellcode monitor\nlength> ") - 1) < 0) {
        return -1;
    }
    if (read_line(fd, line, sizeof(line)) < 0) {
        return -1;
    }
    char *end = NULL;
    unsigned long requested = strtoul(line, &end, 10);
    if (end == line || *end != '\0' || requested == 0 || requested > MAX_PAYLOAD) {
        (void)write_all(fd, "REJECT\n", 7);
        return -1;
    }

    if (write_all(fd, "hex> ", 5) < 0) {
        return -1;
    }
    char encoded[MAX_PAYLOAD * 2 + 1];
    if (read_line(fd, encoded, sizeof(encoded)) < 0 ||
        strlen(encoded) != requested * 2) {
        (void)write_all(fd, "REJECT\n", 7);
        return -1;
    }

    for (size_t i = 0; i < requested; ++i) {
        int high = hex_value(encoded[i * 2]);
        int low = hex_value(encoded[i * 2 + 1]);
        if (high < 0 || low < 0) {
            (void)write_all(fd, "REJECT\n", 7);
            return -1;
        }
        unsigned char value = (unsigned char)((high << 4) | low);
        if ((value & 1u) != 0) {
            (void)write_all(fd, "REJECT\n", 7);
            return -1;
        }
        payload[i] = value;
    }
    *payload_size = requested;
    return 0;
}

__attribute__((naked, noinline, used))
static void execute_shellcode(void) {
    __asm__ volatile(
        "lea arena(%rip), %rax\n"
        "push %rax\n"
        "xor %rax, %rax\n"
        "xor %rbx, %rbx\n"
        "xor %rcx, %rcx\n"
        "xor %rdx, %rdx\n"
        "xor %rsi, %rsi\n"
        "xor %rdi, %rdi\n"
        "xor %rbp, %rbp\n"
        "xor %r8, %r8\n"
        "xor %r9, %r9\n"
        "xor %r10, %r10\n"
        "xor %r11, %r11\n"
        "xor %r12, %r12\n"
        "xor %r13, %r13\n"
        "xor %r14, %r14\n"
        "xor %r15, %r15\n"
        "ret\n"
    );
}

static uint64_t elapsed_ms(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t seconds = (int64_t)now.tv_sec - (int64_t)start->tv_sec;
    int64_t nanos = (int64_t)now.tv_nsec - (int64_t)start->tv_nsec;
    int64_t milliseconds = seconds * 1000 + nanos / 1000000;
    return milliseconds > 0 ? (uint64_t)milliseconds : 0;
}

static const char *wait_for_child(pid_t child) {
    int status = 0;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            break;
        }
        if (result < 0) {
            return "WAITERR\n";
        }
        if (elapsed_ms(&start) >= TIMEOUT_MS) {
            (void)kill(child, SIGALRM);
            (void)waitpid(child, &status, 0);
            return "SIGALRM\n";
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }

    if (WIFEXITED(status)) {
        return "EXIT\n";
    }
    if (!WIFSIGNALED(status)) {
        return "UNKNOWN\n";
    }
    switch (WTERMSIG(status)) {
    case SIGSEGV:
        return "SIGSEGV\n";
    case SIGFPE:
        return "SIGFPE\n";
    case SIGILL:
        return "SIGILL\n";
    case SIGALRM:
        return "SIGALRM\n";
    default:
        return "SIGNAL\n";
    }
}

static void handle_client(int client) {
    unsigned char payload[MAX_PAYLOAD];
    size_t payload_size = 0;
    if (parse_payload(client, payload, &payload_size) < 0) {
        close(client);
        return;
    }

    memset(arena.code, 0, sizeof(arena.code));
    memcpy(arena.code, payload, payload_size);

    pid_t child = fork();
    if (child < 0) {
        (void)write_all(client, "FORKERR\n", 8);
        close(client);
        return;
    }
    if (child == 0) {
        close(client);
        execute_shellcode();
        _exit(0);
    }

    const char *status = wait_for_child(child);
    (void)write_all(client, status, strlen(status));
    close(client);
}

static int load_flag(void) {
    int fd = open(FLAG_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ssize_t count = read(fd, arena.flag, sizeof(arena.flag) - 1);
    close(fd);
    if (count <= 0) {
        return -1;
    }
    arena.flag[count] = '\0';
    char *newline = strpbrk(arena.flag, "\r\n");
    if (newline != NULL) {
        *newline = '\0';
    }
    return 0;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    if (load_flag() < 0) {
        return 1;
    }

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)arena.code & ~(page_size - 1u);
    uintptr_t end = (uintptr_t)&arena + sizeof(arena);
    size_t length = (size_t)(end - start);
    length = (length + page_size - 1u) & ~(page_size - 1u);
    if (mprotect((void *)start, length, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        return 1;
    }

    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        return 1;
    }
    int reuse = 1;
    (void)setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(LISTEN_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(server, 32) < 0) {
        close(server);
        return 1;
    }

    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        handle_client(client);
    }

    close(server);
    return 0;
}
