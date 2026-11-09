#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define SOCKET_PATH "/run/fastcalc/vm.sock"
#define FLAG_PATH "/run/case/flag"

#define REQUEST_MAGIC 0x31564d52u 
#define RESPONSE_MAGIC 0x31564d53u 
#define IMAGE_MAGIC "FWM2"
#define IMAGE_VERSION 2u
#define IMAGE_HEADER_SIZE 36u
#define IMAGE_FLAGS 1u
#define MAX_IMAGE 4096u
#define MAX_CODE 1024u
#define MAX_CONST 512u
#define MAX_OUTPUT 512u
#define MAX_STEPS 4096u


typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t image_len;
    int64_t a;
    int64_t b;
    uint8_t operation;
    uint8_t reserved[7];
} request_header_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t status;
    uint32_t output_len;
} response_header_t;

typedef struct __attribute__((packed)) {
    char magic[4];
    uint16_t version;
    uint16_t header_size;
    uint32_t code_len;
    uint32_t const_len;
    uint32_t entry;
    uint32_t flags;
    uint32_t crc32;
    uint32_t key;
    uint32_t reserved;
} image_header_t;

struct vm;
typedef void (*halt_callback_t)(struct vm *, uint64_t);


typedef struct vm {
    const uint8_t *code;       
    uint64_t code_len;
    uint64_t pc;
    uint64_t steps;
    uint64_t regs[8];          
    uint64_t scratch0;         
    uint64_t scratch1;         
    uint64_t halt_slot;        
    uint64_t secret_slot;      
    uint64_t cookie;
    char output[MAX_OUTPUT];
    uint64_t output_len;
    int error;
    int probe_seen;
} vm_t;

static uint64_t process_cookie;
static int probe_armed;

static void finish_result(vm_t *vm, uint64_t value);
static void reveal_flag(vm_t *vm, uint64_t ignored);

static void fail_vm(vm_t *vm, const char *message) {
    vm->error = 1;
    if (!message) {
        message = "vm error";
    }
    size_t n = strlen(message);
    if (n >= MAX_OUTPUT) {
        n = MAX_OUTPUT - 1;
    }
    memcpy(vm->output, message, n);
    vm->output[n] = '\0';
    vm->output_len = n;
}

static void append_bytes(vm_t *vm, const char *data, size_t length) {
    if (vm->output_len >= MAX_OUTPUT - 1 || length == 0) {
        return;
    }
    size_t room = (MAX_OUTPUT - 1) - (size_t)vm->output_len;
    if (length > room) {
        length = room;
    }
    memcpy(vm->output + vm->output_len, data, length);
    vm->output_len += length;
    vm->output[vm->output_len] = '\0';
}

static void append_number(vm_t *vm, uint64_t value) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%" PRId64, (int64_t)value);
    if (n > 0) {
        append_bytes(vm, buf, (size_t)n);
    }
}

static void append_hex(vm_t *vm, uint64_t value) {
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "0x%016" PRIx64, value);
    if (n > 0) {
        append_bytes(vm, buf, (size_t)n);
    }
}

static void finish_result(vm_t *vm, uint64_t value) {
    
    if (vm->output_len == 0) {
        append_number(vm, value);
    }
}

static void reveal_flag(vm_t *vm, uint64_t ignored) {
    (void)ignored;
    int fd = open(FLAG_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fail_vm(vm, "flag unavailable");
        return;
    }

    char flag[MAX_OUTPUT];
    ssize_t n = read(fd, flag, sizeof(flag) - 1);
    close(fd);
    if (n <= 0) {
        fail_vm(vm, "empty flag");
        return;
    }
    while (n > 0 && (flag[n - 1] == '\n' || flag[n - 1] == '\r')) {
        --n;
    }
    flag[n] = '\0';
    vm->output_len = 0;
    append_bytes(vm, flag, (size_t)n);
}

static uint8_t image_mask(uint32_t key, uint32_t index) {
    uint8_t lane = (uint8_t)((key >> ((index & 3u) * 8u)) & 0xffu);
    return (uint8_t)(lane + index * 0x3du + (index / 4u) * 0x17u);
}

static uint32_t crc32_bytes(const uint8_t *data, size_t length) {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1u) ^ (0xedb88320u & mask);
        }
    }
    return ~crc;
}

static int read_u8(vm_t *vm, uint8_t *value) {
    if (vm->pc >= vm->code_len) {
        fail_vm(vm, "truncated instruction");
        return -1;
    }
    *value = vm->code[vm->pc++];
    return 0;
}

static int read_i8(vm_t *vm, int8_t *value) {
    uint8_t raw;
    if (read_u8(vm, &raw) < 0) {
        return -1;
    }
    *value = (int8_t)raw;
    return 0;
}

static int read_i64(vm_t *vm, int64_t *value) {
    if (vm->pc + sizeof(*value) > vm->code_len) {
        fail_vm(vm, "truncated immediate");
        return -1;
    }
    memcpy(value, vm->code + vm->pc, sizeof(*value));
    vm->pc += sizeof(*value);
    return 0;
}

static int get_slot(vm_t *vm, uint8_t index, uint64_t *value) {
    
    if (index >= 12) {
        fail_vm(vm, "bad slot");
        return -1;
    }
    memcpy(value, ((const uint8_t *)vm->regs) + (size_t)index * sizeof(uint64_t),
           sizeof(*value));
    if (index == 11) {
        vm->probe_seen = 1;
    }
    return 0;
}

static int put_slot(vm_t *vm, uint8_t index, uint64_t value) {
    
    if (index >= 12) {
        fail_vm(vm, "bad slot");
        return -1;
    }
    if (index == 10 && !probe_armed) {
        fail_vm(vm, "maintenance probe required");
        return -1;
    }
    memcpy(((uint8_t *)vm->regs) + (size_t)index * sizeof(uint64_t), &value,
           sizeof(value));
    return 0;
}

static int jump_relative(vm_t *vm, int8_t relative) {
    int64_t next = (int64_t)vm->pc + (int64_t)relative;
    if (next < 0 || (uint64_t)next >= vm->code_len) {
        fail_vm(vm, "jump outside image");
        return -1;
    }
    vm->pc = (uint64_t)next;
    return 0;
}

static int run_vm(vm_t *vm) {
    int halted = 0;
    while (!vm->error && !halted) {
        if (vm->pc >= vm->code_len) {
            fail_vm(vm, "fell off image");
            break;
        }
        if (++vm->steps > MAX_STEPS) {
            fail_vm(vm, "step budget exceeded");
            break;
        }

        uint8_t op;
        if (read_u8(vm, &op) < 0) {
            break;
        }

        uint8_t dst, left, right, slot;
        int64_t immediate;
        int8_t relative;
        uint64_t lhs, rhs;

        switch (op) {
        case 0x00: 
            break;
        case 0x01: 
            if (read_u8(vm, &dst) < 0 || read_i64(vm, &immediate) < 0 ||
                dst >= 8) {
                if (!vm->error) fail_vm(vm, "bad MOVI");
                break;
            }
            vm->regs[dst] = (uint64_t)immediate;
            break;
        case 0x02: 
            if (read_u8(vm, &dst) < 0 || read_u8(vm, &left) < 0 ||
                dst >= 8 || left >= 8) {
                if (!vm->error) fail_vm(vm, "bad MOV");
                break;
            }
            vm->regs[dst] = vm->regs[left];
            break;
        case 0x03: 
        case 0x04: 
        case 0x05: 
        case 0x06: 
        case 0x07: 
        case 0x08: 
        case 0x10: 
        case 0x11: 
        case 0x12: 
        case 0x13: 
            if (read_u8(vm, &dst) < 0 || read_u8(vm, &left) < 0 ||
                read_u8(vm, &right) < 0 || dst >= 8 || left >= 8 || right >= 8) {
                if (!vm->error) fail_vm(vm, "bad arithmetic instruction");
                break;
            }
            lhs = vm->regs[left];
            rhs = vm->regs[right];
            switch (op) {
            case 0x03: vm->regs[dst] = lhs + rhs; break;
            case 0x04: vm->regs[dst] = lhs - rhs; break;
            case 0x05: vm->regs[dst] = lhs * rhs; break;
            case 0x06:
                if (rhs == 0) fail_vm(vm, "division by zero");
                else vm->regs[dst] = (uint64_t)((int64_t)lhs / (int64_t)rhs);
                break;
            case 0x07:
                if (rhs == 0) fail_vm(vm, "division by zero");
                else vm->regs[dst] = (uint64_t)((int64_t)lhs % (int64_t)rhs);
                break;
            case 0x08: vm->regs[dst] = (lhs == rhs); break;
            case 0x10: vm->regs[dst] = lhs ^ rhs; break;
            case 0x11: vm->regs[dst] = lhs & rhs; break;
            case 0x12: vm->regs[dst] = lhs << (rhs & 63u); break;
            case 0x13: vm->regs[dst] = lhs | rhs; break;
            default: fail_vm(vm, "bad arithmetic opcode"); break;
            }
            break;
        case 0x09: 
            if (read_u8(vm, &left) < 0 || read_i8(vm, &relative) < 0 ||
                left >= 8) {
                if (!vm->error) fail_vm(vm, "bad JNZ");
                break;
            }
            if (vm->regs[left] != 0) {
                (void)jump_relative(vm, relative);
            }
            break;
        case 0x0a: 
            if (read_i8(vm, &relative) < 0) {
                break;
            }
            (void)jump_relative(vm, relative);
            break;
        case 0x0b: 
            if (read_u8(vm, &left) < 0 || left >= 8) {
                if (!vm->error) fail_vm(vm, "bad OUT");
                break;
            }
            append_number(vm, vm->regs[left]);
            break;
        case 0x0c: 
            if (read_u8(vm, &left) < 0 || left >= 8) {
                if (!vm->error) fail_vm(vm, "bad OUTHEX");
                break;
            }
            append_hex(vm, vm->regs[left]);
            break;
        case 0x0d: 
            if (read_u8(vm, &dst) < 0 || read_u8(vm, &slot) < 0 || dst >= 8) {
                if (!vm->error) fail_vm(vm, "bad PICK");
                break;
            }
            if (get_slot(vm, slot, &vm->regs[dst]) < 0) {
                break;
            }
            break;
        case 0x0e: 
            if (read_u8(vm, &slot) < 0 || read_u8(vm, &left) < 0 || left >= 8) {
                if (!vm->error) fail_vm(vm, "bad PUT");
                break;
            }
            (void)put_slot(vm, slot, vm->regs[left]);
            break;
        case 0x0f: 
            if (read_u8(vm, &left) < 0 || left >= 8) {
                if (!vm->error) fail_vm(vm, "bad HALT");
                break;
            } else {
                halt_callback_t callback =
                    (halt_callback_t)(uintptr_t)(vm->halt_slot ^ vm->cookie);
                if (!callback) {
                    fail_vm(vm, "null callback");
                } else {
                    callback(vm, vm->regs[left]);
                    halted = 1;
                }
            }
            break;
        default:
            fail_vm(vm, "unknown opcode");
            break;
        }
    }

    if (vm->probe_seen && !vm->error) {
        probe_armed = 1;
    }
    return vm->error ? -1 : (halted ? 0 : -1);
}

static int parse_image(const uint8_t *image, size_t image_len,
                       uint8_t **decoded_code, uint32_t *code_len,
                       uint32_t *entry) {
    if (image_len < sizeof(image_header_t) || image_len > MAX_IMAGE) {
        return -1;
    }
    image_header_t header;
    memcpy(&header, image, sizeof(header));
    if (memcmp(header.magic, IMAGE_MAGIC, 4) != 0 ||
        header.version != IMAGE_VERSION || header.header_size != IMAGE_HEADER_SIZE ||
        header.flags != IMAGE_FLAGS || header.reserved != 0 ||
        header.code_len == 0 || header.code_len > MAX_CODE ||
        header.const_len > MAX_CONST || header.entry >= header.code_len ||
        (size_t)header.header_size + header.code_len + header.const_len != image_len) {
        return -1;
    }

    size_t payload_len = (size_t)header.code_len + header.const_len;
    uint8_t *plain = malloc(payload_len);
    if (!plain) {
        return -1;
    }
    for (size_t i = 0; i < payload_len; ++i) {
        plain[i] = image[header.header_size + i] ^ image_mask(header.key, (uint32_t)i);
    }
    if (crc32_bytes(plain, payload_len) != header.crc32) {
        free(plain);
        return -1;
    }

    *decoded_code = plain;
    *code_len = header.code_len;
    *entry = header.entry;
    return 0;
}

static int process_request(const uint8_t *image, size_t image_len,
                           int64_t a, int64_t b, uint8_t operation,
                           char *output, size_t *output_len) {
    uint8_t *decoded = NULL;
    uint32_t code_len = 0;
    uint32_t entry = 0;
    if (parse_image(image, image_len, &decoded, &code_len, &entry) < 0) {
        const char *message = "invalid firmware";
        memcpy(output, message, strlen(message));
        *output_len = strlen(message);
        return 2;
    }

    vm_t vm;
    memset(&vm, 0, sizeof(vm));
    vm.code = decoded;
    vm.code_len = code_len;
    vm.pc = entry;
    vm.cookie = process_cookie;
    vm.regs[0] = (uint64_t)a;
    vm.regs[1] = (uint64_t)b;
    vm.regs[2] = operation;
    vm.halt_slot = (uint64_t)(uintptr_t)finish_result ^ vm.cookie;
    vm.secret_slot = (uint64_t)(uintptr_t)reveal_flag ^ vm.cookie;

    int status = run_vm(&vm);
    if (status < 0) {
        if (vm.output_len == 0) {
            const char *message = "vm rejected firmware";
            append_bytes(&vm, message, strlen(message));
        }
        status = 1;
    }

    size_t length = (size_t)vm.output_len;
    if (length > MAX_OUTPUT) {
        length = MAX_OUTPUT;
    }
    memcpy(output, vm.output, length);
    *output_len = length;
    free(decoded);
    return status;
}

static int read_full(int fd, void *buffer, size_t length) {
    uint8_t *p = buffer;
    while (length > 0) {
        ssize_t n = read(fd, p, length);
        if (n == 0) return -1;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        length -= (size_t)n;
    }
    return 0;
}

static int write_full(int fd, const void *buffer, size_t length) {
    const uint8_t *p = buffer;
    while (length > 0) {
        ssize_t n = write(fd, p, length);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        length -= (size_t)n;
    }
    return 0;
}

static void serve_client(int fd) {
    request_header_t request;
    if (read_full(fd, &request, sizeof(request)) < 0 ||
        request.magic != REQUEST_MAGIC || request.image_len == 0 ||
        request.image_len > MAX_IMAGE) {
        close(fd);
        return;
    }

    uint8_t *image = malloc(request.image_len);
    if (!image || read_full(fd, image, request.image_len) < 0) {
        free(image);
        close(fd);
        return;
    }

    char output[MAX_OUTPUT];
    size_t output_len = 0;
    int status = process_request(image, request.image_len, request.a, request.b,
                                 request.operation, output, &output_len);
    free(image);

    response_header_t response = {
        .magic = RESPONSE_MAGIC,
        .status = (uint32_t)status,
        .output_len = (uint32_t)output_len,
    };
    if (write_full(fd, &response, sizeof(response)) == 0) {
        (void)write_full(fd, output, output_len);
    }
    close(fd);
}

static int make_socket(void) {
    (void)unlink(SOCKET_PATH);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(SOCKET_PATH) >= sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    strcpy(address.sun_path, SOCKET_PATH);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        chmod(SOCKET_PATH, 0660) < 0 || listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    if (getrandom(&process_cookie, sizeof(process_cookie), 0) !=
        (ssize_t)sizeof(process_cookie)) {
        process_cookie = (uint64_t)time(NULL) ^ (uint64_t)(uintptr_t)&process_cookie;
    }
    if (process_cookie == 0) {
        process_cookie = 0x636c616374736166ULL;
    }

    int server = make_socket();
    if (server < 0) {
        return 1;
    }

    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }
        serve_client(client);
    }

    close(server);
    (void)unlink(SOCKET_PATH);
    return 0;
}
