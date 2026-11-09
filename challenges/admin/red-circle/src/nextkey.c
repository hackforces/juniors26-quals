#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * nextkey — setuid-root helper of The Red Circle.
 * Prints the level secret the caller's REAL uid has earned:
 *   uid 1001..1004 -> password of level(uid-1000+1), i.e. the next envelope;
 *   uid 1005       -> the runtime flag.
 * The secrets live in /run/case (0400, root-owned) and are written by the
 * entrypoint from the flag env; the helper only reads and prints, it never
 * executes anything.
 */

static int read_line(const char *path, char *buf, size_t size)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "nextkey: не могу открыть %s\n", path);
        return 1;
    }
    if (!fgets(buf, (int)size, f)) {
        fclose(f);
        fprintf(stderr, "nextkey: секрет пуст\n");
        return 1;
    }
    fclose(f);
    buf[strcspn(buf, "\r\n")] = '\0';
    return 0;
}

int main(void)
{
    uid_t uid = getuid();
    char path[64];
    char secret[256];

    if (uid >= 1001 && uid <= 1004) {
        unsigned level = uid - 1000;      /* 1..4  */
        unsigned next = level + 1;        /* 2..5  */
        snprintf(path, sizeof path, "/run/case/level%u.key", next);
        if (read_line(path, secret, sizeof secret))
            return 1;
        printf("\n=== КОНВЕРТ %u ИЗ 5 ВСКРЫТ ===\n", level);
        printf("Ключ к следующему конверту — пароль пользователя level%u.\n", next);
        printf("KEY: %s\n", secret);
        printf("Вход дальше: ssh level%u@<тот же хост и порт>\n\n", next);
        return 0;
    }

    if (uid == 1005) {
        if (read_line("/run/case/flag", secret, sizeof secret))
            return 1;
        printf("\n=== ПЯТЫЙ КОНВЕРТ ВСКРЫТ — ЦЕПОЧКА ЗАВЕРШЕНА ===\n");
        printf("Улика из последнего конверта:\n");
        printf("FLAG: %s\n\n", secret);
        return 0;
    }

    fprintf(stderr, "nextkey: ключей для этого пользователя нет\n");
    return 1;
}
