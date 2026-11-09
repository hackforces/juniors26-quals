#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int valid_port(const char *text) {
  char *end = NULL;
  long value = strtol(text, &end, 10);
  return end && *end == '\0' && value >= 2000 && value <= 65535;
}

int main(int argc, char **argv) {
  char token[128] = {0}, expected[128] = {0}, flag[256] = {0};
  struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  if (argc != 2 || !valid_port(argv[1])) {
    puts("usage: courier <localhost-port>");
    return 1;
  }
  address.sin_port = htons((unsigned short)atoi(argv[1]));
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0 || connect(sock, (struct sockaddr *)&address, sizeof(address)) != 0) {
    perror("courier");
    return 1;
  }
  if (recv(sock, token, sizeof(token) - 1, 0) <= 0) return 1;
  token[strcspn(token, "\r\n")] = '\0';
  FILE *tokens = fopen("/etc/copper/token", "r");
  if (!tokens || !fgets(expected, sizeof(expected), tokens)) return 1;
  fclose(tokens);
  expected[strcspn(expected, "\r\n")] = '\0';
  if (strcmp(token, expected) != 0) {
    send(sock, "Courier rejects the token.\n", 27, 0);
    return 1;
  }
  if (setuid(0) != 0) return 1;
  FILE *flags = fopen("/root/flag", "r");
  if (!flags || !fgets(flag, sizeof(flag), flags)) return 1;
  fclose(flags);
  send(sock, flag, strlen(flag), 0);
  return 0;
}
