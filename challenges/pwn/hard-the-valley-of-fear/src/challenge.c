#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void genuine_ending(void) {
  char flag[256];
  FILE *stream = fopen("/run/case/flag", "r");
  if (!stream) exit(1);
  fgets(flag, sizeof(flag), stream);
  puts(flag);
  fclose(stream);
}

void recording(void) {
  char observation[128];
  char transcript[72];
  puts("Archive diagnostic: record one observation.");
  if (!fgets(observation, sizeof(observation), stdin)) return;
  printf(observation);
  puts("Leave a correction for the transcript:");
  read(STDIN_FILENO, transcript, 240);
  puts("Correction archived.");
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("recording marker: %p\n", recording);
  recording();
  return 0;
}
