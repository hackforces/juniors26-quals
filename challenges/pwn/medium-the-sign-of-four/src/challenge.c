#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
volatile unsigned short expedition = 0;
void keeper(void) { char flag[256]; FILE *f=fopen("/run/case/flag","r"); if(!f) exit(1); fgets(flag,sizeof(flag),f); puts(flag); }
int main(void) {
  char signature[160]; setvbuf(stdout,NULL,_IONBF,0);
  puts("Agra terminal: sign the expedition ledger.");
  ssize_t n=read(0,signature,sizeof(signature)-1); if(n<1) return 0; signature[n]=0;
  printf(signature, &expedition); puts("\nLedger checked.");
  if(expedition==0x1337) keeper(); else puts("Only the four may enter.");
  return 0;
}
