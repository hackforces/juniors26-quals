#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void final_note(void) {
  char flag[256]; FILE *f=fopen("/run/case/flag","r");
  if (!f) exit(1); fgets(flag,sizeof(flag),f); puts("The jeweller's note:"); puts(flag); fclose(f);
}
void desk(void) {
  char note[48]; puts("Hotel desk: leave a note for the porter."); gets(note); puts("The porter folds the note.");
}
int main(void) { setvbuf(stdout,NULL,_IONBF,0); desk(); return 0; }
