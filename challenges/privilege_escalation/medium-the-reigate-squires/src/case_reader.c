#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char b[512]; int n, fd;
  if (argc != 2) { puts("usage: case-reader <report>"); return 1; }
  fd=open(argv[1], O_RDONLY); if(fd<0) { perror("report"); return 1; }
  while((n=read(fd,b,sizeof(b)))>0) write(1,b,n);
  return 0;
}
