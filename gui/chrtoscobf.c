#if 0
gcc -s -O2 -o ~/bin/chrtoscobf -fwrapv chrtoscobf.c
exit
#endif

#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned char head[24]={8,0,128,128,0,0,0,0, 255,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
static FILE*comments;
static char*comments_mem;
static size_t comments_size;

int main(int argc,char**argv) {
  unsigned char c;
  int n;
  while((n=getopt(argc,argv,"+c:d:h:p:"))>0) switch(n) {
    case 'c': if(!comments && !(comments=open_memstream(&comments_mem,&comments_size))) err(1,0); fprintf(comments,"%s\n",optarg); break;
    case 'd': head[7]=strtol(optarg,0,10); break;
    case 'h': head[1]=strtol(optarg,0,10); break;
    case 'p': n=strtol(optarg,0,16); head[10]=n; head[11]=n>>8; break;
    default: errx(1,"Improper switch");
  }
  if(!head[1]) {
    if(fseek(stdin,0,SEEK_END)) err(1,"Cannot determine size of stdin");
    n=ftell(stdin);
    if(n<=0) err(1,"Cannot determine size of stdin");
    if(n&255) err(1,"Size of stdin is not a multiple of 256");
    head[1]=n>>8;
    if(fseek(stdin,0,SEEK_SET)) err(1,"Cannot determine size of stdin");
  }
  head[3]-=head[7];
  fwrite("\xFF\x01" "scobf",1,8,stdout);
  fwrite(head,1,24,stdout);
  for(n=0;n<256;n++) {
    putchar(0x01);
    putchar(n);
    putchar(0x00);
    for(c=0;c<head[1];c++) putchar(getchar());
  }
  if(comments) {
    fflush(comments);
    if(!comments_mem) err(1,"Memory error");
    for(n=0;n<comments_size;) {
      c=comments_size-n; c=(c>15?15:c);
      putchar(c|0xF0);
      fwrite(comments_mem+n,1,c,stdout);
      n+=c;
    }
  }
  putchar(0xF0);
  return 0;
}
