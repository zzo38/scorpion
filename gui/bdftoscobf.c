#if 0
gcc -s -O2 -o ~/bin/bdftoscobf -fwrapv bdftoscobf.c
exit
#endif

#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char*linebuf;
static size_t linesize;
static unsigned char head[24];
static int nchars;
static unsigned char chhead[8];
static unsigned char prhead[8];
static FILE*comments;
static char*comments_mem;
static size_t comments_size;

static inline void nextline(void) {
  if(getline(&linebuf,&linesize,stdin)<=0) errx(1,"Input past end of file");
  if(!linebuf) err(1,"Memory error");
}

int main(int argc,char**argv) {
  unsigned char c;
  int n;
  while((n=getopt(argc,argv,"+c:p:"))>0) switch(n) {
    case 'c': if(!comments && !(comments=open_memstream(&comments_mem,&comments_size))) err(1,0); fprintf(comments,"%s\n",optarg); break;
    case 'p': n=strtol(optarg,0,16); head[10]=n; head[11]=n>>8; break;
    default: errx(1,"Improper switch");
  }
  fwrite("\xFF\x01" "scobf",1,8,stdout);
  nextline();
  if(strncmp(linebuf,"STARTFONT ",10)) errx(1,"Bad format");
  for(;;) {
    nextline();
    if(!strncmp(linebuf,"FONTBOUNDINGBOX ",16)) {
      sscanf(linebuf+16,"%hhd %hhd %hhd %hhd",head+0,head+1,head+2,head+3);
      head[2]+=0x80; head[3]+=0x80;
    } else if(!strncmp(linebuf,"DEFAULT_CHAR ",13)) {
      sscanf(linebuf+13,"%d",&n);
      head[4]=n; head[5]=n>>8;
    } else if(!strncmp(linebuf,"FONT_ASCENT ",12)) {
      sscanf(linebuf+12,"%d",&n);
      head[6]=n;
    } else if(!strncmp(linebuf,"FONT_DESCENT ",13)) {
      sscanf(linebuf+13,"%d",&n);
      head[7]=n;
    } else if(!strncmp(linebuf,"CHARS ",6)) {
      sscanf(linebuf+6,"%d",&n);
      head[8]=(n-1); head[9]=(n-1)>>8;
      nchars=n;
      break;
    }
  }
  fwrite(head,1,24,stdout);
  prhead[1]=head[0]+0x80;
  memcpy(prhead+4,head,4);
  while(nchars--) {
    do nextline(); while(strncmp(linebuf,"STARTCHAR",9));
    for(;;) {
      nextline();
      if(!strncmp(linebuf,"ENCODING ",9)) {
        sscanf(linebuf+9,"%d",&n);
        chhead[2]=n; chhead[3]=n>>8;
      } else if(!strncmp(linebuf,"BBX ",4)) {
        sscanf(linebuf+4,"%hhd %hhd %hhd %hhd",chhead+4,chhead+5,chhead+6,chhead+7);
        chhead[6]+=0x80; chhead[7]+=0x80;
      } else if(!strncmp(linebuf,"DWIDTH ",7)) {
        sscanf(linebuf+7,"%d",&n);
        chhead[1]=n+0x80;
      } else if(!strncmp(linebuf,"BITMAP",6)) {
        break;
      }
    }
    if(prhead[1]==chhead[1] && !memcmp(prhead+4,chhead+4,4)) {
      putchar(0x01);
      fwrite(chhead+2,1,2,stdout);
    } else {
      fwrite(chhead,1,8,stdout);
    }
    memcpy(prhead,chhead,8);
    for(;;) {
      nextline();
      if(!strncmp(linebuf,"ENDCHAR",7)) break;
      for(n=0;linebuf[n]>32;n+=2) {
        sscanf(linebuf+n,"%2hhX",&c);
        putchar(c);
      }
    }
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
