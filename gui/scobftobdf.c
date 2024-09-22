#if 0
gcc -s -O2 -o ~/bin/scobftobdf -fwrapv -Wno-unused-result scobftobdf.c
exit
#endif

#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned char head[32];
static const char*name;
static unsigned char chhead[8];
static unsigned long normwidth;

static void send_character(void) {
  unsigned char d[256];
  int w=(chhead[4]+7)/8;
  int n=w*chhead[5];
  printf("STARTCHAR ");
  if(head[16]>0x20 && head[16]<0xFE && head[16]!=0x7F) printf("T+%X%02X%02X",head[18]|(head[19]<<8),chhead[3],chhead[2]); else printf("%d",chhead[2]+(chhead[3]<<8));
  putchar('\n');
  printf("ENCODING %d\n",chhead[2]+(chhead[3]<<8));
  printf("SWIDTH %ld 0\n",(chhead[1]-128)*1000L/normwidth);
  printf("DWIDTH %d 0\n",chhead[1]-128);
  printf("BBX %d %d %d %d\n",chhead[4],chhead[5],chhead[6]-128,chhead[7]-128);
  printf("BITMAP\n");
  while(n--) {
    printf("%02X",getchar());
    if(!(n%w)) putchar('\n');
  }
  printf("ENDCHAR\n");
}

int main(int argc,char**argv) {
  int c,n;
  while((n=getopt(argc,argv,"+n:w:"))>0) switch(n) {
    case 'n': name=optarg; break;
    case 'w': normwidth=strtol(optarg,0,10); break;
    default: errx(1,"Improper switch");
  }
  fread(head,1,32,stdin);
  if(memcmp(head,"\xFF\x01" "scobf",8)) errx(1,"Bad format");
  printf("STARTFONT 2.1\n");
  printf("COMMENT - Conversion by scobftobdf\n");
  if(name) printf("FONT %s\n",name);
  printf("SIZE %d 75 75\n",head[9]);
  if(!normwidth) normwidth=head[8];
  printf("FONTBOUNDINGBOX %d %d %d %d\n",head[8],head[9],head[10]-128,head[11]-128);
  n=3;
  if(head[18]>0x20 && head[18]<0xFE && head[18]!=0x7F) n++;
  printf("STARTPROPERTIES %d\n",n);
  if(!head[14] && !head[15]) {
    head[14]=head[9];
    if(head[11]<128) head[15]=128-head[11];
  }
  printf("FONT_ASCENT %d\n",head[14]);
  printf("FONT_DESCENT %d\n",head[15]);
  printf("DEFAULT_CHAR %d\n",head[12]|(head[13]<<8));
  if(head[18]>0x20 && head[18]<0xFE && head[18]!=0x7F) printf("TRON_PLANE %d\n",head[18]|(head[19]<<8));
  printf("ENDPROPERTIES\n");
  printf("CHARS %d\n",(head[16]|(head[17]<<8))+1);
  memcpy(chhead+4,head+8,4);
  chhead[1]=chhead[4]+128;
  for(;;) {
    c=getchar();
    if(c==EOF) errx(1,"Unexpected end of file");
    if(c&0x80) {
      if(c==0xF0) break;
      printf("COMMENT EXTENSION %02X:",c);
      n=c&15;
      while(n--) printf("%02X",getchar());
      putchar('\n');
    } else if(c==0) {
      fread(chhead+1,1,7,stdin);
      send_character();
    } else if(c==1) {
      fread(chhead+2,1,2,stdin);
      send_character();
    } else {
      errx(1,"Unrecognized command (0x%X)",c);
    }
  }
  printf("ENDFONT\n");
  return 0;
}

/*
  Note: This program uses "-tron-1" for the XLFD for TRON fonts for plane
  0x21, since the plane number is "1" for language specifier code "FE 21".
*/

