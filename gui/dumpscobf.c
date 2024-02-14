#if 0
gcc -s -O2 -o ~/bin/dumpscobf -Wno-unused-result dumpscobf.c
exit
#endif

#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char head[24];
static unsigned char chhead[8];
static unsigned char misc[16];

int main(int argc,char**argv) {
  int c,n;
  fread(head,1,8,stdin);
  if(memcmp("\xFF\x01" "scobf",head,8)) errx(1,"Bad format");
  fread(head,1,24,stdin);
  printf("Font bounding box: %d %d %d %d\n",head[0],head[1],head[2]-128,head[3]-128);
  if(head[4] || head[5]) printf("Default character: 0x%04X\n",head[4]|(head[5]<<8));
  if(head[6]) printf("Ascent: %d\n",head[6]);
  if(head[7]) printf("Descent: %d\n",head[7]);
  printf("Number of characters: %d\n",head[8]+(head[9]<<8)+1);
  if(head[10]) printf("TRON plane: 0x%04X\n",head[10]|(head[11]<<8));
  chhead[1]=head[0]+0x80;
  memcpy(chhead+4,head,4);
  for(;;) {
    switch(c=getchar()) {
      case 0x00:
        fread(chhead+1,1,7,stdin);
        goto glyph;
      case 0x01:
        fread(chhead+2,1,2,stdin);
        goto glyph;
      glyph:
        printf("Character 0x%02X: ",chhead[2]|(chhead[3]<<8));
        printf("%d %d %d %d [%d]\n",chhead[4],chhead[5],chhead[6]-128,chhead[7]-128,chhead[1]-128);
        n=((chhead[4]+7)>>3)*chhead[5];
        while(n--) getchar();
        break;
      case 0xF0: printf("End of file\n"); return 0;
      case 0xF1 ... 0xFF:
        printf("Comment: ");
        n=c&0x0F;
        while(n--) {
          c=getchar();
          if(c>=0x20 && c<0x7F) putchar(c); else printf("<%02X>",c);
        }
        putchar('\n');
        break;
      case EOF: errx(1,"Unexpected end of file");
      default:
        if(c<0x80) errx(1,"Unrecognized command: 0x%02X",c);
        if(c&0x0F) fread(misc,1,c&0x0F,stdin);
        printf("Unknown command: 0x%02X",c);
    }
  }
}
