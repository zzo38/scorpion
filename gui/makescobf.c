#if 0
gcc -s -O2 -o ~/bin/makescobf -fwrapv -Wno-unused-result makescobf.c
exit
#endif

#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  FILE*file;
  char ispipe;
  unsigned char bbox[4];
} InputFont;

static char*linebuf;
static size_t linesize;
static InputFont inputs[64];
static unsigned char head[24];
static int nchars;
static unsigned char chhead[8];
static unsigned char prhead[8];
static unsigned char calcx[128];
static int calcv[128];
static int endcalc;
static char copying_comments;
static char copying_ligkern;
static int linenum;
static unsigned short table[0x10000];
static unsigned char haschar[0x10000>>3];

static void nextline(void) {
  char*p;
  if(getline(&linebuf,&linesize,stdin)<=0) errx(1,"Input past end of file");
  if(!linebuf) err(1,"Memory error");
  if(p=strchr(linebuf,'\n')) *p=0;
  ++linenum;
}

static void read_first_part(void) {
  int m;
  char*p;
  unsigned char b[32];
  FILE*f;
  for(;;) {
    nextline();
    if(*linebuf=='\n' || *linebuf=='\r' || *linebuf=='#' || !*linebuf) continue;
    if(*linebuf=='*') break;
    if(*linebuf=='D' && linebuf[1]=='=') {
      m=strtol(linebuf+2,0,16);
      head[4]=m; head[5]=m>>8;
      continue;
    } else if(*linebuf=='T' && linebuf[1]=='=') {
      m=strtol(linebuf+2,0,16);
      head[10]=m; head[11]=m>>8;
      continue;
    } else if(*linebuf=='N' && linebuf[1]=='=') {
      nchars=strtol(linebuf+2,0,16);
      continue;
    } else if(*linebuf=='N' && linebuf[1]=='+') {
      nchars+=strtol(linebuf+2,0,16);
      continue;
    } else if(*linebuf=='N' && linebuf[1]=='-') {
      nchars-=strtol(linebuf+2,0,16);
      continue;
    } else if(*linebuf=='+') {
      head[0]=strtol(linebuf,&p,10);
      head[1]=strtol(p,&p,10);
      head[2]=strtol(p,&p,10)+128;
      head[3]=strtol(p,0,10)+128;
      continue;
    } else if(*linebuf=='a' && linebuf[1]=='=') {
      head[6]=strtol(linebuf+2,0,10);
      continue;
    } else if(*linebuf=='d' && linebuf[1]=='=') {
      head[7]=strtol(linebuf+2,0,10);
      continue;
    } else if(*linebuf=='?') {
      fprintf(stderr,"Line %d: %d characters remain; ",linenum,nchars);
      for(m=0;m<24;m++) fprintf(stderr,"%02X ",head[m]);
      fputc('\n',stderr);
      continue;
    }
    m=strtol(linebuf,&p,0);
    if(m<0 || m>63 || inputs[m].file) errx(1,"Wrong font number on line %d",linenum);
    if(*p=='|') {
      f=inputs[m].file=popen(p+1,"r");
      inputs[m].ispipe=1;
    } else if(*p=='<') {
      f=inputs[m].file=fopen(p+1,"r");
      inputs[m].ispipe=0;
    } else {
      errx(1,"Syntax error on line %d",linenum);
    }
    if(!f) err(1,"Cannot open font %d",m);
    if(fread(b,1,32,f)!=32 || memcmp(b,"\xFF\x01" "scobf",8)) errx(1,"Improper font format");
    memcpy(inputs[m].bbox,b+8,4);
    if(!head[0] && !head[1]) {
      memcpy(head,b+8,4);
    } else {
      if(b[10]<head[2]) head[0]+=head[2]-b[10],head[2]=b[10];
      if(b[11]<head[3]) head[1]+=head[7]-b[11],head[3]=b[11];
      if(head[0]+head[2]>b[8]+b[10]) head[0]=b[8]+b[10]-head[2];
      if(head[1]+head[3]>b[9]+b[11]) head[1]=b[9]+b[11]-head[3];
    }
    if(b[14]<head[6]) head[6]=b[14];
    if(b[15]<head[7]) head[7]=b[15];
    nchars+=b[16]+(b[17]<<8)+1;
  }
  if(nchars>0x10000) errx(1,"Too many characters");
  m=nchars-1;
  head[8]=m; head[9]=m>>8;
}

static void make_calc(char*p) {
  char*q;
  int i,j;
  for(;;) {
    while(*p==' ') p++;
    if(endcalc==128) errx(1,"Too many calculation instructions");
    if(!*p) break;
    switch(*p) {
      case '0' ... '9': case 'A' ... 'F': case 'a' ... 'f':
        calcx[endcalc]=0;
        calcv[endcalc]=strtol(p,&q,16);
        p=q;
        break;
      case '+': case '-': case '*': case '/': case '%': case '&': case '|': case '^': case '<': case '>': case 'H': case 'L':
      case '#': case '$': case '.': case '@': case 'Z': case 'Y': case 'T':
        calcx[endcalc]=*p++;
        break;
      case '\\':
        p++;
        if(*p<'a' || *p>'z') errx(1,"Improper calculation: %s",p-1);
        calcx[endcalc]=*p++;
        break;
      case '(': case '[':
        calcx[endcalc]=*p++;
        calcv[endcalc]=endcalc+1;
        break;
      case ':':
        calcx[endcalc]=*p++;
        calcv[endcalc]=endcalc+1;
        for(i=endcalc-1,j=1;i>=0 && j;i--) {
          if(calcx[i]=='(' || calcx[i]=='[') j--; else if(calcx[i]==')' || calcx[i]==']') j++;
        }
        if(i<0) errx(1,"Misnested blocks");
        calcv[i+1]=endcalc+1;
        break;
      case ')': case ']':
        calcx[endcalc]=*p++;
        for(i=endcalc-1,j=1;i>=0 && j;i--) {
          if(calcx[i]=='(' || calcx[i]=='[') j--; else if(calcx[i]==')' || calcx[i]==']') j++;
          if(calcx[i]==':' && j==1) break;
        }
        if(i<0) errx(1,"Misnested blocks");
        calcv[i+1]=endcalc+1;
        break;
      default: errx(1,"Improper calculation: %s",p);
    }
    endcalc++;
  }
}

#define StackReq(xx,yy) do{ if(ns-xx<0) errx(1,"Stack underflow"); if(ns-xx+yy>64) errx(1,"Stack overflow"); }while(0)
static int do_calc(int v) {
  unsigned long stack[64];
  int ns=1;
  int pc=0;
  *stack=v;
  while(pc<endcalc) switch(v=calcv[pc],calcx[pc++]) {
    case 0: StackReq(0,1); stack[ns++]=v; break;
    case '+': StackReq(2,1); ns--; stack[ns-1]+=stack[ns]; break;
    case '-': StackReq(2,1); ns--; stack[ns-1]-=stack[ns]; break;
    case '*': StackReq(2,1); ns--; stack[ns-1]*=stack[ns]; break;
    case '/': StackReq(2,1); ns--; if(!stack[ns]) return -1; stack[ns-1]/=stack[ns]; break;
    case '%': StackReq(2,1); ns--; if(!stack[ns]) return -1; stack[ns-1]%=stack[ns]; break;
    case '&': StackReq(2,1); ns--; stack[ns-1]&=stack[ns]; break;
    case '|': StackReq(2,1); ns--; stack[ns-1]|=stack[ns]; break;
    case '^': StackReq(2,1); ns--; stack[ns-1]^=stack[ns]; break;
    case '<': StackReq(2,1); ns--; stack[ns-1]<<=stack[ns]; break;
    case '>': StackReq(2,1); ns--; stack[ns-1]>>=stack[ns]; break;
    case 'H': StackReq(1,1); stack[ns-1]=(stack[ns-1]>>8)&0xFF; break;
    case 'L': StackReq(1,1); stack[ns-1]=stack[ns-1]&0xFF; break;
    case 'Y': StackReq(2,1); ns--; stack[ns-1]<<=8; stack[ns-1]+=stack[ns]&0xFF; break;
    case '#': StackReq(1,2); stack[ns]=stack[ns-1]; ns++; break;
    case '$': StackReq(2,2); v=stack[ns-1]; stack[ns-1]=stack[ns-2]; stack[ns-2]=v; break;
    case '.': if(ns) --ns; break;
    case '@': StackReq(0,1); stack[ns++]=*stack; break;
    case '(': StackReq(1,0); if(!stack[--ns]) pc=v; break;
    case ':': pc=v; break;
    case ')': /* do nothing */ break;
    case '[': StackReq(1,1); if(!stack[ns-1]) pc=v; break;
    case ']': /* do nothing */ break;
    case 'Z': return -1;
    case 'T': StackReq(1,1); stack[ns-1]=table[stack[ns-1]&0xFFFF]; break;
    case 'p': fprintf(stderr," %lX [%d] %lX\n",*stack,ns,ns?stack[ns-1]:0); break;
  }
  return ns?*stack&0xFFFF:-1;
}

static void do_font(int fontnum) {
  unsigned char b[64];
  FILE*f;
  int c,n,m;
  if(fontnum&~63) errx(1,"Incorrect font number");
  f=inputs[fontnum].file;
  if(!f) errx(1,"Incorrect font number");
  memcpy(chhead+4,inputs[fontnum].bbox,4);
  chhead[1]=head[0]+0x80;
  for(;;) {
    c=fgetc(f);
    if(c==EOF || c==0xF0) break;
    switch(c) {
      case 0x00:
        fread(chhead+1,1,7,f);
        goto glyph;
      case 0x01:
        fread(chhead+2,1,2,f);
        goto glyph;
      glyph:
        c=do_calc(chhead[2]|(chhead[3]<<8));
        n=((chhead[4]+7)>>3)*chhead[5];
        if(c==-1) {
          while(n>0) c=(n>64?64:n),fread(b,1,c,f),n-=c;
        } else {
          if(haschar[c>>3]&(1<<(c&7))) errx(1,"Duplicate character code 0x%04X",c);
          haschar[c>>3]|=1<<(c&7);
          if(!nchars--) errx(1,"Wrong number of characters (line %d; code 0x%04X)",linenum,c);
          chhead[2]=c; chhead[3]=c>>8;
          if(prhead[1]==chhead[1] && !memcmp(prhead+4,chhead+4,4)) {
            putchar(0x01);
            fwrite(chhead+2,1,2,stdout);
          } else {
            putchar(0x00);
            fwrite(chhead+1,1,7,stdout);
          }
          memcpy(prhead,chhead,8);
          while(n>0) c=(n>64?64:n),fread(b,1,c,f),fwrite(b,1,c,stdout),n-=c;
        }
        break;
      case 0x85:
        fread(b,1,5,f);
        if(copying_ligkern) {
          c=do_calc(b[0]|(b[1]<<8));
          if(c==-1) break;
          n=do_calc(b[2]|(b[3]<<8));
          if(n==-1) break;
          putchar(0x85);
          putchar(c); putchar(c>>8);
          putchar(n); putchar(n>>8);
          putchar(b[4]);
        }
        break;
      case 0x86:
        fread(b,1,6,f);
        if(copying_ligkern) {
          c=do_calc(b[0]|(b[1]<<8));
          if(c==-1) break;
          n=do_calc(b[2]|(b[3]<<8));
          if(n==-1) break;
          m=do_calc(b[4]|(b[5]<<8));
          if(m==-1) break;
          putchar(0x86);
          putchar(c); putchar(c>>8);
          putchar(n); putchar(n>>8);
          putchar(n); putchar(n>>8);
        }
        break;
      case 0xF1 ... 0xFF:
        fread(b,1,c&0x0F,f);
        if(copying_comments) {
          putchar(c);
          fwrite(b,1,c&0x0F,stdout);
        }
        break;
      default:
        if(c<0x80) errx(1,"Unrecognized command: 0x%02X",c);
        fread(b,1,c&0x0F,f);
    }
  }
}

static void make_glyph(int ch) {
  static unsigned char*raster=0;
  int n,r,y;
  if(haschar[ch>>3]&(1<<(ch&7))) errx(1,"Duplicate character code 0x%04X",ch);
  haschar[ch>>3]|=1<<(ch&7);
  if(!nchars--) errx(1,"Wrong number of characters (line %d; code 0x%04X)",linenum,ch);
  if(!raster) raster=malloc(((head[0]+7)>>3)*head[1]);
  if(!raster) err(1,"Memory error");
  memset(raster,0,((head[0]+7)>>3)*head[1]);
  for(r=y=0;;) {
    nextline();
    if(*linebuf!='.' && *linebuf!='o') break;
    if(y==head[1]) errx(1,"Wrong glyph size on line %d",linenum);
    for(n=0;;) {
      if(linebuf[n]=='o') raster[r+n/8]|=0x80>>(n&7);
      else if(linebuf[n]!='.') errx(1,"Syntax error on line %d",linenum);
      n++;
      if(n==head[0]) break;
    }
    if(linebuf[n]) errx(1,"Wrong glyph size on line %d",linenum);
    y++;
    r+=(head[0]+7)>>3;
  }
  if(y!=head[1]) errx(1,"Wrong glyph size on line %d (expected: %d=%d)",linenum,y,head[1]);
  chhead[1]=head[0]^0x80;
  memcpy(chhead+4,head,4);
  chhead[2]=ch; chhead[3]=ch>>8;
  if(prhead[1]==chhead[1] && !memcmp(prhead+4,chhead+4,4)) {
    putchar(0x01);
    fwrite(chhead+2,1,2,stdout);
  } else {
    putchar(0x00);
    fwrite(chhead+1,1,7,stdout);
  }
  memcpy(prhead,chhead,8);
  fwrite(raster,1,((head[0]+7)>>3)*head[1],stdout);
}

static void make_glyph_multi(void) {
  static unsigned char*raster=0;
  unsigned char q[8]={0,0,0,0,0,0,0,0};
  int c,n,r,y;
  int z=((head[0]+7)>>3)*head[1];
  if(!raster) raster=malloc(z<<3);
  if(!raster) err(1,"Memory error");
  memset(raster,0,z<<3);
  for(r=y=0;;) {
    nextline();
    if(*linebuf!='.' && (*linebuf<'a' || *linebuf>'h')) break;
    if(y==head[1]) errx(1,"Wrong glyph size on line %d",linenum);
    for(n=0;;) {
      if(linebuf[n]>='a' && linebuf[n]<='h') raster[r+n/8+z*(linebuf[n]-'a')]|=0x80>>(n&7);
      else if(linebuf[n]!='.') errx(1,"Syntax error on line %d",linenum);
      n++;
      if(n==head[0]) break;
    }
    if(linebuf[n]) errx(1,"Wrong glyph size on line %d (expected: %d=%d)",linenum,n,head[0]);
    y++;
    r+=(head[0]+7)>>3;
  }
  if(y!=head[1]) errx(1,"Wrong glyph size on line %d (expected: %d=%d)",linenum,y,head[1]);
  chhead[1]=head[0]^0x80;
  memcpy(chhead+4,head,4);
  for(n=0;n<256;n++) {
    c=do_calc(n);
    if(c==-1) continue;
    if(haschar[c>>3]&(1<<(c&7))) errx(1,"Duplicate character code 0x%04X (multi code 0x%02X)",c,n);
    haschar[c>>3]|=1<<(c&7);
    if(!nchars--) errx(1,"Wrong number of characters (line %d; code 0x%04X)",linenum,c);
    chhead[2]=c; chhead[3]=c>>8;
    if(prhead[1]==chhead[1] && !memcmp(prhead+4,chhead+4,4)) {
      putchar(0x01);
      fwrite(chhead+2,1,2,stdout);
    } else {
      putchar(0x00);
      fwrite(chhead+1,1,7,stdout);
    }
    for(y=0;y<8;y++) q[y]=n&(1<<y)?0xFF:0x00;
    for(y=0;y<z;y++) putchar((raster[0*z+y]&q[0])|(raster[1*z+y]&q[1])|(raster[2*z+y]&q[2])|(raster[3*z+y]&q[3])|(raster[4*z+y]&q[4])|(raster[5*z+y]&q[5])|(raster[6*z+y]&q[6])|(raster[7*z+y]&q[7]));
  }
}

static void make_table(char*s) {
  static unsigned short k=0;
  static unsigned short v=0;
  int n;
  while(*s) switch(*s++) {
    case ':': k=v=0; memset(table,0,sizeof(table)); break;
    case '0' ... '9': case 'A' ... 'F': k=strtol(s-1,&s,16); break;
    case '=': table[k++]=v=strtol(s,&s,16); break;
    case 'x': n=strtol(s,&s,16)-1; while(n-->0) table[k++]=v; break;
    case '*': n=strtol(s,&s,16)-1; while(n-->0) table[k++]=++v; break;
    case ',': case ' ': /* do nothing */ break;
    default: errx(1,"Syntax error on line %d",linenum);
  }
}

int main(int argc,char**argv) {
  char*p;
  int n;
  read_first_part();
  fwrite("\xFF\x01" "scobf",1,8,stdout);
  fwrite(head,1,24,stdout);
  prhead[1]=head[0]^0x80;
  memcpy(prhead+4,head,4);
  for(;;) {
    nextline();
    thisline:
    if(*linebuf==':') {
      n=strlen(p=linebuf+1);
      while(n) {
        if(n>15) {
          putchar(0xFF);
          fwrite(p,1,15,stdout);
          p+=15;
          n-=15;
        } else if(n==15) {
          putchar(0xFF);
          fwrite(p,1,15,stdout);
          fwrite("\xF1\n",1,2,stdout);
          break;
        } else {
          putchar(n+0xF1);
          fwrite(p,1,n,stdout);
          putchar('\n');
          break;
        }
      }
    } else if(*linebuf==',' || *linebuf==';') {
      if(*linebuf==';') endcalc=0;
      make_calc(linebuf+1);
    } else if(*linebuf>='0' && *linebuf<='9') {
      do_font(strtol(linebuf,&p,10));
      if(*p) errx(1,"Syntax error");
    } else if(*linebuf=='C' && linebuf[1]=='+') {
      copying_comments=1;
    } else if(*linebuf=='C' && linebuf[1]=='-') {
      copying_comments=0;
    } else if(*linebuf=='K' && linebuf[1]=='+') {
      copying_ligkern=1;
    } else if(*linebuf=='K' && linebuf[1]=='-') {
      copying_ligkern=0;
    } else if(*linebuf=='T') {
      make_table(linebuf+1);
    } else if(*linebuf=='M') {
      make_glyph_multi();
      goto thisline;
    } else if(*linebuf=='=') {
      make_glyph(strtol(linebuf+1,0,16));
      goto thisline;
    } else if(*linebuf=='*') {
      break;
    } else if(*linebuf=='?') {
      fprintf(stderr,"Line %d: %d characters remain\n",linenum,nchars);
    } else if(*linebuf && *linebuf!='#') {
      errx(1,"Syntax error on line %d",linenum);
    }
  }
  if(nchars) errx(1,"Wrong number of characters (expected %d more)",nchars);
  for(n=0;n<64;n++) if(inputs[n].ispipe) pclose(inputs[n].file);
  putchar(0xF0);
  return 0;
}
