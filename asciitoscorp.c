#if 0
gcc -s -O2 -o ~/bin/asciitoscorp -Wno-multichar asciitoscorp.c
exit
#endif

#define _GNU_SOURCE
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  TOK_EOF,
  TOK_CHAR,
  TOK_TRON_CHAR,
  TOK_COMMAND,
  TOK_COMMAND_BEGIN,
  TOK_COMMAND_END,
  TOK_COMMAND_MID,
  TOK_BLANK_LINE,
};

enum {
#define X(xxx) CMD_##xxx,
#include "asciitoscorp.inc"
#undef X
};

static const char*const commands[]={
#define X(xxx) #xxx,
#include "asciitoscorp.inc"
#undef X
};

#define Error(xxx,...) errx(1,"Error on line %d: "xxx,linenum,##__VA_ARGS__)
static int linenum=1;
static char*attrbuf;
static size_t attrlen;
static FILE*attrf;
static char*bodybuf;
static size_t bodylen;
static FILE*bodyf;
static uint8_t curchset=0x10;
static uint32_t tokent,tokenv;
static FILE*infile;

#define InvalidTC(xxx,yyy) ((((xxx)>>yyy)&0xFF)==0x7F || (((xxx)>>yyy)&0xFF)<0x21 || (((xxx)>>yyy)&0xFF)>0xFD)

static inline int inp(void) {
  int c;
  retry:
  while((c=fgetc(infile))=='\r');
  if(c=='\n' && infile==stdin) linenum++;
  if(c==EOF && infile!=stdin) {
    pclose(infile);
    infile=stdin;
    goto retry;
  }
  return c;
}

static uint32_t read_euctron(int k,int c) {
  int p=-0x80;
  int d;
  if(c==0x90 || c==0x91) {
    p=(c&1?0:-0x40);
    c=inp();
  }
  while(c==0x80) p+=0x100,c=inp();
  p+=c;
  c=inp(); d=inp();
  p=(p<<16)+(c<<8)+d;
  switch(k) {
    case 0x88: return p^0x8080;
    case 0x89: return p^0x0080;
    case 0x8A: return p^0x8000;
    case 0x8B: return p^0x0000;
    case 0x8C: return (c<0xC0?p-0x2080:(p&~0xFFFF)+(d<<8)+c-0x8040);
    case 0x8D: return (c<0xC0?p-0x2000:c<0xE0?(p&~0xFFFF)+(d<<8)+c-0x0040:p-0x6060);
  }
}

static uint32_t read_tchar(int c) {
  static const uint8_t jisx[0x80]={
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0xA1, 0xA3,0xA4,0xA5,0xA8, 0xAC,0xAD,0xAE,0xAF,
    0xEE,0xEF,0xF0,0xF1, 0xF2,0xF3,0xF4,0xF5, 0xF6,0xF7,0xF8,0xF9, 0xFA,0xFB,0xFC,0xFD,
    0xFE,0x87,0x00,0x88, 0x89,0x8A,0x00,0x00, 0x8B,0x00,0x00,0x00, 0x8C,0x8D,0x8E,0x8F,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x90,0x91,
    0x92,0x93,0x94,0x95, 0x96,0x97,0x98,0x99, 0x9A,0x9B,0x9C,0x9D, 0x9E,0x9F,0xA0,0x00,
  };
  uint32_t v=0;
  int d;
  if(c==0x20) return 0x20;
  if(c<0x7F) return c+0x702200; //TODO: possibly change this to convert ASCII to JIS
  d=inp();
  if(d<0x80) Error("Truncated character code");
  convert: switch(curchset&0x0F) {
    case 0x01: // EUC-JP or EUC-TRON
      if(c==0x8F) {
        c=d; d=inp();
        if(d<0x80) Error("Truncated character code");
        v=((jisx[c&0x7F]?:c)<<8)^d^0x210080;
      } else if(c==0x8E) {
        v=d+0x702300;
      } else if(c>=0x88 && c<=0x8D) {
        v=read_euctron(c,d);
      } else {
        v=(c<<8)^d^0x218080;
      }
      break;
    case 0x02: // EUC-CN
      c-=0xA1; d-=0xA1;
      c=c*94+d;
      v=((c/126+0x21)<<8)|(c%126+0x210080);
      break;
    case 0x04: // EUC-KR
      c-=0xA1; d-=0xA1;
      c=c*94+d;
      v=((c/126+0xB7)<<8)|(c%126+0x210080);
      break;
  }
  if(InvalidTC(v,0) || InvalidTC(v,8) || InvalidTC(v,16)) Error("Invalid character code: <%lX>",(long)v);
  return v;
}

static int read_charset(void) {
  int i;
  char b[16];
  int c;
  for(i=0;;) {
    c=inp();
    if(c=='>') break;
    if(c==EOF) Error("Unexpected end of file");
    if(c==' ' || c=='\n') Error("Unterminated charset name");
    if(i==15) Error("Too long charset name");
    if((c>='A' && c<='Z') || (c>='0' && c<='9')) b[i++]=c;
    else if(c>='a' && c<='z') b[i++]=c+'A'-'a';
    else if(c!='-' && c!='_') Error("Invalid character in charset name");
  }
  b[i]=0;
  if(!strcmp(b,"ASCII") || !strcmp(b,"PC")) return 0x10;
  if(!strcmp(b,"EUCJP") || !strcmp(b,"JP") || !strcmp(b,"EUCTRON") || !strcmp(b,"TRON") || !strcmp(b,"TRON8")) return 0x01;
  if(!strcmp(b,"EUCCN") || !strcmp(b,"CN")) return 0x02;
  if(!strcmp(b,"EUCKR") || !strcmp(b,"KR")) return 0x04;
  if(!strcmp(b,"EUCTRONLTR") || !strcmp(b,"TRONLTR") || !strcmp(b,"TRON8LTR")) return 0x01;
  if(!strcmp(b,"EUCTRONRTL") || !strcmp(b,"TRONRTL") || !strcmp(b,"TRON8RTL")) return 0x81;
  Error("Invalid charset name: %s",b);
}

static void open_pipe_for_input(void) {
  char com[0x800];
  int n=0;
  int c;
  for(;;) {
    c=inp();
    if(c==EOF || c<' ') Error("Improper character in <! !> block or unterminated <! !> block");
    if(n && c=='>' && com[n-1]=='!') break;
    if(n>=0x7FF) Error("Too long command in <! !> block");
    com[n++]=c;
  }
  com[n-1]=0;
  infile=popen(com,"r");
  if(!infile) err(3,"Cannot open pipe for input");
}

static int compare_commands(const void*a,const void*b) {
  return strcmp(*(const char**)a,*(const char**)b);
}

static void nexttok(void) {
  static char linestate=0;
  static char heredoc=0;
  static char heredocs[32];
  static char m=0;
  static char n=0;
  const char**q;
  int c,i,h;
  char key[16];
  char*pkey=key;
  restart:
  if(heredoc&~1) {
    if(n==m) {
      m=n=0;
      c=heredoc&0xFF;
      heredoc=1;
      goto nheredoc;
    } else {
      tokent=TOK_CHAR;
      tokenv=heredocs[n++]&0xFF;
      return;
    }
  }
  while(heredoc) {
    c=inp();
    if(c==EOF) {
      Error("Unexpected end of file in heredoc");
    } else if(c=='\n' && !heredocs[m]) {
      linestate=0;
      m=n=heredoc=0;
      tokent=TOK_COMMAND;
      tokenv=CMD_BR;
      return;
    } else if(c==heredocs[m]) {
      m++;
    } else if(m) {
      n=1;
      heredoc=c;
      tokent=TOK_COMMAND;
      tokenv=CMD_BR;
      return;
    } else {
      nheredoc:
      tokent=TOK_CHAR,tokenv=c;
      if(c=='\t') tokent=TOK_COMMAND,tokenv=CMD_TAB;
      else if(c=='\n') tokent=TOK_COMMAND,tokenv=CMD_BR;
      else if(!(c&~0x1F)) Error("Improper character in heredoc");
      return;
    }
  }
  if(linestate>2) {
    if(linestate>6) c=0xFF&*heredocs,linestate-=4; else c=inp();
    if(c=='}' && linestate<5) {
      linestate+=2;
      goto restart;
    } else if((linestate==5 && c=='>') || (linestate==6 && c=='|')) {
      linestate=1;
      goto restart;
    } else if(linestate>4) {
      tokent=TOK_CHAR;
      tokenv='}';
      *heredocs=c;
      linestate+=2;
      return;
    } else {
      tokent=TOK_CHAR;
      tokenv=c;
      return;
    }
  }
  c=inp();
  tokenv=0;
  if(c==EOF) {
    tokent=TOK_EOF;
  } else if(c=='<' || c=='|') {
    linestate=1;
    tokent=(c=='<'?TOK_COMMAND:TOK_COMMAND_END);
    for(h=i=0;i<16;i++) {
      c=inp();
      if(c=='$' && !i) {
        i=read_charset();
        if((0xF0&(i^curchset)) && ftell(bodyf)) Error("Cannot change charset at this time");
        curchset=i;
        goto restart;
      } else if(c=='=' && !i && tokent==TOK_COMMAND_END) {
        linestate=2;
        goto restart;
      } else if(c=='{' && !i) {
        linestate=(tokent==TOK_COMMAND?3:4);
        goto restart;
      } else if(c=='<' && !i && tokent==TOK_COMMAND) {
        *heredocs='\n';
        i=1;
        while(c!='\n') {
          c=inp();
          if(c==EOF) Error("Unexpected end of file");
          if(c&~0x7F) Error("Improper character after <<");
          if(i==31) Error("Too long text after <<");
          heredocs[i++]=c;
        }
        heredocs[i]=0;
        heredoc=1;
        m=n=0;
        goto restart;
      } else if(c=='!' && !i && tokent==TOK_COMMAND) {
        if(infile!=stdin) Error("Use if <! !> while <! !> is already active");
        open_pipe_for_input();
        goto restart;
      }
      if(c==EOF) Error("Unexpected end of file");
      if((c>='0' && c<='9') || (c>='A' && c<='Z')) {
        if(c>'F') h=1;
        key[i]=c;
      } else if(c>='a' && c<='z') {
        if(c>'f') h=1;
        key[i]=c+'A'-'a';
      } else if(c=='|' || c=='>') {
        key[i]=0;
        if(c=='>' && tokent==TOK_COMMAND && !h && i>1 && i<9) {
          tokenv=strtol(key,0,16);
          tokent=(tokenv>0xFF)?TOK_TRON_CHAR:TOK_CHAR;
          if(tokenv>0xFF) if(InvalidTC(tokenv,0) || InvalidTC(tokenv,8) || InvalidTC(tokenv,16)) Error("Improper character code");
          return;
        }
        if(c=='|') tokent++;
        if(tokent==TOK_COMMAND_MID && !i) {
          tokenv=CMD_0;
        } else {
          q=bsearch(&pkey,commands,sizeof(commands)/sizeof(*commands),sizeof(*commands),compare_commands);
          if(!q) Error("Unrecognized command: %s",key);
          tokenv=q-commands;
        }
        return;
      }
    }
    Error("Improper command");
  } else if(c=='>') {
    Error("Syntax error");
  } else if(c=='\n') {
    if(linestate==2) {
      linestate=0;
      goto restart;
    } else {
      tokent=(linestate?TOK_CHAR:TOK_BLANK_LINE);
      tokenv=0x20;
      linestate=0;
    }
  } else if(c==' ') {
    if(linestate!=1) goto restart;
    tokent=TOK_CHAR;
    tokenv=0x20;
    linestate=2;
  } else {
    if(!(c&~0x1F)) Error("Improper character");
    tokent=TOK_CHAR;
    tokenv=c;
    linestate=1;
  }
}

static int do_include(char p) {
  uint32_t s,t;
  char m[0x2000];
  int c;
  FILE*f;
  fputc(0,attrf);
  fflush(attrf);
  if(!attrbuf) err(2,"Memory error");
  f=p?popen(attrbuf,"r"):fopen(attrbuf,"r");
  if(!f) err(2,"Cannot open file: %s",attrbuf);
  rewind(attrf);
  while((c=fgetc(f))!=EOF) {
    putchar(c);
    s=fgetc(f)<<8; s|=fgetc(f);
    if(feof(f)) errx(2,"Unexpected EOF in include file");
    putchar(s>>8); putchar(s);
    while(s) {
      t=fread(m,1,s>0x2000?0x2000:s,f);
      if(!t || t>s) err(2,"Error reading include file");
      fwrite(m,1,t,stdout);
      s-=t;
    }
    s=fgetc(f)<<16; s|=fgetc(f)<<8; s|=fgetc(f);
    if(feof(f)) errx(2,"Unexpected EOF in include file");
    putchar(s>>16); putchar(s>>8); putchar(s);
    while(s) {
      t=fread(m,1,s>0x2000?0x2000:s,f);
      if(!t || t>s) err(2,"Error reading include file");
      fwrite(m,1,t,stdout);
      s-=t;
    }
  }
  if(p) pclose(f); else fclose(f);
  return 1;
}

static int do_block(void) {
  int bt=0;
  uint32_t tt,tv,as,bs;
  uint16_t plane=0;
  uint16_t splane=0;
  uint8_t sty=0x11;
  int mode=0;
  int i;
  do nexttok(); while(tokent==TOK_BLANK_LINE || (tokent==TOK_CHAR && tokenv==' '));
  if(tokent==TOK_EOF) return 0;
  rewind(attrf);
  rewind(bodyf);
  tt=tokent;
  if(tt==TOK_COMMAND || tt==TOK_COMMAND_BEGIN) {
    switch(tv=tokenv) {
      case CMD_1: bt=0x01; break;
      case CMD_2: bt=0x02; break;
      case CMD_3: bt=0x03; break;
      case CMD_4: bt=0x04; break;
      case CMD_5: bt=0x05; break;
      case CMD_6: bt=0x06; break;
      case CMD_ALT: bt=0x0B; if(tt==TOK_COMMAND) Error("Attribute is required for <ALT>"); break;
      case CMD_ASK: bt=0x09; break;
      case CMD_INC: if(tt==TOK_COMMAND) Error("Attribute is required for <INC>"); break;
      case CMD_INT: bt=0x0A; break;
      case CMD_L: bt=0x08; break;
      case CMD_PIPE: if(tt==TOK_COMMAND) Error("Attribute is required for <PIPE>"); break;
      case CMD_Q: bt=0x0C; if(tt==TOK_COMMAND_BEGIN) Error("Attribute not allowed for <Q>"); break;
      case CMD_X: bt=0x0D; break;
      default: goto body;
    }
    nexttok();
  } else if(tt==TOK_CHAR || tt==TOK_TRON_CHAR) {
    goto body;
  } else {
    Error("Improper token at beginning of block");
  }
  if(tt!=TOK_COMMAND_BEGIN) goto body;
  attribute:
  while(tokent==TOK_CHAR && tokenv==0x20) nexttok();
  for(;;) {
    if(tokent==TOK_CHAR) {
      fputc(tokenv,attrf);
    } else if(tokent==TOK_COMMAND_END && tokenv==tv) {
      fflush(attrf);
      if(as=ftell(attrf)) {
        if(as>0xFFFF) Error("Too long attribute");
        if(!attrbuf) err(2,"Memory error");
        while(as && attrbuf[as-1]==' ') --as;
        fseek(attrf,as,SEEK_SET);
      }
      if(tv==CMD_INC) return do_include(0);
      if(tv==CMD_PIPE) return do_include(1);
      nexttok();
      goto body;
    } else {
      Error("Improper token in attribute");
    }
    nexttok();
  }
  body:
  if(tv!=CMD_X) while(tokent==TOK_CHAR && tokenv==0x20) nexttok();
  for(;;) {
    if(tokent==TOK_CHAR || (tokent==TOK_TRON_CHAR && !(curchset&0x70))) {
      if(mode=='S') {
        if(tokent==TOK_TRON_CHAR || tokenv<0x30 || tokenv>0x3B || tokenv==0x3A) Error("Improper character in SGR code");
        fputc(tokenv,bodyf);
      } else if(curchset&0x70) {
        if(tokenv>=0x20) {
          fputc(tokenv,bodyf);
        } else {
          if(!tokenv) Error("Invalid character code");
          fputc(0x10,bodyf);
          fputc(tokenv+0x40,bodyf);
        }
      } else if(tokenv<0x20) {
        Error("Invalid character code: <%lX>",(long)tokenv);
      } else {
        if(tokent==TOK_CHAR && tokenv!=0x20) tokenv=read_tchar(tokenv);
        if((tokenv>>16)!=plane && tokenv>0xFFFF) {
          plane=tokenv>>16;
          for(i=plane>>16;i>=0;i--) fputc(0xFE,bodyf);
          fputc(plane,bodyf);
        }
        if(tokenv&0xFF00) fputc(tokenv>>8,bodyf);
        fputc(tokenv,bodyf);
      }
    } else if(tokent==TOK_COMMAND) {
      switch(tokenv) {
        case CMD_BR: if(bt!=0x0D || mode) goto bad; fputc(0x0A,bodyf); break;
        case CMD_E: if(bt==0x0D || mode) goto bad; fputc(sty=0x13,bodyf); break;
        case CMD_F: if(bt==0x0D || mode) goto bad; fputc(sty=0x14,bodyf); break;
        case CMD_N: if(bt==0x0D || mode) goto bad; fputc(sty=0x11,bodyf); break;
        case CMD_S: if(bt==0x0D || mode) goto bad; fputc(sty=0x12,bodyf); break;
        case CMD_TAB: if(bt!=0x0D || mode) goto bad; fputc(0x09,bodyf); break;
        case CMD_RGR: if(mode) goto bad; fputs("\e[m",bodyf); break;
        default: bad: Error("Improper command in body");
      }
    } else if(tokent==TOK_COMMAND_BEGIN) {
      switch(tokenv) {
        case CMD_E: if(bt==0x0D || mode) goto bad; fputc(0x13,bodyf); break;
        case CMD_F: if(bt==0x0D || mode) goto bad; fputc(0x14,bodyf); break;
        case CMD_FUR: if(bt==0x0D || mode) goto bad; fputc(0x17,bodyf); mode='F'; splane=plane; break;
        case CMD_N: if(bt==0x0D || mode) goto bad; fputc(0x11,bodyf); break;
        case CMD_R: if(bt==0x0D || mode) goto bad; fputc(0x16,bodyf); break;
        case CMD_S: if(bt==0x0D || mode) goto bad; fputc(0x12,bodyf); break;
        case CMD_SGR: if(mode) goto bad; fputc(0x1B,bodyf); fputc(0x5B,bodyf); mode='S'; break;
        default: goto bad;
      }
    } else if(tokent==TOK_COMMAND_END) {
      switch(tokenv) {
        case CMD_E: if(bt==0x0D || mode) goto bad; fputc(sty,bodyf); break;
        case CMD_F: if(bt==0x0D || mode) goto bad; fputc(sty,bodyf); break;
        case CMD_FUR: if(mode!='f') goto bad; fputc(0x19,bodyf); mode=0; if(splane!=plane) plane=0; break;
        case CMD_N: if(bt==0x0D || mode) goto bad; fputc(sty,bodyf); break;
        case CMD_R: if(bt==0x0D || mode) goto bad; fputc(0x15,bodyf); break;
        case CMD_S: if(bt==0x0D || mode) goto bad; fputc(sty,bodyf); break;
        case CMD_SGR: if(mode!='S') goto bad; fputc(0x6D,bodyf); mode=0; break;
        default: goto bad;
      }
    } else if(tokent==TOK_COMMAND_MID) {
      switch(tokenv) {
        case CMD_0: if(mode=='F') goto mid_fur; goto bad;
        case CMD_FUR: mid_fur: if(mode!='F') goto bad; fputc(0x18,bodyf); mode='f'; if(splane!=plane) plane=0; break;
        default: goto bad;
      }
    } else if(tokent==TOK_EOF || tokent==TOK_BLANK_LINE) {
      if(mode) Error("Unterminated subcommand");
      fflush(bodyf);
      if(bs=ftell(bodyf)) {
        if(bs>0xFFFFFF) Error("Too long body");
        if(!bodybuf) err(2,"Memory error");
        if(bt!=0x0D) while(bs && bodybuf[bs-1]==' ') --bs;
      }
      goto done;
    } else {
      Error("Improper token in body");
    }
    nexttok();
  }
  done:
  if(!as && !bs) return 1;
  putchar(bt|(curchset&0xF0));
  putchar(as>>8); putchar(as);
  if(as) fwrite(attrbuf,1,as,stdout);
  putchar(bs>>16); putchar(bs>>8); putchar(bs);
  if(bs) fwrite(bodybuf,1,bs,stdout);
  rewind(bodyf);
  return 1;
}

int main(int argc,char**argv) {
  attrf=open_memstream(&attrbuf,&attrlen);
  bodyf=open_memstream(&bodybuf,&bodylen);
  if(!attrf || !bodyf) err(1,"Allocation failed");
  infile=stdin;
  while(do_block());
  return 0;
}

