#if 0
gcc -s -O2 -o ~/bin/asciitoscorp -Wno-multichar asciitoscorp.c
exit
#endif

#define _GNU_SOURCE
#include <err.h>
#include <glob.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
  IM_UNKNOWN,
  IM_NORMAL,
  IM_DATA,
  IM_BODY,
  IM_TEMPLATE,
};

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
static char internalmode;
static char multimode;
static char regen_flag;
static FILE*controlfile;
static char controlfile_done;
static unsigned int seqnum;
static FILE*dataf;
static uint8_t data_code=0;
static char*template;
static char verbose;

#define InvalidTC(xxx,yyy) ((((xxx)>>yyy)&0xFF)==0x7F || (((xxx)>>yyy)&0xFF)<0x21 || (((xxx)>>yyy)&0xFF)>0xFD)

static int do_multi(FILE*f);

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
    eof:
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
        linestate=0;
        for(;;) {
          c=inp();
          if(c=='\n') goto restart;
          if(c==EOF) goto eof;
        }
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
    if(internalmode) putchar(IM_NORMAL);
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

static void set_size_attribute(void) {
  struct stat s;
  fflush(attrf);
  if(!attrbuf) errx(2,"Memory error");
  if(stat(attrbuf,&s)) err(1,"Cannot stat");
  if(!S_ISREG(s.st_mode)) Error("Stat is not regular file");
  fprintf(attrf,"%llu ",(long long)s.st_size);
}

static void raw_entry(FILE*f) {
  uint32_t t;
  FILE*p;
  char m[0x2000];
  int i=0;
  for(;;) {
    nexttok();
    if(tokent==TOK_CHAR) {
      if(i>=0x1FFF) Error("Too long command in <RAW>");
      m[i++]=tokenv;
    } else if(tokent==TOK_COMMAND_END && tokenv==CMD_RAW) {
      break;
    } else {
      Error("Improper token in <RAW>");
    }
  }
  m[i]=0;
  p=popen(m,"r");
  if(!p) err(2,"Cannot open pipe");
  while(t=fread(m,1,0x2000,p)) fwrite(m,1,t,f);
  pclose(p);
}

static void raw_inline_entry(FILE*f) {
  int t=fgetc(infile);
  int c;
  while((c=fgetc(infile))!=t && c!=EOF) fputc(c,f);
}

static void env_entry(FILE*f) {
  char*s;
  char m[256];
  int i=0;
  for(;;) {
    nexttok();
    if(tokent==TOK_CHAR && tokenv!='=') {
      if(tokenv==' ') continue;
      if(i>=255) Error("Too long command in <ENV>");
      m[i++]=tokenv;
    } else if(tokent==TOK_COMMAND_END && tokenv==CMD_ENV) {
      break;
    } else {
      Error("Improper token in <ENV>");
    }
  }
  if(s=getenv(m)) fputs(s,f);
}

static int do_block(void) {
  char*q;
  int bt=0;
  uint32_t tt,tv,as,bs;
  uint16_t plane=0;
  uint16_t splane=0;
  uint8_t sty=0x11;
  int mode=0;
  int mode2=0;
  int i;
  do nexttok(); while(tokent==TOK_BLANK_LINE || (tokent==TOK_CHAR && tokenv==' '));
  if(tokent==TOK_EOF) return 0;
  as=0;
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
      case CMD_BODY: if(tt==TOK_COMMAND_BEGIN) Error("Attribute not allowed for <BODY>"); if(!internalmode) Error("Not allowed in single mode"); goto tbody;
      case CMD_DATA: if(tt==TOK_COMMAND_BEGIN) Error("Attribute not allowed for <DATA>"); if(!internalmode) Error("Not allowed in single mode"); break;
      case CMD_INC: if(tt==TOK_COMMAND) Error("Attribute is required for <INC>"); break;
      case CMD_INT: bt=0x0A; break;
      case CMD_L: bt=0x08; break;
      case CMD_PIPE: if(tt==TOK_COMMAND) Error("Attribute is required for <PIPE>"); break;
      case CMD_SET: /* nothing to do in this case */ break;
      case CMD_Q: bt=0x0C; if(tt==TOK_COMMAND_BEGIN) Error("Attribute not allowed for <Q>"); break;
      case CMD_X: bt=0x0D; break;
      default: goto body;
    }
    nexttok();
  } else if(tt==TOK_CHAR || tt==TOK_TRON_CHAR) {
    goto body;
  } else {
    Error("Improper token at beginning of block (%d;%d)",tokent,tokenv);
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
    } else if(tokent==TOK_COMMAND_BEGIN && tokenv==CMD_RAW) {
      raw_entry(attrf);
    } else if(tokent==TOK_COMMAND_BEGIN && tokenv==CMD_ENV) {
      env_entry(attrf);
    } else if(tokent==TOK_COMMAND && tokenv==CMD_RAWI) {
      raw_inline_entry(attrf);
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
      } else if(mode=='I') {
        if(tokent==TOK_TRON_CHAR || tokenv<' ' || tokenv>'~') Error("Improper character in file info attribute");
        if(tokenv!=' ' || mode2==1) fputc(tokenv,attrf);
        if(tokenv==' ' && mode2==1) mode2=2; else if(tokenv!=' ' && !mode2) mode2=1;
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
        case CMD_FIS: if(bt!=0x08 || mode) goto bad; fputc(0,attrf); fputc(0x20,attrf); set_size_attribute(); as=ftell(attrf); break;
        case CMD_N: if(bt==0x0D || mode) goto bad; fputc(sty=0x11,bodyf); break;
        case CMD_RAWI: raw_inline_entry(bodyf); break;
        case CMD_S: if(bt==0x0D || mode) goto bad; fputc(sty=0x12,bodyf); break;
        case CMD_TAB: if((bt!=0x0D && tv!=CMD_SET) || mode) goto bad; fputc(0x09,bodyf); break;
        case CMD_RGR: if(mode) goto bad; fputs("\e[m",bodyf); break;
        default: bad: Error("Improper command in body (%d;%d)",tokent,tokenv);
      }
    } else if(tokent==TOK_COMMAND_BEGIN) {
      switch(tokenv) {
        case CMD_E: if(bt==0x0D || mode) goto bad; fputc(0x13,bodyf); break;
        case CMD_ENV: env_entry(bodyf); break;
        case CMD_F: if(bt==0x0D || mode) goto bad; fputc(0x14,bodyf); break;
        case CMD_FI: if(bt<0x08 || bt>0x09 || mode) goto bad; mode='I'; mode2=0; fputc(0,attrf); fputc(0x20,attrf); break;
        case CMD_FIS: if(bt!=0x08 || mode) goto bad; mode='I'; mode2=2; fputc(0,attrf); fputc(0x20,attrf); set_size_attribute(); break;
        case CMD_FUR: if(bt==0x0D || mode) goto bad; fputc(0x17,bodyf); mode='F'; splane=plane; break;
        case CMD_N: if(bt==0x0D || mode) goto bad; fputc(0x11,bodyf); break;
        case CMD_R: if(bt==0x0D || mode) goto bad; fputc(0x16,bodyf); break;
        case CMD_RAW: if(mode) goto bad; raw_entry(bodyf); break;
        case CMD_S: if(bt==0x0D || mode) goto bad; fputc(0x12,bodyf); break;
        case CMD_SGR: if(mode) goto bad; fputc(0x1B,bodyf); fputc(0x5B,bodyf); mode='S'; break;
        default: goto bad;
      }
    } else if(tokent==TOK_COMMAND_END) {
      switch(tokenv) {
        case CMD_E: if(bt==0x0D || mode) goto bad; fputc(sty,bodyf); break;
        case CMD_F: if(bt==0x0D || mode) goto bad; fputc(sty,bodyf); break;
        case CMD_FI: if(mode!='I') goto bad; fflush(attrf); as=ftell(attrf); mode=0; break;
        case CMD_FIS: if(mode!='I') goto bad; fflush(attrf); as=ftell(attrf); mode=0; break;
        case CMD_FUR: if(mode!='f') goto bad; fputc(0x19,bodyf); mode=0; if(splane!=plane) plane=0; break;
        case CMD_N: if(bt==0x0D || mode) goto bad; fputc(sty,bodyf); break;
        case CMD_R: if(bt==0x0D || mode) goto bad; fputc(0x15,bodyf); break;
        case CMD_S: if(bt==0x0D || mode) goto bad; fputc(sty,bodyf); break;
        case CMD_SGR: if(mode!='S') goto bad; fputc(0x6D,bodyf); mode=0; break;
        default: goto bad;
      }
    } else if(tokent==TOK_COMMAND_MID) {
      switch(tokenv) {
        case CMD_0: if(mode=='F') goto mid_fur; if(!mode) goto mid_0; goto bad;
        case CMD_FUR: mid_fur: if(mode!='F') goto bad; fputc(0x18,bodyf); mode='f'; if(splane!=plane) plane=0; break;
        default: goto bad;
        mid_0: fputc(0x02,bodyf); break;
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
  if(tv!=CMD_SET) {
    if(internalmode) putchar(tv==CMD_DATA?IM_DATA:IM_NORMAL);
    putchar(bt|(curchset&0xF0));
    putchar(as>>8); putchar(as);
    if(as) fwrite(attrbuf,1,as,stdout);
    putchar(bs>>16); putchar(bs>>8); putchar(bs);
    if(bs) fwrite(bodybuf,1,bs,stdout);
  } else {
    if(as+bs>=0x1FFF) Error("Improper <SET>");
    if(!as) {
      q=memchr(bodybuf,'=',bs);
      if(!q) Error("Improper <SET>");
      *q++=0;
      setenv(bodybuf,q,1);
    } else if(q=memchr(attrbuf,'=',as)) {
      if(bs) Error("Improper <SET>");
      *q++=0;
      setenv(attrbuf,q,1);
    } else {
      attrbuf[as]=0;
      bodybuf[bs]=0;
      setenv(attrbuf,bodybuf,1);
    }
  }
  rewind(bodyf);
  return 1;
  tbody: putchar(IM_BODY); return 1;
}

static void open_controlfile(const char*name) {
  if(controlfile_done) return;
  if(!controlfile) controlfile=fopen(name,"r+")?:fopen(name,"w+x");
  if(!controlfile) err(1,"Cannot open control file");
  if(regen_flag==1) return;
  //TODO: read control file
}

static void im_normal(FILE*f,FILE*o) {
  uint32_t s,t;
  char m[0x2000];
  fputc(fgetc(f),o);
  s=fgetc(f)<<8; s|=fgetc(f);
  if(feof(f)) errx(2,"Unexpected error");
  fputc(s>>8,o); fputc(s,o);
  while(s) {
    t=fread(m,1,s>0x2000?0x2000:s,f);
    if(!t || t>s) err(2,"Unexpected error");
    fwrite(m,1,t,o);
    s-=t;
  }
  s=fgetc(f)<<16; s|=fgetc(f)<<8; s|=fgetc(f);
  if(feof(f)) errx(2,"Unexpected error");
  fputc(s>>16,o); fputc(s>>8,o); fputc(s,o);
  while(s) {
    t=fread(m,1,s>0x2000?0x2000:s,f);
    if(!t || t>s) err(2,"Unexpected error");
    fwrite(m,1,t,o);
    s-=t;
  }
}

static void im_data(FILE*f) {
  uint32_t s,t;
  char m[0x2000];
  fgetc(f); // unused
  if(fgetc(f) || fgetc(f)) errx(2,"Unexpected error");
  s=fgetc(f)<<16; s|=fgetc(f)<<8; s|=fgetc(f);
  if(feof(f)) errx(2,"Unexpected error");
  while(s) {
    t=fread(m,1,s>0x2000?0x2000:s,f);
    if(!t || t>s) err(2,"Unexpected error");
    fwrite(m,1,t,dataf);
    s-=t;
  }
  fputc(data_code,dataf);
}

static void copy_body(FILE*f) {
  uint32_t s;
  fflush(bodyf);
  s=ftell(bodyf);
  if(!bodybuf) errx(2,"Memory error");
  fwrite(bodybuf,1,s,f);
  rewind(bodyf);
}

static void do_one_conversion(const char*in,const char*out,int m,const char*tem) {
  FILE*fi=fopen(in,"r");
  FILE*fo=fopen(out,"w");
  FILE*f;
  pid_t x;
  int d[2];
  char b[64];
  struct stat s;
  int c;
  if(verbose) fprintf(stderr,"Conversion: %s -> %s [%c] %s\n",in?:".",out?:".",m?:'-',tem?:".");
  if(!fi || !fo) err(1,"Cannot open file");
  if(m=='T') rewind(bodyf);
  snprintf(b,32,"%u",++seqnum);
  if(setenv("_seq",b,1) || setenv("_in",in,1) || setenv("_out",out,1)) err(2,"Cannot set environment variable");
  if(stat(in,&s)) err(2,"Cannot stat file '%s'",in);
  snprintf(b,64,"%llu",(long long)s.st_mtime);
  setenv("_mtim",b,1);
  snprintf(b,64,"%llu",(long long)s.st_ctime);
  setenv("_ctim",b,1);
  if(pipe(d)) err(2,"Cannot create pipe");
  x=fork();
  if(x==-1) err(2,"Cannot fork");
  if(x) {
    // Parent
    close(d[1]);
    f=fdopen(d[0],"r");
    for(;;) switch(c=fgetc(f)) {
      case EOF: goto eof;
      case IM_NORMAL: im_normal(f,m=='T'?bodyf:fo); break;
      case IM_DATA: im_data(f); break;
      case IM_BODY: if(m!='t') errx(1,"Cannot use <BODY> here"); copy_body(fo); break;
      case IM_TEMPLATE: m='t'; break;
      default: errx(3,"Unknown error");
    }
    eof: fclose(f);
    waitpid(x,&c,0);
    if(!WIFEXITED(c) || WEXITSTATUS(c)) errx(3,"External program exit code %d",WEXITSTATUS(c));
  } else {
    // Child
    close(d[0]);
    dup2(fileno(fi),0);
    dup2(d[1],1);
    if(m=='T') execl("/proc/self/exe",in,"-J",tem,(void*)0);
    else if(m=='E') execl("/bin/sh","/bin/sh","-c",tem,(void*)0);
    else execl("/proc/self/exe",in,"-I",(void*)0);
    warn("Cannot execute self");
    _exit(3);
  }
  fclose(fi);
  fclose(fo);
}

static void do_one_conversion_x(const char*in,const char*c) {
  FILE*f;
  pid_t x;
  int d[2];
  char b[64];
  struct stat s;
  int i;
  snprintf(b,32,"%u",++seqnum);
  if(setenv("_seq",b,1) || setenv("_in",in,1)) err(2,"Cannot set environment variable");
  if(stat(in,&s)) err(2,"Cannot stat file '%s'",in);
  snprintf(b,64,"%llu",(long long)s.st_mtime);
  setenv("_mtim",b,1);
  snprintf(b,64,"%llu",(long long)s.st_ctime);
  setenv("_ctim",b,1);
  if(pipe(d)) err(2,"Cannot create pipe");
  x=fork();
  if(x==-1) err(2,"Cannot fork");
  if(x) {
    // Parent
    close(d[1]);
    f=fdopen(d[0],"r");
    if(!f) err(2,"Cannot open");
    if(i=do_multi(f)) exit(i);
    fclose(f);
    waitpid(x,&i,0);
    if(!WIFEXITED(i) || WEXITSTATUS(i)) errx(3,"External program exit code %d",WEXITSTATUS(i));
  } else {
    // Child
    close(d[0]);
    dup2(d[1],1);
    execl("/bin/sh","/bin/sh","-c",c,(void*)0);
    warn("Cannot execute self");
    _exit(3);
  }
}

static void do_conversions(char*p,int m) {
  char b[512];
  glob_t g={0,0,0};
  int i,j,n;
  char*q=strchr(p,' ');
  char*pa;
  char*qa;
  char*s;
  char*t=0;
  if(!q) errx(1,"Improper command in multi mode: CNV%c %s",m?:' ',p);
  *q++=0;
  if(m=='E' || m=='T') {
    t=strchr(q,' ');
    if(!t) errx(1,"Improper command in multi mode");
    *t++=0;
  }
  if(pa=strchr(p,'*')) {
    if(m!='X') {
      qa=strchr(q,'*');
      if(!qa) errx(1,"Improper CNV command");
    }
    i=glob(p,GLOB_ERR|GLOB_NOESCAPE|GLOB_NOSORT|GLOB_MARK,0,&g);
    if(i==GLOB_NOMATCH) {
      warnx("No match for pattern '%s'",p);
      return;
    } else if(i) {
      errx(2,"Glob error (%d)",i);
    }
    snprintf(b,512,"%u",(int)g.gl_pathc);
    setenv("_glo",b,1);
    n=strlen(p);
    for(i=0;i<g.gl_pathc;i++) {
      s=g.gl_pathv[i];
      if(!s || !*s || s[(j=strlen(s))-1]=='/') continue;
      snprintf(b,512,"%.*s",j-n+1,s+(pa-p));
      setenv("_name",b,1);
      if(m!='X') {
        snprintf(b,512,"%.*s%.*s%s",(int)(qa-q),q,j-n+1,s+(pa-p),qa+1);
        do_one_conversion(s,b,m,t);
      } else {
        do_one_conversion_x(s,q);
      }
    }
    globfree(&g);
  } else {
    if(m=='X') do_one_conversion_x(p,q); else do_one_conversion(p,q,m,t);
  }
}

static int do_time_env(char*p,int m) {
  char*q=strchr(p,'=');
  struct tm tm;
  time_t ti=time(0);
  char buf[256];
  if(!q) return 1;
  *q++=0;
  if(m) gmtime_r(&ti,&tm); else localtime_r(&ti,&tm);
  if(!strftime(buf,255,q,&tm)) errx(1,"Cannot convert date/time");
  if(setenv(p,buf,1)) err(2,"Cannot set environment variable '%s'",p);
  return 0;
}

static void do_size_env(char*p) {
  char buf[32];
  fflush(attrf);
  snprintf(buf,32,"%lu",(long)ftell(attrf));
  if(setenv(p,buf,1)) err(2,"Cannot set environment variable '%s'",p);
}

static void do_send_data(char*p) {
  FILE*f;
  uint32_t s;
  fflush(attrf);
  s=ftell(attrf);
  if(!attrbuf) err(2,"Memory error");
  f=popen(p,"w");
  if(!p) err(2,"Cannot open pipe");
  fwrite(attrbuf,1,s,f);
  pclose(f);
}

static int do_multi(FILE*f) {
  static const int mu[4]={'\1\0\0\0','\0\1\0\0','\0\0\1\0','\0\0\0\1'};
  static const int ms[5]={'____','\0___','\0\0__','\0\0\0_','\0\0\0\0'};
  char*line=0;
  size_t line_size=0;
  char*p;
  char*q;
  int c,i,m;
  while(getline(&line,&line_size,f)>0) {
    p=line+strlen(line);
    while(p>line && (p[-1]==' ' || p[-1]=='\t' || p[-1]=='\n' || p[-1]=='\r')) *--p=0;
    if(verbose) fprintf(stderr,"** %s\n",line);
    if(*line=='#' || !*line) continue;
    for(p=line,m=i=0;i<4;i++) {
      if(p[i]==' ' || p[i]=='=' || !p[i]) break;
      if(p[i]>='a' && p[i]<='z') p[i]+='A'-'a';
      m+=mu[i]*p[i];
    }
    m+=ms[i];
    if(p[i]!=' ' && p[i]!='=' && p[i]) goto bad;
    p+=i+(p[i]?1:0);
    switch(m) {
      case 'ALL_': if(regen_flag!=1) regen_flag=strtol(p,0,10)?2:0; break;
      case 'CD__': if(chdir(p)) err(1,"Cannot change directory"); break;
      case 'CNV_': do_conversions(p,0); break;
      case 'CNVE': do_conversions(p,'E'); break;
      case 'CNVT': do_conversions(p,'T'); break;
      case 'CNVX': do_conversions(p,'X'); break;
      case 'CTR_': open_controlfile(p); break;
      case 'DATA': fwrite(p,1,strlen(p),dataf); fputc(data_code,dataf); break;
      case 'DIV_': if(dataf!=attrf) pclose(dataf); dataf=popen(p,"w"); if(!dataf) err(2,"Cannot open pipe"); break;
      case 'END_': if(dataf!=attrf) pclose(dataf); dataf=attrf; break;
      case 'NOWJ': if(do_time_env(p,0)) goto bad; break;
      case 'NOWZ': if(do_time_env(p,1)) goto bad; break;
      case 'REW_': rewind(attrf); break;
      case 'SEND': do_send_data(p); break;
      case 'SEQ_': seqnum=strtol(p,0,10); break;
      case 'SET_': q=strchr(p,'='); if(!q) goto bad; *q++=0; if(setenv(p,q,1)) err(2,"Cannot set environment variable '%s'",p); break;
      case 'SIZE': do_size_env(p); break;
      case 'SYS_': i=system(p); if(i==-1) err(1,"Cannot execute external program"); if(i=WEXITSTATUS(i)) errx(1,"External program exit code %d",i); break;
      case 'TERM': data_code=strtol(p,0,16); break;
      default: bad: errx(1,"Improper command in multi mode: %s",line);
    }
  }
  free(line);
  return 0;
}

static void chmod_auto(char*s) {
  char*p=strrchr(s,'/');
  int c;
  if(p) {
    c=p[1];
    p[1]=0;
    if(verbose) fprintf(stderr,"Changing directory to: %s\n",s);
    if(chdir(s)) err(1,"Cannot change directory");
    p[1]=c;
  }
}

int main(int argc,char**argv) {
  int c;
  while((c=getopt(argc,argv,"+IJ:ac:m:v"))>0) switch(c) {
    case 'I': internalmode=1; break;
    case 'J': internalmode=1; template=optarg; break;
    case 'a': regen_flag=1; break;
    case 'c': open_controlfile(optarg); break;
    case 'm': multimode=1; if(*optarg && (*optarg!='-' || optarg[1]) && !freopen(optarg,"r",stdin)) err(1,"Cannot open command file"); chmod_auto(optarg); break;
    case 'v': verbose=1; break;
    default: return 1;
  }
  if(argc!=optind) errx(1,"Too many arguments");
  attrf=open_memstream(&attrbuf,&attrlen);
  bodyf=open_memstream(&bodybuf,&bodylen);
  if(!attrf || !bodyf) err(2,"Allocation failed");
  if(multimode) {
    dataf=attrf;
    return do_multi(stdin);
  }
  infile=stdin;
  while(do_block());
  if(template) {
    linenum=1;
    argv[0]=template;
    stdin=freopen(template,"r",stdin);
    if(!stdin) err(2,"Cannot open template file");
    putchar(IM_TEMPLATE);
    while(do_block());
  }
  return 0;
}

