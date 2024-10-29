#if 0
gcc -g -O0 -o ./tertoder tertoder.c asn1.o
exit
#endif

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "asn1.h"

enum {
  TOK_EOF,
  TOK_BRACE_BEGIN,
  TOK_BRACE_END,
  TOK_SEQ_BEGIN,
  TOK_SEQ_END,
  TOK_SET_BEGIN,
  TOK_SET_END,
  TOK_KV_BEGIN,
  TOK_KV_END,
  TOK_EXT_BEGIN,
  TOK_EXT_END,
  TOK_WRAP,
  TOK_EQUAL,
  TOK_NAME,
  TOK_PREFIX,
  TOK_IMPLICIT,
  TOK_SPECIAL_0,
  TOK_SPECIAL_1,
  TOK_INTEGER,
  TOK_REAL,
  TOK_OID,
  TOK_RELATIVE_OID,
  TOK_START_BIT_STRING,
  TOK_START_HEX_STRING,
  TOK_START_BASE64_STRING,
  TOK_START_TEXT_STRING,
};

typedef struct {
  const char*name;
  uint8_t type;
} Prefix;

static const Prefix prefix[]={
  {"A",ASN1_IA5_STRING},
  {"BCD",ASN1_BCD_STRING},
  {"BITS",ASN1_BIT_STRING},
  {"BMP",ASN1_BMP_STRING},
  {"DESC",ASN1_OBJECT_DESCRIPTOR},
  {"DESCRIPTOR",ASN1_OBJECT_DESCRIPTOR},
  {"GEN",ASN1_GENERAL_STRING},
  {"GENERAL",ASN1_GENERAL_STRING},
  {"GENTIME",ASN1_GENERALIZED_TIME},
  {"GR",ASN1_GRAPHIC_STRING},
  {"GRAPHIC",ASN1_GRAPHIC_STRING},
  {"GT",ASN1_GENERALIZED_TIME},
  {"IA5",ASN1_IA5_STRING},
  {"NUMERIC",ASN1_NUMERIC_STRING},
  {"O",ASN1_OCTET_STRING},
  {"OCTET",ASN1_OCTET_STRING},
  {"P",ASN1_PRINTABLE_STRING},
  {"PC",ASN1_PC_STRING},
  {"PRINTABLE",ASN1_PRINTABLE_STRING},
  {"TELETEX",ASN1_TELETEX_STRING},
  {"TIME",250},
  {"TRON",ASN1_TRON_STRING},
  {"TS",ASN1_UTC_TIMESTAMP},
  {"UNIVERSAL",ASN1_UNIVERSAL_STRING},
  {"UT",ASN1_UTCTIME},
  {"UTCTIME",ASN1_UTCTIME},
  {"UTF16",ASN1_UTF16_STRING},
  {"UTF8",ASN1_UTF8_STRING},
  {"V",ASN1_VISIBLE_STRING},
  {"VIDEOTEX",ASN1_VIDEOTEX_STRING},
  {"VISIBLE",ASN1_VISIBLE_STRING},
};

#define TOKENMAX 8000
static ASN1_Encoder*enc;
static int tokent;
static uint8_t tokenb;
static int64_t tokenv;
static uint32_t tokenw;
static uint8_t tokenstr[(TOKENMAX)+4];
static int tokenlen;

#define ReturnT(x) do{ return tokent=x; }while(0)
#define ReturnTV(x,y) do{ tokenv=y; return tokent=x; }while(0)
#define ReturnTW(x,y) do{ tokenw=y; return tokent=x; }while(0)
#define ReturnTBW(x,y,z) do{ tokenb=y; tokenw=z; return tokent=x; }while(0)

static const char wordch[128]={
  ['#']=2, ['0' ... '9']=1, ['-']=1, ['+']=2, ['.']=2,
  ['a' ... 'z']=3, ['A' ... 'Z']=3, ['_']=3,
};

static int wordtok(int colon) {
  int i,j;
  // Name, prefix
  if(wordch[*tokenstr]==3) {
    for(i=1;i<tokenlen && (wordch[tokenstr[i]]&1);i++);
    if(i==tokenlen) {
      if(colon) {
        getchar();
        ReturnT(TOK_PREFIX);
      }
      ReturnT(TOK_NAME);
    }
  }
  // Purely decimal integer, implicit
  if((*tokenstr>='0' && *tokenstr<='9') || *tokenstr=='-' || *tokenstr=='+') {
    for(i=1;i<tokenlen && tokenstr[i]>='0' && tokenstr[i]<='9';i++);
    if(i==tokenlen) ReturnTBW(TOK_INTEGER,10,0);
    if(i==tokenlen-1 && *tokenstr>='0' && *tokenstr<='9' && (tokenstr[i]=='A' || tokenstr[i]=='C' || tokenstr[i]=='P' || tokenstr[i]=='U')) {
      if(colon) getchar();
      if(tokenstr[i]=='A') ReturnTBW(TOK_IMPLICIT,ASN1_APPLICATION,strtol(tokenstr,0,10));
      if(tokenstr[i]=='C') ReturnTBW(TOK_IMPLICIT,ASN1_CONTEXT_SPECIFIC,strtol(tokenstr,0,10));
      if(tokenstr[i]=='P') ReturnTBW(TOK_IMPLICIT,ASN1_PRIVATE,strtol(tokenstr,0,10));
      if(tokenstr[i]=='U') ReturnTBW(TOK_IMPLICIT,ASN1_UNIVERSAL,strtol(tokenstr,0,10));
    }
  }
  // Special values
  if(*tokenstr=='#') {
    if(tokenlen==2) {
      if(tokenstr[1]=='Z') ReturnTW(TOK_SPECIAL_0,ASN1_NULL);
      if(tokenstr[1]=='F') ReturnTBW(TOK_SPECIAL_1,-0,ASN1_BOOLEAN);
      if(tokenstr[1]=='T') ReturnTBW(TOK_SPECIAL_1,-1,ASN1_BOOLEAN);
    } else if(tokenlen==4 && tokenstr[1]=='I' && tokenstr[2]=='N' && tokenstr[3]=='F') {
      ReturnTBW(TOK_SPECIAL_1,0x40,ASN1_REAL);
    } else if(tokenlen==4 && tokenstr[1]=='N' && tokenstr[2]=='A' && tokenstr[3]=='N') {
      ReturnTBW(TOK_SPECIAL_1,0x42,ASN1_REAL);
    } else if(tokenlen==5 && tokenstr[2]=='I' && tokenstr[3]=='N' && tokenstr[4]=='F') {
      if(tokenstr[1]=='+') ReturnTBW(TOK_SPECIAL_1,0x40,ASN1_REAL);
      if(tokenstr[1]=='-') ReturnTBW(TOK_SPECIAL_1,0x41,ASN1_REAL);
    }
  }
  // Object identifier
  if(tokenlen>2 && *tokenstr>='0' && *tokenstr<='2' && tokenstr[1]=='.') {
    for(i=2;i<tokenlen && ((tokenstr[i]>='0' && tokenstr[i]<='9') || tokenstr[i]=='.');i++);
    if(i==tokenlen) ReturnT(TOK_OID);
  }
  // Relative object identifier
  if(tokenlen>5 && tokenstr[0]=='.' && tokenstr[1]=='.' && tokenstr[2]=='.' && tokenstr[3]>='0' && tokenstr[3]<='2' && tokenstr[4]=='.') {
    for(i=5;i<tokenlen && ((tokenstr[i]>='0' && tokenstr[i]<='9') || tokenstr[i]=='.');i++);
    if(i==tokenlen) ReturnT(TOK_RELATIVE_OID);
  }
  // Integer with base number, real with base number
  if(tokenlen>2 && *tokenstr>='1' && *tokenstr<='9') {
    tokenb=*tokenstr-'0';
    if(tokenstr[1]>='0' && tokenstr[1]<='9') tokenb=10*tokenb+tokenstr[1]-'0',tokenw=2; else tokenw=1;
    if(tokenstr[tokenw]=='#' && tokenb>=2 && tokenb<=36) {
      ++tokenw;
      for(i=tokenw;i<tokenlen;i++) if(tokenstr[i]>='a' && tokenstr[i]<='z') tokenstr[i]+='A'-'a';
      if(tokenb==10) {
        for(i=tokenw;i<tokenlen;i++) if(tokenstr[i]=='e' || tokenstr[i]=='E' || tokenstr[i]=='.') goto decimal;
      } else if(tokenb==2 || tokenb==4 || tokenb==8 || tokenb==16) {
        for(i=tokenw;i<tokenlen;i++) if(tokenstr[i]=='p' || tokenstr[i]=='P' || tokenstr[i]=='.') break;
        j=0;
        if(i!=tokenlen) {
          i=(tokenstr[i]=='-' || tokenstr[i]=='+')?(j=1,tokenw+1):tokenw;
          for(;i<tokenlen && ((tokenstr[i]>='0' && tokenstr[i]<='9' && tokenstr[i]<tokenb+'0') || (tokenstr[i]>='A' && tokenstr[i]<'A'+tokenb-10));i++);
          if(i!=tokenlen && tokenstr[i]=='.') {
            j=1;
            for(i++;i<tokenlen && ((tokenstr[i]>='0' && tokenstr[i]<='9' && tokenstr[i]<tokenb+'0') || (tokenstr[i]>='A' && tokenstr[i]<'A'+tokenb-10));i++);
          }
          if(i!=tokenlen && (tokenstr[i]=='p' || tokenstr[i]=='P')) {
            i++;
            j=1;
            if(i!=tokenlen && (tokenstr[i]=='-' || tokenstr[i]=='+')) i++;
            for(;i<tokenlen && tokenstr[i]>='0' && tokenstr[i]<='9';i++);
          }
          if(j && i==tokenlen) ReturnT(TOK_REAL);
        }
      }
      for(i=tokenw;i<tokenlen && ((tokenstr[i]>='0' && tokenstr[i]<='9' && tokenstr[i]<tokenb+'0') || (tokenstr[i]>='A' && tokenstr[i]<'A'+tokenb-10));i++);
      if(i==tokenlen) ReturnT(TOK_INTEGER);
    }
  }
  // Real without base number
  if(tokenlen>3 && ((*tokenstr>='0' && *tokenstr<='9') || *tokenstr=='.' || *tokenstr=='-' || *tokenstr=='+')) {
    tokenw=0;
    tokenb=10;
    decimal:
    i=tokenw;
    if(i<tokenlen && (tokenstr[i]=='-' || tokenstr[i]=='+')) i++;
    for(;i<tokenlen && tokenstr[i]>='0' && tokenstr[i]<='9';i++);
    if(i!=tokenlen && tokenstr[i]=='.') {
      for(i++;i<tokenlen && tokenstr[i]>='0' && tokenstr[i]<='9';i++);
    }
    if(i!=tokenlen && (tokenstr[i]=='e') || (tokenstr[i]=='E')) {
      i++;
      if(i<tokenlen && (tokenstr[i]=='-' || tokenstr[i]=='+')) i++;
      for(;i<tokenlen && tokenstr[i]>='0' && tokenstr[i]<='9';i++);
      if(i==tokenlen) ReturnT(TOK_REAL);
    }
  }
  // No match
  errx(1,"Improper token");
}

static int nexttok(void) {
  int c;
  tokenlen=0;
  again:
  c=getchar();
  if(c==' ' || c=='\t' || c=='\r' || c=='\n' || c=='\f') goto again;
  if(c==EOF) ReturnT(TOK_EOF);
  switch(c) {
    case '%':
      for(;;) {
        c=getchar();
        if(c==EOF) ReturnT(TOK_EOF);
        if(c=='\r' || c=='\n' || c=='\f') goto again;
      }
      break;
    case '{': ReturnT(TOK_BRACE_BEGIN);
    case '}':
      c=getchar();
      if(c=='>') ReturnT(TOK_EXT_END);
      if(c!=EOF) ungetc(c,stdin);
      ReturnT(TOK_BRACE_END);
    case '[': ReturnT(TOK_SEQ_BEGIN);
    case ']':
      c=getchar();
      if(c=='>') ReturnT(TOK_SET_END);
      if(c!=EOF) ungetc(c,stdin);
      ReturnT(TOK_SEQ_END);
    case '<':
      c=getchar();
      if(c=='<') ReturnT(TOK_KV_BEGIN);
      if(c=='[') ReturnT(TOK_SET_BEGIN);
      if(c=='{') ReturnT(TOK_EXT_BEGIN);
      if(c=='+') ReturnT(TOK_START_BIT_STRING);
      if(c=='=') ReturnT(TOK_START_BASE64_STRING);
      if(c!=EOF) ungetc(c,stdin);
      ReturnT(TOK_START_HEX_STRING);
    case '>':
      c=getchar();
      if(c=='>') ReturnT(TOK_KV_END); else errx(1,"Improper token");
    case '(': ReturnTW(TOK_START_TEXT_STRING,ASN1_IA5STRING);
    case '~': ReturnT(TOK_WRAP);
    case '=': ReturnT(TOK_EQUAL);
    case '#': case '0' ... '9': case '-': case '+': case '.':
    case 'a' ... 'z': case 'A' ... 'Z': case '_':
      word:
      if(tokenlen==TOKENMAX) errx(1,"Too long word");
      tokenstr[tokenlen++]=c;
      c=getchar();
      if(c==EOF) goto eofword;
      if(c&~127) errx(1,"Improper character");
      if(wordch[c]==2 && wordch[*tokenstr]==3) goto endword;
      if(wordch[c]==2 && tokenlen>1 && *tokenstr=='.' && wordch[tokenstr[1]]==3) goto endword;
      if(wordch[c]) goto word;
      endword:
      ungetc(c,stdin);
      eofword:
      tokenstr[tokenlen]=0;
      return wordtok(c==':');
    default: errx(1,"Improper character");
  }
}

static void do_hex_string(void) {
  FILE*f=asn1_primitive_stream(enc,ASN1_UNIVERSAL,ASN1_OCTET_STRING);
  int c,v;
  if(!f) errx(1,"Unexpected error");
  for(;;) {
    switch(c=getchar()) {
      case EOF: errx(1,"Unexpected end of file"); break;
      case ' ': case '\t': case '\f': case '\r': case '\n': /* do nothing */ break;
      case '0' ... '9': case 'A' ... 'F': case 'a' ... 'f':
        v=((c&15)+(c>='A'?9:0))<<4;
        c=getchar();
        if(c>='0' && c<='9') v+=c-'0';
        else if(c>='A' && c<='F') v+=c+10-'A';
        else if(c>='a' && c<='f') v+=c+10-'a';
        else errx(1,"Improper hex character in hex string");
        fputc(v,f);
        break;
      case '>': asn1_end(enc); return;
      case '%':
        while(c=getchar()) if(c=='\r' || c=='\n' || c=='\f' || c==EOF) break;
        break;
      default: errx(1,"Unexpected character in hex string");
    }
  }
}

static void do_base64_string(void) {
  static int8_t b64[128]={
    [0 ... 127]=-1,
    ['A']=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
    ['a']=26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,
    ['0']=52,53,54,55,56,57,58,59,60,61,
    ['+']=62, ['/']=63,
    ['-']=62, [',']=63, ['_']=63,
  };
  FILE*f=asn1_primitive_stream(enc,ASN1_UNIVERSAL,ASN1_OCTET_STRING);
  uint32_t v=0;
  int b,c;
  if(!f) errx(1,"Unexpected error");
  for(b=0;;) {
    switch(c=getchar()) {
      case EOF: errx(1,"Unexpected end of file"); break;
      case ' ': case '\t': case '\f': case '\r': case '\n': /* do nothing */ break;
      case '=':
        if(b) {
          fputc(v>>16,f);
          if(b==1) errx(1,"Improper length of base64 string");
          if(b==3) fputc(v>>8,f);
        }
        while(c=getchar()) {
          if(c=='>') break;
          if(c!='=' && c!=' ' && c!='\r' && c!='\n' && c!='\f' && c!='\t') errx(1,"Improper character in base64 string");
        }
        asn1_end(enc);
        return;
      case '%':
        while(c=getchar()) if(c=='\r' || c=='\n' || c=='\f' || c==EOF) break;
        break;
      default:
        if((c&~127) || b64[c]<0) errx(1,"Improper character in base64 string");
        v|=b64[c]<<(18-6*b++);
        if(b==4) {
          fputc(v>>16,f);
          fputc(v>>8,f);
          fputc(v>>0,f);
          b=0;
          v=0;
        }
        break;
    }
  }
}

static void send_unicode(FILE*f,uint32_t t,uint32_t v) {
  switch(t) {
    case ASN1_UTF8_STRING:
      if(v<0x80) {
        fputc(v,f);
      } else if(v<0x800) {
        fputc((v>>6)+0xC0,f);
        fputc(((v>>0)&0x3F)+0x80,f);
      } else if(v<0x10000) {
        fputc((v>>12)+0xE0,f);
        fputc(((v>>6)&0x3F)+0x80,f);
        fputc(((v>>0)&0x3F)+0x80,f);
      } else if(v<0x200000) {
        fputc((v>>18)+0xF0,f);
        fputc(((v>>12)&0x3F)+0x80,f);
        fputc(((v>>6)&0x3F)+0x80,f);
        fputc(((v>>0)&0x3F)+0x80,f);
      } else if(v<0x4000000) {
        fputc((v>>24)+0xF8,f);
        fputc(((v>>18)&0x3F)+0x80,f);
        fputc(((v>>12)&0x3F)+0x80,f);
        fputc(((v>>6)&0x3F)+0x80,f);
        fputc(((v>>0)&0x3F)+0x80,f);
      } else if(v<0x80000000U) {
        fputc((v>>30)+0xFC,f);
        fputc(((v>>24)&0x3F)+0x80,f);
        fputc(((v>>18)&0x3F)+0x80,f);
        fputc(((v>>12)&0x3F)+0x80,f);
        fputc(((v>>6)&0x3F)+0x80,f);
        fputc(((v>>0)&0x3F)+0x80,f);
      } else {
        errx(1,"Unicode character out of range");
      }
      break;
    case ASN1_UTF16_STRING:
      if(v<0x10000) {
        fputc(v>>8,f);
        fputc(v>>0,f);
      } else if(v<0x110000) {
        v-=0x10000;
        fputc(((v>>18)&3)+0xD8,f);
        fputc(v>>10,f);
        fputc(((v>>8)&3)+0xDC,f);
        fputc(v>>0,f);
      } else {
        errx(1,"Unicode character out of range");
      }
      break;
    case ASN1_UNIVERSAL_STRING:
      fputc(v>>24,f);
      fputc(v>>16,f);
      fputc(v>>8,f);
      fputc(v>>0,f);
      break;
    default: errx(1,"Unicode characters are not allowed in non-Unicode strings");
  }
}

static void do_relative_oid(void) {
  uint8_t buf[257];
  ASN1 x;
  memmove(tokenstr+1,tokenstr,++tokenlen);
  *tokenstr=tokenstr[2]='0';
  if(asn1_make_static_oid(tokenstr,buf,257,&x)) errx(1,"Unexpected error");
  asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_RELATIVE_OID,x.data+1,x.length-1);
}

static void do_text_string(uint32_t type) {
  // ISO 2022 is not fully handled yet, but it is usable
  const char bcd[]="0123456789*#+-. ";
  const char printable[128]={
    [32]=1, [65 ... 90]=1, [97 ... 122]=1, [48 ... 57]=1,
    [39 ... 41]=1, [43 ... 47]=1, [58]=1, [61]=1, [63]=1,
  };
  const char*p;
  FILE*f=asn1_primitive_stream(enc,ASN1_UNIVERSAL,type);
  uint16_t g0=0;
  uint16_t g1;
  uint8_t bc=0;
  uint32_t nest=0;
  uint32_t cc;
  int c;
  if(!f) errx(1,"Unexpected error");
  for(;;) {
    c=getchar();
    if(c<32 || c>126) errx(1,"Unexpected literal character in text string");
    if(c==40) ++nest;
    if(c==41 && !nest--) break;
    if(c!='\\') {
      normal:
      switch(type) {
        case ASN1_BCD_STRING:
          p=strchr(bcd,c);
          if(!p) errx(1,"Improper character in BCD string");
          if(g0) {
            g0=0;
            fputc(bc|(p-bcd),f);
            bc=0;
          } else {
            g0=1;
            bc=(p-bcd)<<4;
          }
          break;
        case ASN1_TRON_STRING:
          // TODO: implement ASCII -> TRON
          if(c<=32 || c==127) fputc(c,f); else errx(1,"Improper character in TRON string");
          break;
        case ASN1_NUMERIC_STRING:
          if((c<'0' || c>'9') && c!=' ') errx(1,"Improper character in numeric string");
          goto direct;
        case ASN1_PRINTABLE_STRING:
          if(!printable[c]) errx(1,"Improper character in printable string");
          goto direct;
        case ASN1_VISIBLE_STRING:
          if(c<32 || c>126) errx(1,"Improper character in visible string");
          goto direct;
        case ASN1_BMP_STRING: fputc(0,f); fputc(c,f); break;
        case ASN1_UNIVERSAL_STRING: fputc(0,f); fputc(0,f); fputc(0,f); fputc(c,f); break;
        default: direct: fputc(c,f);
      }
    } else {
      switch(c=getchar()) {
        case '(': case ')': case '\\': goto normal;
        case 'a': c='\a'; goto normal;
        case 'b': c='\b'; goto normal;
        case 'e': c='\e'; goto normal;
        case 'f': c='\f'; goto normal;
        case 'n': c='\n'; goto normal;
        case 'r': c='\r'; goto normal;
        case 't': c='\t'; goto normal;
        case 'u':
          c=getchar();
          if(c>='0' && c<='9') cc=c-'0'; else if(c>='A' && c<='F') cc=c+10-'A'; else if(c>='a' && c<='f') cc=c+10-'a'; else errx(1,"Improper escape sequence");
          cc<<=4;
          c=getchar();
          if(c>='0' && c<='9') cc|=c-'0'; else if(c>='A' && c<='F') cc|=c+10-'A'; else if(c>='a' && c<='f') cc|=c+10-'a'; else errx(1,"Improper escape sequence");
          cc<<=4;
          c=getchar();
          if(c>='0' && c<='9') cc|=c-'0'; else if(c>='A' && c<='F') cc|=c+10-'A'; else if(c>='a' && c<='f') cc|=c+10-'a'; else errx(1,"Improper escape sequence");
          cc<<=4;
          c=getchar();
          if(c>='0' && c<='9') cc|=c-'0'; else if(c>='A' && c<='F') cc|=c+10-'A'; else if(c>='a' && c<='f') cc|=c+10-'a'; else errx(1,"Improper escape sequence");
          send_unicode(f,type,cc);
          break;
        case 'v': c='\v'; goto normal;
        case 'x':
          if(type==ASN1_BCD_STRING || type==ASN1_BMP_STRING || type==ASN1_UNIVERSAL_STRING) errx(1,"Cannot use \\x in BCD string, BMP string, Universal string");
          c=getchar();
          if(c>='0' && c<='9') cc=c-'0'; else if(c>='A' && c<='F') cc=c+10-'A'; else if(c>='a' && c<='f') cc=c+10-'a'; else errx(1,"Improper escape sequence");
          cc<<=4;
          c=getchar();
          if(c>='0' && c<='9') cc|=c-'0'; else if(c>='A' && c<='F') cc|=c+10-'A'; else if(c>='a' && c<='f') cc|=c+10-'a'; else errx(1,"Improper escape sequence");
          c=cc;
          goto normal;
        case 'T':
          if(type!=ASN1_TRON_STRING) errx(1,"Cannot use \\T in non-TRON strings");
          c=getchar();
          if(c>='0' && c<='9') cc=c-'0'; else if(c>='A' && c<='F') cc=c+10-'A'; else if(c>='a' && c<='f') cc=c+10-'a'; else errx(1,"Improper escape sequence");
          for(;;) {
            c=getchar();
            if(c==';') break;
            if(cc&0xF0000000L) errx(1,"Too long escape sequence");
            cc<<=4;
            if(c>='0' && c<='9') cc|=c-'0'; else if(c>='A' && c<='F') cc|=c+10-'A'; else if(c>='a' && c<='f') cc|=c+10-'a'; else errx(1,"Improper escape sequence");
          }
          if(cc<=0x20 || cc==0x7F) {
            fputc(cc,f);
          } else {
            if(cc>0xFFFF && g0!=(cc>>16)) {
              g0=cc>>16;
              if((g0&0xFF)==0x7F || (g0&0xFF)<0x21 || (g0&0xFF)>0xFD) errx(1,"Improper TRON character");
              g1=(g0>>8)+1;
              while(g1--) fputc(0xFE,f);
              fputc(g0,f);
            }
            if((cc&0xFF)==0x7F || (cc&0xFF)<0x21 || (cc&0xFF)>0xFD) errx(1,"Improper TRON character");
            if(((cc>>8)&0xFF)==0x7F || ((cc>>8)&0xFF)<0x21 || ((cc>>8)&0xFF)>0xFD) errx(1,"Improper TRON character");
            fputc(cc>>8,f);
            fputc(cc>>0,f);
          }
          break;
        case 'U':
          c=getchar();
          if(c>='0' && c<='9') cc=c-'0'; else if(c>='A' && c<='F') cc=c+10-'A'; else if(c>='a' && c<='f') cc=c+10-'a'; else errx(1,"Improper escape sequence");
          for(;;) {
            c=getchar();
            if(c==';') break;
            if(cc&0xF0000000L) errx(1,"Too long escape sequence");
            cc<<=4;
            if(c>='0' && c<='9') cc|=c-'0'; else if(c>='A' && c<='F') cc|=c+10-'A'; else if(c>='a' && c<='f') cc|=c+10-'a'; else errx(1,"Improper escape sequence");
          }
          send_unicode(f,type,cc);
          break;
        case 'Z': /* not implemented */ break;
        case ' ': case '\t': case '\r': case '\n':
          for(;;) {
            c=getchar();
            if(c==';') break;
            if(c!=' ' && c!='\t' && c!='\r' && c!='\n') errx(1,"Improper escape sequence");
          }
          break;
        case ';': /* do nothing */ break;
        default: errx(1,"Improper escape sequence");
      }
    }
  }
  if(type==ASN1_BCD_STRING && g0) fputc(bc+15,f);
  asn1_end(enc);
}

static int prefix_compare(const void*a,const void*b) {
  const Prefix*x=a;
  const Prefix*y=b;
  return strcmp(x->name,y->name);
}

static void do_prefixed(void) {
  Prefix key={tokenstr};
  Prefix*item;
  uint8_t type;
  int c,i;
  item=bsearch(&key,prefix,sizeof(prefix)/sizeof(*prefix),sizeof(Prefix),prefix_compare);
  if(!item) errx(1,"Unrecognized prefix");
  type=item->type;
  if(type==ASN1_BIT_STRING) {
    uint8_t*buf=malloc(1);
    size_t len=0;
    char un=0;
    if(!buf) err(1,"Allocation failed");
    if(nexttok()!=TOK_BRACE_BEGIN) errx(1,"Unexpected token");
    for(;;) {
      nexttok();
      if(tokent==TOK_BRACE_END) break;
      if(tokent!=TOK_INTEGER) errx(1,"Expected nonnegative integer or end of block");
      i=strtol(tokenstr+tokenw,0,tokenb);
      if(i<0) err(1,"Expected nonnegative integer or end of block");
      if(len<i/8+1) {
        buf=realloc(buf,i/8+2);
        if(!buf) err(1,"Allocation failed");
        while(len<i/8+1) buf[++len]=0;
        un=7;
      }
      if(len==i/8+1 && un>(7&~i)) un=7&~i;
      buf[i/8+1]|=0x80>>(i&7);
    }
    *buf=un;
    asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_BIT_STRING,buf,len+1);
    free(buf);
    return;
  }
  if(type==250 || type==ASN1_UTCTIME || type==ASN1_GENERALIZED_TIME || type==ASN1_UTC_TIMESTAMP) i=1; else i=0;
  for(;;) {
    c=getchar();
    if(c==EOF) errx(1,"Unexpected end of file");
    if((c==40 || c=='<') && !i) {
      break;
    } else if(i && (c>='0' && c<='9')) {
      break;
    } else if(c=='%') {
      while(c=getchar()) if(c=='\r' || c=='\n' || c=='\f' || c==EOF) break;
    } else {
      errx(1,"Improper use of prefix");
    }
  }
  if(c=='<') {
    asn1_implicit(enc,ASN1_UNIVERSAL,type);
    ungetc(c,stdin);
    nexttok();
    if(tokent==TOK_START_HEX_STRING) {
      do_hex_string();
    } else if(tokent==TOK_START_BASE64_STRING) {
      do_base64_string();
    } else {
      errx(1,"Improper use of prefix");
    }
  } else if(i) {
    // Date/time types
    ASN1_DateTime d={};
    ungetc(c,stdin);
    for(tokenlen=0;;) {
      c=getchar();
      if(tokenlen==64) errx(1,"Too long date/time format");
      if(c==EOF) errx(1,"Unexpected end of file");
      if(c<43 || c>90 || (c>58 && c<65) || c=='/') {
        ungetc(c,stdin);
        break;
      }
      tokenstr[tokenlen++]=c;
    }
    tokenstr[tokenlen]=0;
    for(c=i=0;i<tokenlen;i++) {
      if(tokenstr[i]>='0' && tokenstr[i]<='9') c++;
      if(i>10 && (tokenstr[i]=='+' || tokenstr[i]=='-')) break; // time zones
    }
    if(*tokenstr<'0' && *tokenstr>'9' && type!=ASN1_UTC_TIMESTAMP) errx(1,"BC and AD beyond 9999 is not supported");
    if(c<10) errx(1,"Too short date/time format (%d)",c);
    if(type==250) {
      if(c==10 || c==12) type=ASN1_UTCTIME; else type=ASN1_GENERALIZEDTIME;
    } else if(type==ASN1_UTCTIME && c>12) {
      errx(1,"Cannot use UTCTime type with year numbers longer than two digits");
    }
    if(type==ASN1_UTCTIME) {
      // Short year
      if((tokenstr[0]<'0' || tokenstr[0]>'9') || (tokenstr[1]<'0' || tokenstr[1]>'9')) errx(1,"Improper date/time format");
      d.year=tokenstr[0]*10+tokenstr[1]+1472;
      if(d.year>2049) d.year-=100;
      i=2;
    } else if(type==ASN1_UTC_TIMESTAMP && *tokenstr<'0') {
      // Long year
      for(i=1;i<tokenlen && tokenstr[i]!='-';i++) {
        if(tokenstr[i]<'0' || tokenstr[i]>'9') errx(1,"Improper date/time format");
        if(d.year>3275) errx(1,"Too long year number");
        d.year=10*d.year+tokenstr[i]-'0';
      }
      if(*tokenstr=='-') d.year*=-1;
      i++;
    } else {
      // Normal year
      for(i=0;i<4;i++) {
        if(tokenstr[i]<'0' || tokenstr[i]>'9') errx(1,"Improper date/time format");
        d.year=10*d.year+tokenstr[i]-'0';
      }
    }
    // Month
    if(tokenstr[i]=='-') i++;
    if((tokenstr[i]<'0' || tokenstr[i]>'1') || (tokenstr[i+1]<'0' || tokenstr[i+1]>'9')) errx(1,"Improper date/time format");
    d.month=tokenstr[i]*10+tokenstr[i+1]-528;
    i+=2;
    // Day
    if(tokenstr[i]=='-') i++;
    if((tokenstr[i]<'0' || tokenstr[i]>'3') || (tokenstr[i+1]<'0' || tokenstr[i+1]>'9')) errx(1,"Improper date/time format");
    d.day=tokenstr[i]*10+tokenstr[i+1]-528;
    i+=2;
    // Hours
    if(tokenstr[i]=='T') i++;
    if((tokenstr[i]<'0' || tokenstr[i]>'2') || (tokenstr[i+1]<'0' || tokenstr[i+1]>'9')) errx(1,"Improper date/time format");
    d.hours=tokenstr[i]*10+tokenstr[i+1]-528;
    i+=2;
    // Minutes
    if(tokenstr[i]==':') i++;
    if((tokenstr[i]<'0' || tokenstr[i]>'5') || (tokenstr[i+1]<'0' || tokenstr[i+1]>'9')) errx(1,"Improper date/time format");
    d.minutes=tokenstr[i]*10+tokenstr[i+1]-528;
    i+=2;
    // Seconds
    if(tokenstr[i]==':') i++;
    if((tokenstr[i]<'0' || tokenstr[i]>'6') || (tokenstr[i+1]<'0' || tokenstr[i+1]>'9')) errx(1,"Improper date/time format");
    d.seconds=tokenstr[i]*10+tokenstr[i+1]-528;
    i+=2;
    // Nanoseconds
    d.nano=0;
    if(type!=ASN1_UTCTIME && (tokenstr[i]=='.' || tokenstr[i]==',')) {
      uint32_t o=1000000000;
      i++;
      while(tokenstr[i]>='0' && tokenstr[i]<='9') d.nano+=(tokenstr[i++]-'0')*(o/=10);
    }
    // Time zone
    if(tokenstr[i]=='Z' && !tokenstr[i+1]) {
      d.zone=0;
    } else if((tokenstr[i]=='+' || tokenstr[i]=='-') && tokenlen==i+5) {
      if((tokenstr[i+1]<'0' || tokenstr[i+1]>'2') || (tokenstr[i+2]<'0' || tokenstr[i+2]>'9')) errx(1,"Improper date/time format");
      if((tokenstr[i+3]<'0' || tokenstr[i+3]>'5') || (tokenstr[i+4]<'0' || tokenstr[i+4]>'9')) errx(1,"Improper date/time format");
      d.zone=tokenstr[i+3]*10+tokenstr[i+4]-528;
      d.zone+=(tokenstr[i+1]*10+tokenstr[i+2]-528)*60;
      if(tokenstr[i]=='-') d.zone*=-1;
    } else {
      errx(1,"Improper time zone (%s)",tokenstr+i);
    }
    if(asn1_encode_date(enc,type,&d)) errx(1,"Cannot encode date/time");
  } else {
    do_text_string(type);
  }
}

static void do_one_item(void) {
  char imp=0;
  int i;
  again: switch(tokent) {
    case TOK_SEQ_BEGIN:
      asn1_construct(enc,ASN1_UNIVERSAL,ASN1_SEQUENCE,0);
      while(nexttok()!=TOK_SEQ_END) do_one_item();
      asn1_end(enc);
      break;
    case TOK_SET_BEGIN:
      asn1_construct(enc,ASN1_UNIVERSAL,ASN1_SET,ASN1_SORT);
      while(nexttok()!=TOK_SET_END) do_one_item();
      asn1_end(enc);
      break;
    case TOK_KV_BEGIN:
      asn1_construct(enc,ASN1_UNIVERSAL,ASN1_KEY_VALUE_LIST,ASN1_KVSORT);
      while(nexttok()!=TOK_KV_END) do_one_item();
      asn1_end(enc);
      break;
    case TOK_WRAP:
      asn1_wrap(enc);
      nexttok(); goto again;
    case TOK_IMPLICIT:
      imp=1;
      asn1_implicit(enc,tokenb,tokenw);
      nexttok(); goto again;
    case TOK_SPECIAL_0:
      asn1_primitive(enc,ASN1_UNIVERSAL,tokenw,"",0);
      break;
    case TOK_SPECIAL_1:
      asn1_primitive(enc,ASN1_UNIVERSAL,tokenw,&tokenb,1);
      break;
    case TOK_OID:
      asn1_encode_oid(enc,tokenstr);
      break;
    case TOK_RELATIVE_OID:
      do_relative_oid();
      break;
    case TOK_INTEGER:
      i=1;
      if(tokenstr[tokenw]=='+') tokenw++; else if(tokenstr[tokenw]=='-') i=-1,tokenw++;
      asn1_encode_integer_base(enc,tokenb,tokenstr+tokenw,tokenlen-tokenw,i,1);
      break;
    case TOK_START_HEX_STRING:
      do_hex_string();
      break;
    case TOK_START_BASE64_STRING:
      do_base64_string();
      break;
    case TOK_START_TEXT_STRING:
      do_text_string(imp?ASN1_OCTET_STRING:ASN1_IA5_STRING);
      break;
    case TOK_PREFIX:
      do_prefixed();
      break;
    default: errx(1,"Wrong token in this context");
  }
}

int main(int argc,char**argv) {
  enc=asn1_create_encoder(stdout);
  if(!enc) errx(1,"Unexpected error");
  nexttok();
  do_one_item();
  if(nexttok()) errx(1,"Expected end of file");
  asn1_finish_encoder(enc);
  return 0;
}

