#if 0
gcc -g -O0 -o ./tertoder tertoder.c asn1.o -ldl -rdynamic
exit
#endif

#include <dlfcn.h>
#include <err.h>
#include <search.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
  TOK_ASTERISK,
  TOK_DEFAULT,
  TOK_QUESTION,
  TOK_NAME,
  TOK_PREFIX,
  TOK_IMPLICIT,
  TOK_SPECIAL_0,
  TOK_SPECIAL_1,
  TOK_INTEGER,
  TOK_REAL,
  TOK_OID,
  TOK_RELATIVE_OID,
  TOK_FIELD,
  TOK_FUNCTION,
  TOK_START_BIT_STRING,
  TOK_START_HEX_STRING,
  TOK_START_BASE64_STRING,
  TOK_START_TEXT_STRING,
};

enum {
  OP_END,
  OP_OF,
  OP_TYPE,
  OP_VMIN,
  OP_VMAX,
  OP_SMIN,
  OP_SMAX,
  OP_FIELD,
  OP_MULTI,
  OP_IMPLICIT,
  OP_WRAP,
  OP_BEGIN_SEQUENCE,
  OP_BEGIN_SET,
  OP_END_CONSTRUCT,
  OP_DEFAULT,
  OP_FUNCTION,
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
  {"DOUBLE",ASN1_REAL},
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
  {"SINGLE",ASN1_REAL},
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

typedef struct Field Field;
typedef struct Schema Schema;

enum {
  NK_UNDEF,
  NK_OBJECT,
  NK_FIELD,
  NK_SCHEMA,
  NK_BUSY,
  NK_FUNCTION,
  NK_EXTENSION,
};

typedef struct {
  const char*name;
  uint8_t kind;
  union {
    // NK_OBJECT
    struct {
      uint8_t*oid;
      size_t oidlen;
    };
    // NK_SCHEMA
    Schema*schema;
    // NK_FUNCTION
    struct {
      int(*call)(ASN1_Encoder*enc,const ASN1*values,int nvalues,const uint8_t*data,size_t length,void*userdata);
      void*userdata;
      uint32_t option;
    };
    // NK_EXTENSION
    void*handle;
  };
} Name;

#define FF_OPTIONAL 0x01
#define FF_CONSTRAINT 0x02
#define FF_NAMED 0x04
#define FF_DEFAULT 0x08
#define FF_VALUE 0x10
#define FF_MULTI 0x20

struct Field {
  union {
    Name*fname;
    uint16_t fnumber;
  };
  Name*xname;
  uint32_t constraint;
  uint32_t value;
  uint32_t im_type;
  uint8_t im_class;
  uint8_t stringtype;
  uint8_t flag;
};

struct Schema {
  uint8_t type; // ASN1_ENUMERATED, ASN1_SEQUENCE, ASN1_KEY_VALUE_LIST
  Field*fields;
  uint16_t nfields;
  uint8_t*constraint;
  uint8_t*program;
  size_t length;
  const Name*function;
};

#define TOKENMAX 8000
static ASN1_Encoder*enc;
static int tokent;
static uint8_t tokenb;
static int64_t tokenv;
static uint32_t tokenw;
static uint8_t tokenstr[(TOKENMAX)+4];
static int tokenlen;
static void*names;
static char repeattoken;
static char debugschema;
static char debugtokens;

#define ReturnT(x) do{ if(debugtokens) fprintf(stderr,"t=%d (b=%d w=%lu)\n",x,tokenb,(unsigned long)tokenw); return tokent=x; }while(0)
#define ReturnTB(x,y) do{ tokenb=y; if(debugtokens) fprintf(stderr,"t=%d b=%d (w=%lu)\n",x,tokenb,(unsigned long)tokenw); return tokent=x; }while(0)
#define ReturnTV(x,y) do{ tokenv=y; if(debugtokens) fprintf(stderr,"t=%d v=%lld (b=%d w=%lu)\n",x,(long long)tokenv,tokenb,(unsigned long)tokenw); return tokent=x; }while(0)
#define ReturnTW(x,y) do{ tokenw=y; if(debugtokens) fprintf(stderr,"t=%d w=%lu (b=%d)\n",x,(unsigned long)tokenw,tokenb); return tokent=x; }while(0)
#define ReturnTBW(x,y,z) do{ tokenb=y; tokenw=z; if(debugtokens) fprintf(stderr,"t=%d b=%d w=%lu\n",x,tokenb,(unsigned long)tokenw); return tokent=x; }while(0)

static int funct_b(ASN1_Encoder*enc,const ASN1*values,int nvalues,const uint8_t*data,size_t length,void*userdata) {
  uint8_t*buf=malloc(1);
  size_t len=0;
  char un=0;
  uint16_t i;
  int n;
  if(!buf) err(1,"Allocation failed");
  for(n=0;n<nvalues;n++) {
    if(values[n].class) goto wrong;
    if(values[n].type==ASN1_INTEGER) {
      if(asn1_decode_number(values+n,0,&i)) goto wrong;
      if(len<i/8+1) {
        buf=realloc(buf,i/8+2);
        if(!buf) err(1,"Allocation failed");
        while(len<i/8+1) buf[++len]=0;
        un=7;
      }
      if(len==i/8+1 && un>(7&~i)) un=7&~i;
      buf[i/8+1]|=0x80>>(i&7);
    } else if(values[n].type==ASN1_BIT_STRING && values[n].length) {
      if(values[n].length-1>len) {
        i=values[n].length-1;
        buf=realloc(buf,i+1);
        if(!buf) err(1,"Allocation failed");
        while(len<i) buf[++len]=0;
        un=values[n].data[0];
      } else if(values[n].length-1==len && un>values[n].data[0]) {
        un=values[n].data[0];
      }
      for(i=1;i<values[n].length;i++) buf[i]|=values[n].data[i];
    } else if(values[n].type) {
      wrong:
      free(buf);
      return 1;
    }
  }
  *buf=un;
  asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_BIT_STRING,buf,len+1);
  free(buf);
  return 0;
}

static int funct_e(ASN1_Encoder*enc,const ASN1*values,int nvalues,const uint8_t*data,size_t length,void*userdata) {
  int n;
  for(n=0;n<nvalues;n++) if(values[n].class || values[n].type) {
    asn1_explicit(enc,ASN1_CONTEXT_SPECIFIC,n);
    asn1_encode(enc,values+n);
    return 0;
  }
  asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_NULL,"",0);
  return 0;
}

static int funct_i(ASN1_Encoder*enc,const ASN1*values,int nvalues,const uint8_t*data,size_t length,void*userdata) {
  int n;
  for(n=0;n<nvalues;n++) if(values[n].class || values[n].type) {
    asn1_implicit(enc,ASN1_CONTEXT_SPECIFIC,n);
    asn1_encode(enc,values+n);
    return 0;
  }
  asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_NULL,"",0);
  return 0;
}

static const Name builtins[26]={
  ['B'-'A']={.name="$B",.kind=NK_FUNCTION,.call=funct_b,.option=0},
  ['E'-'A']={.name="$E",.kind=NK_FUNCTION,.call=funct_e,.option=0},
  ['I'-'A']={.name="$I",.kind=NK_FUNCTION,.call=funct_i,.option=0},
};

static void do_one_item(void);

static int name_compare(const void*a,const void*b) {
  const Name*x=a;
  const Name*y=b;
  return strcmp(x->name,y->name);
}

static Name*find_name(void) {
  Name key={tokenstr,NK_UNDEF};
  Name**nam=tsearch(&key,&names,name_compare);
  if(!nam) errx(1,"Memory error");
  if(*nam==&key) {
    *nam=calloc(1,sizeof(Name));
    if(!*nam) errx(1,"Memory error");
    (*nam)->name=strdup(tokenstr);
    if(!(*nam)->name) errx(1,"Memory error");
  }
  return *nam;
}

static const char wordch[128]={
  ['#']=2, ['0' ... '9']=1, ['-']=1, ['+']=2, ['.']=2,
  ['a' ... 'z']=3, ['A' ... 'Z']=3, ['_']=3,
};

static int wordtok(int colon) {
  int i,j;
  if(debugtokens) fprintf(stderr,"Token \"%s\"\n",tokenstr);
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
        for(i=tokenw;i<tokenlen;i++) if(tokenstr[i]=='E' || tokenstr[i]=='.') goto decimal;
      } else if(tokenb==2 || tokenb==4 || tokenb==8 || tokenb==16) {
        for(i=tokenw;i<tokenlen;i++) if(tokenstr[i]=='P' || tokenstr[i]=='.') break;
        j=0;
        if(i!=tokenlen) {
          i=(tokenstr[tokenw]=='-' || tokenstr[tokenw]=='+')?(j=1,tokenw+1):tokenw;
          for(;i<tokenlen && ((tokenstr[i]>='0' && tokenstr[i]<='9' && tokenstr[i]<tokenb+'0') || (tokenstr[i]>='A' && tokenstr[i]<'A'+tokenb-10));i++);
          if(i!=tokenlen && tokenstr[i]=='.') {
            j=1;
            for(i++;i<tokenlen && ((tokenstr[i]>='0' && tokenstr[i]<='9' && tokenstr[i]<tokenb+'0') || (tokenstr[i]>='A' && tokenstr[i]<'A'+tokenb-10));i++);
          }
          if(i!=tokenlen && tokenstr[i]=='P') {
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
    j=!!i;
    if(i<tokenlen && (tokenstr[i]=='-' || tokenstr[i]=='+')) i++,j++;
    for(;i<tokenlen && tokenstr[i]>='0' && tokenstr[i]<='9';i++);
    if(i!=tokenlen && tokenstr[i]=='.') {
      for(i++;i<tokenlen && tokenstr[i]>='0' && tokenstr[i]<='9';i++);
    }
    if(i!=tokenlen && (tokenstr[i]=='e' || tokenstr[i]=='E')) {
      i++,j++;
      if(i<tokenlen && (tokenstr[i]=='-' || tokenstr[i]=='+')) i++;
      for(;i<tokenlen && tokenstr[i]>='0' && tokenstr[i]<='9';i++);
    }
    if(j && i==tokenlen) ReturnT(TOK_REAL);
  }
  // No match
  errx(1,"Improper token: %s",tokenstr);
}

static int nexttok(void) {
  int c;
  if(repeattoken) {
    if(debugtokens) fprintf(stderr,"(Repeated token)\n");
    repeattoken=0;
    return tokent;
  }
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
      if(c==EOF) errx(1,"Unexpected end of file");
      ungetc(c,stdin);
      ReturnT(TOK_START_HEX_STRING);
    case '>':
      c=getchar();
      if(c=='>') ReturnT(TOK_KV_END); else errx(1,"Improper token");
    case '(': ReturnTW(TOK_START_TEXT_STRING,ASN1_IA5STRING);
    case '~': ReturnT(TOK_WRAP);
    case '=': ReturnT(TOK_EQUAL);
    case '*': ReturnT(TOK_ASTERISK);
    case '^': ReturnT(TOK_DEFAULT);
    case '?': ReturnT(TOK_QUESTION);
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
    case '$':
      tokenw=0;
      c=getchar();
      if(c>='A' && c<='Z') ReturnTB(TOK_FUNCTION,c);
      if(c<'0' || c>'9') errx(1,"Improper token");
      for(;;) {
        if(c<'0' || c>'9') break;
        if(++tokenlen>6 || tokenw>6553) errx(1,"Improper field number");
        tokenw=10*tokenw+c-'0';
        c=getchar();
      }
      if(tokenw>65535 || !tokenlen) errx(1,"Improper field number");
      if(c!=EOF) ungetc(c,stdin);
      ReturnT(TOK_FIELD);
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

static void do_bit_string(void) {
  uint8_t*buf=0;
  size_t len=0;
  uint8_t cur=0;
  uint8_t sh=0;
  uint8_t bs=1;
  char ok=0;
  int c,d;
  FILE*f=open_memstream((char**)&buf,&len);
  if(!f) errx(1,"Unexpected error");
  fputc(0,f); // will be changed later
  for(;;) {
    switch(c=getchar()) {
      case EOF: errx(1,"Unexpected end of file"); break;
      case ' ': case '\t': case '\f': case '\r': case '\n': /* do nothing */ break;
      case 'A' ... 'F': c+=10-'A'; goto digit;
      case 'a' ... 'f': c+=10-'a'; goto digit;
      case '0' ... '9':
        c-='0';
        digit:
        if(c>1 && bs==1 && !ok) {
          if(getchar()!='#') {
            goto bad;
          } else if(c==6 && cur==0x80 && sh==7) {
            bs=4;
            cur=sh=0;
            ok=1;
          } else if(cur || sh) {
            goto bad;
          } else if(c==2 || c==4 || c==8) {
            bs=c/3+1;
            ok=1;
          } else {
            goto bad;
          }
        } else if(c>=(1<<bs)) {
          bad: errx(1,"Improper digit in bit string");
        } else {
          if(cur || sh || !c) ok=1;
          for(d=bs;d;) {
            cur|=(1&(c>>--d))<<(sh=(sh-1)&7);
            if(!sh) fputc(cur,f),cur=0;
          }
        }
        break;
      case '+':
        if(getchar()!='>') errx(1,"Improper character in bit string");
        goto end;
      case '%':
        while(c=getchar()) if(c=='\r' || c=='\n' || c=='\f' || c==EOF) break;
        break;
      default: errx(1,"Improper character in bit string");
    }
  }
  end:
  if(sh) fputc(cur,f);
  fclose(f);
  if(!buf) errx(1,"Unexpected error");
  *buf=sh;
  if(asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_BIT_STRING,buf,len)) errx(1,"Error encoding bit string");
  free(buf);
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
    } else if(type==ASN1_REAL) {
      break;
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
  } else if(type==ASN1_REAL) {
    char*p;
    i=*tokenstr;
    ungetc(c,stdin);
    for(tokenlen=0;;) {
      c=getchar();
      if(tokenlen==TOKENMAX-1) errx(1,"Too long SINGLE or DOUBLE");
      if(c==EOF) errx(1,"Unexpected end of file");
      if(c<43 || c>122 || (c>58 && c<65) || c==47 || (c>90 && c<97)) {
        ungetc(c,stdin);
        break;
      }
      tokenstr[tokenlen++]=c;
    }
    tokenstr[tokenlen]=0;
    if(!tokenlen) errx(1,"Improper SINGLE or DOUBLE");
    if(i=='D') {
      double f=strtod(tokenstr,&p);
      if(*p) errx(1,"Improper SINGLE or DOUBLE");
      asn1_encode_double(enc,f);
    } else {
      float f=strtof(tokenstr,&p);
      if(*p) errx(1,"Improper SINGLE or DOUBLE");
      asn1_encode_float(enc,f);
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

static void do_real(void) {
  uint8_t*significand=0;
  size_t length=0;
  int8_t sign=+1;
  uint8_t decimal=(tokenb==10);
  int64_t exponent=0;
  size_t at=tokenw;
  uint8_t bits=(tokenb==2?1:tokenb==4?2:tokenb==8?3:tokenb==16?4:0);
  uint8_t exbits=(bits?:1);
  uint8_t cur=0;
  uint8_t shift=0;
  FILE*f=open_memstream((char**)&significand,&length);
  if(!f) errx(1,"Unexpected error");
  if(tokenstr[at]=='+') at++; else if(tokenstr[at]=='-') at++,sign=-1;
  if(decimal) {
    while(at<tokenlen) {
      if(tokenstr[at]=='.' && exbits) {
        exbits=0;
      } else if(tokenstr[at]>='0' && tokenstr[at]<='9') {
        exponent+=exbits;
        if(shift^=1) cur=(tokenstr[at]-'0')*10; else fputc(cur+tokenstr[at]-'0',f);
      } else {
        break;
      }
      at++;
    }
    if(shift) fputc(cur,f);
    if(tokenstr[at]=='E' || tokenstr[at]=='e') exponent+=strtoll(tokenstr+at+1,0,10);
  } else {
    while(at<tokenlen) {
      if(tokenstr[at]=='.' && exbits) {
        exbits=0;
      } else if(tokenstr[at]>='0' && tokenstr[at]<='F') {
        shift+=bits;
        cur|=((tokenstr[at]+(tokenstr[at]>'9'?10-'A':-'0'))<<8)>>shift;
        if(shift>=8) {
          shift-=8;
          fputc(cur,f);
          cur=((tokenstr[at]+(tokenstr[at]>'9'?10-'A':-'0'))<<8)>>shift;
        }
        exponent+=exbits;
      } else {
        break;
      }
      at++;
    }
    if(cur) fputc(cur,f);
    if(tokenstr[at]=='P') exponent+=strtoll(tokenstr+at+1,0,10);
  }
  fputc(0,f);
  fclose(f);
  if(!significand) errx(1,"Unexpected error");
  if(asn1_encode_real_parts(enc,significand,length,sign,decimal,exponent,0)) errx(1,"Error encoding real number");
  free(significand);
}

static void define_constraint_value(FILE*f) {
  ASN1_Encoder*enc0=enc;
  enc=asn1_create_encoder(f);
  if(!enc) errx(1,"Unexpected error");
  nexttok();
  do_one_item();
  asn1_finish_encoder(enc);
  enc=enc0;
  if(debugtokens) fprintf(stderr,"End of constraint/schema value\n");
}

static void define_charset_constraint(FILE*f,int typ) {
  uint8_t v[32]={};
  int c,r,e,m,i;
  fputc(OP_OF,f);
  e=m=0; r=-1;
  for(;;) {
    c=getchar();
    if(c==EOF) errx(1,"Unexpected end of file");
    if(c<32 || c>126) errx(1,"Improper character in text string");
    c&=0xFF;
    if(c=='(') ++m; else if(c==')' && !m--) break;
    if(c=='\\') {
      switch(c=getchar()) {
        case '\\': case '(': case ')': case '=': /* do nothing */ break;
        case 'a': c='\a'; break;
        case 'b': c='\b'; break;
        case 'e': c='\e'; break;
        case 'f': c='\f'; break;
        case 'n': c='\n'; break;
        case 'r': c='\r'; break;
        case 'v': c='\v'; break;
        case 'x':
          i=getchar();
          if(i>='0' && i<='9') c=i-'0'; else if(i>='A' && i<='F') c=i+10-'A'; else if(i>='a' && i<='f') c=i+10-'a'; else errx(1,"Improper escape sequence");
          c<<=4;
          i=getchar();
          if(i>='0' && i<='9') c+=i-'0'; else if(i>='A' && i<='F') c+=i+10-'A'; else if(i>='a' && i<='f') c+=i+10-'a'; else errx(1,"Improper escape sequence");
          break;
        case ';': continue;
        case ' ': case '\t': case '\r': case '\n':
          for(;;) {
            c=getchar();
            if(c==';') break;
            if(c!=' ' && c!='\t' && c!='\r' && c!='\n') errx(1,"Improper escape sequence");
          }
          continue;
        default: errx(1,"Improper escape sequence");
      }
    } else if(c=='=') {
      if(e++ || r==-1) errx(1,"Improper use of = in OF: constraint");
      continue;
    }
    v[c>>3]|=1<<(c&7);
    if(e) {
      if(r>=c) errx(1,"Improper use of = in OF: constraint");
      e=0;
      while(++r<c) v[r>>3]|=1<<(r&7);
      r=-1;
    } else {
      r=c;
    }
  }
  if(e) errx(1,"Improper use of = in OF: constraint");
  if(typ==ASN1_BCD_STRING) {
    if(v[0] || v[1]) errx(1,"Improper OF: constraint for BCD strings");
    v[0]=v[6];
    v[1]=v[7]&3;
    if(v['*'/8]&(1<<('*'&7))) v[1]+=4;
    if(v['#'/8]&(1<<('#'&7))) v[1]+=8;
    if(v['+'/8]&(1<<('+'&7))) v[1]+=16;
    if(v['-'/8]&(1<<('-'&7))) v[1]+=32;
    if(v['.'/8]&(1<<('.'&7))) v[1]+=64;
    if(v[' '/8]&(1<<(' '&7))) v[1]+=128;
    if(v[4]&2) v[2]=0xFF; else v[2]=0;
    fwrite(v,1,3,f);
  } else {
    fwrite(v,1,32,f);
  }
}

static int constraint_output_item(FILE*f,Schema*sch,int level) {
  Name*nam;
  int i;
  again:
  switch(nexttok()) {
    case TOK_NAME:
      nam=find_name();
      if(nam->kind==NK_FUNCTION) {
        if(sch->function) errx(1,"A function is not allowed to occur more than once in the output list of a schema");
        fputc(OP_FUNCTION,f);
        sch->function=nam;
        return 0;
      }
      for(i=0;i<sch->nfields;i++) if((sch->fields[i].flag&FF_NAMED) && nam==sch->fields[i].fname) break;
      if(i==sch->nfields) errx(1,"Wrong field name in output list");
      fputc(OP_FIELD,f);
      fputc(i>>8,f);
      fputc(i,f);
      break;
    case TOK_FIELD:
      for(i=0;i<sch->nfields;i++) if(!(sch->fields[i].flag&FF_NAMED) && tokenw==sch->fields[i].fnumber) break;
      if(i==sch->nfields) errx(1,"Wrong field name in output list");
      fputc(OP_FIELD,f);
      fputc(i>>8,f);
      fputc(i,f);
      break;
    case TOK_ASTERISK:
      fputc(OP_MULTI,f);
      return 0;
    case TOK_SEQ_BEGIN:
      fputc(OP_BEGIN_SEQUENCE,f);
      while(!constraint_output_item(f,sch,1));
      if(tokent!=TOK_SEQ_END) errx(1,"Wrong token (%d)",tokent);
      fputc(OP_END_CONSTRUCT,f);
      return 0;
    case TOK_SET_BEGIN:
      fputc(OP_BEGIN_SET,f);
      while(!constraint_output_item(f,sch,1));
      if(tokent!=TOK_SET_END) errx(1,"Wrong token (%d)",tokent);
      fputc(OP_END_CONSTRUCT,f);
      return 0;
    case TOK_IMPLICIT:
      fputc(OP_IMPLICIT,f);
      fputc(tokenb,f);
      fputc(tokenw>>030,f);
      fputc(tokenw>>020,f);
      fputc(tokenw>>010,f);
      fputc(tokenw>>000,f);
      goto again;
    case TOK_WRAP:
      fputc(OP_WRAP,f);
      goto again;
    case TOK_FUNCTION:
      if(sch->function) errx(1,"A function is not allowed to occur more than once in the output list of a schema");
      fputc(OP_FUNCTION,f);
      sch->function=builtins+tokenb-'A';
      if(!sch->function->kind) errx(1,"Undefined built-in function: $%c",tokenb);
      return 0;
    case TOK_SEQ_END: case TOK_SET_END: return 1;
    default: errx(1,"Wrong token in schema output item");
  }
  if(level) {
    if(nexttok()==TOK_DEFAULT) {
      fputc(OP_DEFAULT,f);
      define_constraint_value(f);
    } else {
      repeattoken=1;
    }
  }
  return 0;
}

static void define_schema(Name*nam0,int schtype,int endtok) {
  Prefix prkey={tokenstr};
  Prefix*pritem;
  size_t bprg;
  FILE*prg;
  Schema*sch;
  Name*nam;
  Field fie;
  int i,c;
  char mu=(schtype!=ASN1_SEQUENCE);
  nam0->kind=NK_BUSY;
  nam0->schema=sch=calloc(sizeof(Schema),1);
  if(!sch) err(1,"Memory error");
  sch->type=schtype;
  prg=open_memstream((char**)&sch->constraint,&sch->length);
  if(!prg) errx(1,"Unexpected error");
  nexttok();
  // Inputs
  while(tokent!=endtok) {
    if(sch->nfields==0xFFFF) errx(1,"Too many fields");
    memset(&fie,0,sizeof(Field));
    if(sch->type==ASN1_ENUMERATED) fie.flag=FF_OPTIONAL;
    if(tokent==TOK_ASTERISK) {
      if(mu++) errx(1,"Improper use of * in schema");
      fie.flag|=FF_MULTI;
      nexttok();
    }
    if(tokent==TOK_PREFIX) {
      if(tokenlen==3 && tokenstr[0]=='O' && tokenstr[1]=='I' && tokenstr[2]=='D') {
        fie.stringtype=ASN1_OID;
      } else {
        pritem=bsearch(&prkey,prefix,sizeof(prefix)/sizeof(*prefix),sizeof(Prefix),prefix_compare);
        if(!pritem) errx(1,"Unrecognzied prefix");
        if(pritem->type==ASN1_UTCTIME || pritem->type==ASN1_UTC_TIMESTAMP || pritem->type==ASN1_REAL || pritem->type==ASN1_GENERALIZED_TIME || pritem->type==ASN1_BIT_STRING) errx(1,"Incorrect prefix");
        fie.stringtype=pritem->type;
      }
      nexttok();
    } else {
      fie.stringtype=ASN1_IA5_STRING;
    }
    if(tokent==TOK_NAME) {
      nam=find_name();
      if(nam->kind==NK_UNDEF) nam->kind=NK_FIELD; else if(nam->kind!=NK_FIELD) errx(1,"Wrong name in this context");
      for(i=0;i<sch->nfields;i++) if((sch->fields[i].flag&FF_NAMED) && sch->fields[i].fname==nam) errx(1,"Repeated field name in schema");
      fie.flag|=FF_NAMED;
      fie.fname=nam;
    } else if(tokent==TOK_FIELD) {
      for(i=0;i<sch->nfields;i++) if(!(sch->fields[i].flag&FF_NAMED) && sch->fields[i].fnumber==tokenw) errx(1,"Repeated field number in schema");
      fie.fnumber=tokenw;
    } else {
      errx(1,"Field designation expected");
    }
    if(nexttok()==TOK_QUESTION) {
      if(sch->type==ASN1_KEY_VALUE_LIST) errx(1,"Optional fields are not allowed in a key/value list");
      fie.flag|=FF_OPTIONAL;
      nexttok();
    }
    if(tokent==TOK_BRACE_BEGIN) {
      fie.flag|=FF_CONSTRAINT;
      fie.constraint=ftell(prg);
      while(nexttok()!=TOK_BRACE_END) {
        if(tokent==TOK_NAME) {
          if(fie.xname) errx(1,"Constraint has multiple names but is not allowed");
          fie.xname=find_name();
        } else if(tokent==TOK_PREFIX) {
          if(tokenlen==4) {
            if(!memcmp(tokenstr,"TYPE",4)) {
              fputc(OP_TYPE,prg);
              nexttok();
              if(tokent==TOK_BRACE_BEGIN) {
                while(nexttok()!=TOK_BRACE_END) {
                  if(tokent!=TOK_IMPLICIT) errx(1,"Expected implicit type token");
                  fputc(tokenb+0x80,prg);
                  fputc(tokenw>>030,prg);
                  fputc(tokenw>>020,prg);
                  fputc(tokenw>>010,prg);
                  fputc(tokenw>>000,prg);
                }
              } else if(tokent==TOK_IMPLICIT) {
                fputc(tokenb+0x80,prg);
                fputc(tokenw>>030,prg);
                fputc(tokenw>>020,prg);
                fputc(tokenw>>010,prg);
                fputc(tokenw>>000,prg);
              } else {
                if(tokent!=TOK_IMPLICIT) errx(1,"Expected implicit type token");
              }
              fputc(0,prg);
            } else if(!memcmp(tokenstr,"VMIN",4)) {
              fputc(OP_VMIN,prg);
              define_constraint_value(prg);
            } else if(!memcmp(tokenstr,"VMAX",4)) {
              fputc(OP_VMAX,prg);
              define_constraint_value(prg);
            } else if(!memcmp(tokenstr,"SMIN",4)) {
              fputc(OP_SMIN,prg);
              goto sminmax;
            } else if(!memcmp(tokenstr,"SMAX",4)) {
              fputc(OP_SMAX,prg);
              sminmax:
              if(nexttok()!=TOK_INTEGER) errx(1,"Expected integer");
              tokenv=strtoll(tokenstr+tokenw,0,tokenb);
              if(tokenv&~0x7FFFFFFFUL) errx(1,"Expected nonnegative integer");
              fputc(tokenv>>030,prg);
              fputc(tokenv>>020,prg);
              fputc(tokenv>>010,prg);
              fputc(tokenv>>000,prg);
            } else {
              errx(1,"Prefix \"%s\" is not valid in constraints",tokenstr);
            }
          } else if(tokenlen==2 && tokenstr[0]=='O' && tokenstr[1]=='F') {
            if(nexttok()!=TOK_START_TEXT_STRING) errx(1,"Prefix \"OF\" must be followed by a text string");
            define_charset_constraint(prg,fie.stringtype);
          } else if(tokenlen==3 && tokenstr[2]=='P') {
            if(sch->type==ASN1_KEY_VALUE_LIST || (sch->type==ASN1_SEQUENCE && mu)) errx(1,"Cannot use IMP: and EXP: here");
            if(fie.im_class) errx(1,"Cannot use IMP: and EXP: multiple times in one field");
            if(tokenstr[0]=='I' && tokenstr[1]=='M') {
              fie.im_class=0x80;
            } else if(tokenstr[0]=='E' && tokenstr[1]=='X') {
              fie.im_class=0xC0;
            } else {
              errx(1,"Prefix \"%s\" is not valid in constraints",tokenstr);
            }
            if(nexttok()!=TOK_IMPLICIT) errx(1,"Expected implicit type token");
            fie.im_class+=tokenb;
            fie.im_type=tokenw;
          } else {
            errx(1,"Prefix \"%s\" is not valid in constraints",tokenstr);
          }
        } else if(tokent==TOK_FUNCTION) {
          if(fie.xname) errx(1,"Constraint has multiple names but is not allowed");
          fie.xname=(Name*)(builtins+tokenb-'A');
          if(!fie.xname->kind) errx(1,"Undefined built-in function: $%c",tokenb);
        } else {
          errx(1,"Expected constraint or end brace");
        }
      }
      nexttok();
      fputc(0,prg);
    }
    if(tokent==TOK_EQUAL || tokent==TOK_DEFAULT) {
      if(sch->type==TOK_EQUAL && !(fie.flag&FF_NAMED)) errx(1,"Numbered field cannot use = value");
      if(sch->type==TOK_EQUAL && (fie.flag&FF_CONSTRAINT)) errx(1,"A field cannot use a = value and constraints together");
      if(sch->type==ASN1_KEY_VALUE_LIST) errx(1,"Implied and default values are not allowed in a key/value list");
      if(sch->type==ASN1_ENUMERATED && tokent==TOK_DEFAULT) errx(1,"Default values are only allowed in a [ ] schema");
      fie.flag|=(tokent==TOK_EQUAL?FF_VALUE:FF_DEFAULT)|FF_OPTIONAL;
      fie.value=ftell(prg);
      define_constraint_value(prg);
      nexttok();
    }
    if(!(sch->fields=realloc(sch->fields,++sch->nfields*sizeof(Field)))) err(1,"Memory error");
    sch->fields[sch->nfields-1]=fie;
  }
  if(sch->type==ASN1_KEY_VALUE_LIST && sch->nfields!=2) errx(1,"A key/value schema must have exactly two fields");
  if(!sch->nfields) errx(1,"Schema does not have any fields");
  if(sch->type==ASN1_KEY_VALUE_LIST) sch->fields->flag|=FF_MULTI;
  bprg=ftell(prg);
  if(bprg&~0x7FFFFFFF) errx(1,"Too many constraints");
  // Outputs
  if(sch->type!=ASN1_KEY_VALUE_LIST && constraint_output_item(prg,sch,0)) errx(1,"Wrong token");
  // Finish
  fputc(OP_END,prg);
  fclose(prg);
  if(!sch->constraint) errx(1,"Unexpected error");
  sch->program=sch->constraint+bprg;
  nam0->kind=NK_SCHEMA;
  // Debug
  if(debugschema) {
    unsigned long w;
    fprintf(stderr,"Schema: \"%s\" (%p)\n",nam0->name,sch);
    fprintf(stderr,"  Type = %d\n  Num. fields = %d\n",sch->type,sch->nfields);
    if(sch->function) fprintf(stderr,"  Function = \"%s\" (%p)\n",sch->function->name,sch->function);
    for(i=0;i<sch->nfields;i++) {
      fprintf(stderr,"  Field %d:\n    Flags = 0x%02X\n    String type = %d\n",i,sch->fields[i].flag,sch->fields[i].stringtype);
      if(sch->fields[i].flag&FF_NAMED) fprintf(stderr,"    Name = \"%s\"\n",sch->fields[i].fname->name);
      else fprintf(stderr,"    Designation = $%d\n",sch->fields[i].fnumber);
      if(sch->fields[i].xname) fprintf(stderr,"    Xname = \"%s\"\n",sch->fields[i].xname->name);
      fprintf(stderr,"    Constraint = 0x%lX\n",(unsigned long)sch->fields[i].constraint);
    }
    fprintf(stderr,"  Program:");
    for(w=0;w<sch->length;w++) {
      if(!(w&15)) fprintf(stderr,"\n    %08lX: ",w);
      fprintf(stderr,"%c%02X",w==bprg?'*':' ',sch->constraint[w]);
    }
    fputc('\n',stderr);
  }
}

typedef struct {
  size_t start,length;
} FieldData;

static void output_by_function(const Schema*sch,uint8_t*data,size_t datalen,FieldData*fid) {
  ASN1*asn=calloc(sizeof(ASN1),sch->nfields);
  uint32_t n;
  if(!asn) errx(1,"Allocation failed");
  for(n=0;n<sch->nfields;n++) if(fid[n].start && asn1_parse(data+fid[n].start,fid[n].length,asn+n,0)) errx(1,"ASN.1 parse error");
  if(fid[sch->nfields].start) {
    data+=fid[sch->nfields].start;
    datalen-=fid[sch->nfields].start;
  } else {
    data=0;
    datalen=0;
  }
  if(sch->function->call(enc,asn,sch->nfields,data,datalen,sch->function->userdata)) errx(1,"Function call error");
  free(asn);
}

static void do_schema_item(const Schema*sch) {
  static uint8_t oid[512];
  ASN1 asn;
  ASN1_Encoder*enc0=enc;
  FieldData*fid;
  uint8_t*data=0;
  size_t datalen=0;
  FILE*fp;
  Name*nam;
  uint32_t con;
  uint16_t nf=0;
  uint16_t cf;
  int32_t mult=-1;
  size_t at,siz;
  char aft=0;
  char first;
  char imp=1;
  int endtok=0;
  int i,c;
  if(debugschema) fprintf(stderr,"Begin schema item (%p)\n",sch);
  fid=calloc(sch->nfields+1,sizeof(FieldData));
  if(!fid) errx(1,"Memory error");
  if(sch->type==ASN1_KEY_VALUE_LIST) {
    asn1_construct(enc,ASN1_UNIVERSAL,ASN1_KEY_VALUE_LIST,ASN1_KVSORT);
    fp=asn1_current_file(enc);
    mult=0;
  } else {
    fp=open_memstream((char**)&data,&datalen);
    if(!fp) errx(1,"Memory error");
    for(i=0;i<sch->nfields;i++) if(sch->fields[i].flag&FF_MULTI) {
      mult=i;
      break;
    }
    enc=asn1_create_encoder(fp);
    if(!enc) errx(1,"Memory error");
    fputc(0,fp);
  }
  nexttok();
  if(tokent==TOK_BRACE_BEGIN) endtok=TOK_BRACE_END;
  else if(tokent==TOK_KV_BEGIN && sch->type==ASN1_KEY_VALUE_LIST) endtok=TOK_KV_END;
  else if(tokent==TOK_SEQ_BEGIN && sch->type==ASN1_SEQUENCE) endtok=TOK_SEQ_END;
  if(endtok) nexttok();
  if(sch->type!=ASN1_ENUMERATED) {
    if(!endtok) errx(1,"Expected beginning delimiter of value according to schema");
  } else {
    fid[sch->nfields].start=1;
  }
  while(tokent!=endtok || !endtok) {
    if(tokent==TOK_NAME) {
      nam=find_name();
      if(nam->kind!=NK_FIELD) goto noname;
      for(cf=0;cf<sch->nfields;cf++) if((sch->fields[cf].flag&FF_NAMED) && sch->fields[cf].fname==nam) break;
      if(cf==sch->nfields) errx(1,"Field name \"%s\" does not match any field in the schema",tokenstr);
      nexttok();
      goto found;
    }
    noname:
    while(nf<sch->nfields && (sch->fields[nf].flag&FF_NAMED)) nf++;
    cf=nf++;
    if(mult>=0 && cf>=sch->nfields) {
      nf=mult;
      while(nf<sch->nfields && (sch->fields[nf].flag&FF_NAMED)) nf++;
      cf=nf++;
    }
    if(cf>=sch->nfields) errx(1,"Too many fields");
    found:
    if(aft && cf<mult) errx(1,"Cannot use field before * if field after * is present");
    if(mult>=0 && cf>=mult && !aft) {
      aft=1;
      fid[sch->nfields].start=ftell(fp);
    }
    if((cf<mult || mult<0) && fid[cf].start) errx(1,"Repeated field");
    if(sch->fields[cf].flag&FF_VALUE) {
      con=sch->fields[cf].value;
      siz=0;
      asn1_parse(sch->constraint+con,sch->length,&asn,&siz);
      fid[cf].start=ftell(fp);
      fid[cf].length=siz;
      fwrite(sch->constraint+con,1,siz,fp);
    } else {
      nam=sch->fields[cf].xname;
      fid[cf].start=ftell(fp);
      if(!nam) {
        // No special handling is used for this case
      } else if(nam->kind==NK_SCHEMA) {
        repeattoken=1;
        do_schema_item(nam->schema);
        asn1_flush(enc);
        fid[cf].length=ftell(fp)-fid[cf].start;
        goto endv;
      } else if(nam->kind==NK_FUNCTION && sch->type!=ASN1_KEY_VALUE_LIST) {
        // This case is handled later
      } else if(nam->kind!=NK_OBJECT) {
        errx(1,"Constraint name (%s) in schema is not of the expected kind",nam->name);
      }
      if(nam && nam->kind==NK_OBJECT && tokent==TOK_OID) {
        if(asn1_make_static_oid(tokenstr,oid,512,&asn)) errx(1,"Improper object identifier");
        if(asn.length>=nam->oidlen && !memcmp(oid,nam->oid,nam->oidlen)) {
          asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_RELATIVE_OID,oid+nam->oidlen,asn.length-nam->oidlen);
        } else {
          asn1_encode(enc,&asn);
        }
      } else if(nam && nam->kind==NK_OBJECT && tokent==TOK_NAME && (nam=find_name())->kind==NK_OBJECT) {
        if(nam->oidlen>505) errx(1,"Too long object identifier in schema definition");
        c=getchar();
        if(c=='.') {
          memcpy(tokenstr,"0.0.",4);
          for(tokenlen=4;tokenlen<TOKENMAX;tokenlen) {
            c=getchar();
            if((c>='0' && c<='9') || c=='.') {
              tokenstr[tokenlen++]=c;
            } else {
              if(c!=EOF) ungetc(c,stdin);
              break;
            }
          }
          tokenstr[tokenlen]=0;
          if(asn1_make_static_oid(tokenstr,oid+nam->oidlen-1,512-nam->oidlen,&asn)) errx(1,"Improper object identifier");
          memcpy(oid,nam->oid,nam->oidlen);
          asn.data=oid;
          asn.length+=nam->oidlen-1;
        } else {
          ungetc(c,stdin);
          asn.class=ASN1_UNIVERSAL;
          asn.type=ASN1_OID;
          asn.data=nam->oid;
          asn.length=nam->oidlen;
        }
        nam=sch->fields[cf].xname;
        if(asn.length>=nam->oidlen && !memcmp(oid,nam->oid,nam->oidlen)) {
          asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_RELATIVE_OID,oid+nam->oidlen,asn.length-nam->oidlen);
        } else {
          asn1_encode(enc,&asn);
        }
      } else if(sch->fields[cf].stringtype==ASN1_OID && tokent!=TOK_OID && (tokent!=TOK_RELATIVE_OID || !sch->fields[cf].xname)) {
        errx(1,"Value must be a object identifier");
      } else {
        if(tokent==TOK_START_TEXT_STRING) do_text_string(sch->fields[cf].stringtype); else do_one_item();
      }
      nexttok();
      asn1_flush(enc);
      first=1;
      nextoption:
      nam=sch->fields[cf].xname;
      if((sch->fields[cf].flag&FF_CONSTRAINT) && (sch->constraint[sch->fields[cf].constraint]!=OP_END || (nam && nam->kind==NK_FUNCTION))) {
        if(!data) errx(1,"Improper use of constraints");
        asn1_parse(data+fid[cf].start,ftell(fp)-fid[cf].start,&asn,0);
        con=sch->fields[cf].constraint;
        while(sch->constraint[con]!=OP_END) {
          switch(sch->constraint[con++]) {
            case OP_TYPE:
              for(i=0;sch->constraint[con];) {
                if(asn.class==(sch->constraint[con]&3) && asn.type==(((uint32_t)sch->constraint[con+1])<<030)+(sch->constraint[con+2]<<020)+(sch->constraint[con+3]<<010)+sch->constraint[con+4]) i=1;
                con+=5;
              }
              con++;
              if(!i) goto mismatch;
              break;
            case OP_OF:
              if(asn.constructed || asn.class || asn.type!=sch->fields[cf].stringtype) goto mismatch;
              if(asn.type!=ASN1_BCD_STRING) {
                for(at=0;at<asn.length;at++) if(!(sch->constraint[con+(asn.data[at]>>3)]&(1<<(asn.data[at]&7)))) goto mismatch;
                con+=32;
              } else {
                for(at=0;at<asn.length;at++) {
                  i=asn.data[at]>>4;
                  if(!(sch->constraint[con+(i>>3)]&(1<<(i&7)))) goto mismatch;
                  i=asn.data[at]&15;
                  if(i==15 && at==asn.length-1 && sch->constraint[con+2]) break;
                  if(!(sch->constraint[con+(i>>3)]&(1<<(i&7)))) goto mismatch;
                }
                con+=3;
              }
              break;
            case OP_SMIN:
              if(asn.length<(((uint32_t)sch->constraint[con])<<030)+(sch->constraint[con+1]<<020)+(sch->constraint[con+2]<<010)+sch->constraint[con+3]) goto mismatch;
              con+=4;
              break;
            case OP_SMAX:
              if(asn.length>(((uint32_t)sch->constraint[con])<<030)+(sch->constraint[con+1]<<020)+(sch->constraint[con+2]<<010)+sch->constraint[con+3]) goto mismatch;
              con+=4;
              break;
            //TODO: OP_VMIN, OP_VMAX
            default: errx(1,"Unexpected constraint opcode");
            mismatch:
              if((sch->fields[cf].flag&FF_NAMED) || !(sch->fields[cf].flag&FF_OPTIONAL)) errx(1,"Constraint failed");
              while(nf<sch->nfields && (sch->fields[nf].flag&FF_NAMED)) nf++;
              if(nf==sch->nfields && mult>=0 && first) {
                first=0;
                nf=mult;
                while(nf<sch->nfields && (sch->fields[nf].flag&FF_NAMED)) nf++;
                if(nf==sch->nfields) errx(1,"Constraint failed");
              }
              fid[nf]=fid[cf];
              fid[cf].start=0;
              cf=nf++;
              goto nextoption;
          }
        }
        if(nam && nam->kind==NK_FUNCTION) {
          fid[cf].start=ftell(fp);
          if(nam->call(enc,&asn,1,0,0,nam->userdata)) goto mismatch;
          asn1_flush(enc);
        }
      }
      fid[cf].length=ftell(fp)-fid[cf].start;
    }
    endv:
    if(fid[cf].start && fid[cf].length && sch->fields[cf].im_class) {
      c=sch->fields[cf].im_class;
      at=fid[cf].start;
      if(!(c&0x40)) {
        asn1_flush(enc);
        if(!data) errx(1,"Unexpected error");
        asn1_parse(data+at,fid[cf].length,&asn,0);
      }
      fid[cf].start=ftell(fp);
      asn1_write_type(c&0x40?:data[at]&0x20,c&3,sch->fields[cf].im_type,fp);
      asn1_write_length(c&0x40?fid[cf].length:asn.length,fp);
      fflush(fp);
      if(!data) errx(1,"Unexpected error");
      fwrite(c&0x40?(const uint8_t*)data+at:asn.data,1,c&0x40?fid[cf].length:asn.length,fp);
      fid[cf].length=ftell(fp)-fid[cf].start;
    }
    if(sch->type==ASN1_ENUMERATED) {
      if(endtok && tokent!=endtok) errx(1,"Missing ending delimiter");
      break;
    }
  }
  if(tokent==endtok) nexttok();
  if(sch->type==ASN1_KEY_VALUE_LIST) {
    if(!cf) errx(1,"Improper number of items in key/value list");
    asn1_end(enc);
  } else {
    for(cf=0;cf<sch->nfields;cf++) {
      if(sch->fields[cf].flag&FF_MULTI) break;
      if(!fid[cf].start) {
        if(!(sch->fields[cf].flag&FF_OPTIONAL)) errx(1,"Required field missing");
        if(sch->fields[cf].flag&FF_DEFAULT) {
          con=sch->fields[cf].value;
          siz=0;
          asn1_parse(sch->constraint+con,sch->length,&asn,&siz);
          fid[cf].start=ftell(fp);
          fid[cf].length=siz;
          fwrite(sch->constraint+con,1,siz,fp);
        }
      }
    }
    // Send output
    asn1_finish_encoder(enc);
    fclose(fp);
    enc=enc0;
    if(!data) errx(1,"Unexpected error");
    if(sch->type==ASN1_ENUMERATED && datalen==1) errx(1,"Missing item");
    for(at=0;sch->program[at]!=OP_END;) switch(sch->program[at++]) {
      case OP_FIELD:
        cf=(sch->program[at]<<8)+sch->program[at+1];
        at+=2;
        if(sch->program[at]==OP_DEFAULT) {
          siz=++at;
          if(asn1_parse(sch->program+at,sch->length,&asn,&at)) errx(1,"Unexpected error");
          if(fid[cf].start && fid[cf].length==at-siz && !memcmp(data+fid[cf].start,sch->program+siz,at-siz)) {
            if(imp) errx(1,"Improper use of implicit fields in schema");
            break;
          }
        }
        if(fid[cf].start) {
          if(asn1_parse(data+fid[cf].start,fid[cf].length,&asn,0)) errx(1,"Unexpected error decoding output parts of schema");
          asn1_encode(enc,&asn);
        } else if(imp) {
          asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_NULL,"",0);
        }
        imp=0;
        break;
      case OP_MULTI:
        if(siz=fid[sch->nfields].start) while(siz<datalen) {
          if(asn1_parse(data+siz,datalen-siz,&asn,&siz)) errx(1,"Unexpected error");
          asn1_encode(enc,&asn);
          imp=0;
        }
        if(imp) {
          asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_NULL,"",0);
          imp=0;
        }
        break;
      case OP_IMPLICIT:
        asn1_implicit(enc,sch->program[at],(((uint32_t)sch->program[at+1])<<030)+(sch->program[at+2]<<020)+(sch->program[at+3]<<010)+sch->program[at+4]);
        at+=5;
        imp=1;
        break;
      case OP_WRAP: asn1_wrap(enc); imp=1; break;
      case OP_BEGIN_SEQUENCE: asn1_construct(enc,ASN1_UNIVERSAL,ASN1_SEQUENCE,0); imp=0; break;
      case OP_BEGIN_SET: asn1_construct(enc,ASN1_UNIVERSAL,ASN1_SET,ASN1_SORT); imp=0; break;
      case OP_END_CONSTRUCT: asn1_end(enc); imp=0; break;
      case OP_FUNCTION: output_by_function(sch,data,datalen,fid); imp=0; break;
      default: errx(1,"Unexpected output opcode");
    }
    endout:
    free(data);
  }
  free(fid);
  if(debugschema) fprintf(stderr,"End schema item (%p)\n",sch);
}

static void define_extension_function(Name*nam,void*handle) {
  ASN1_Encoder*enc0=enc;
  const char*(*fun)(int(**)(ASN1_Encoder*enc,const ASN1*values,int nvalues,const uint8_t*data,size_t length,void*userdata),void**userdata,const char**option,uint8_t*data,size_t length);
  const char*x;
  const char*opt=0;
  uint8_t*data=0;
  size_t length=0;
  FILE*fp=open_memstream((char**)&data,&length);
  int c;
  if(!fp) errx(1,"Unexpected error");
  if(getchar()!='.') errx(1,"Wrong token in this context");
  strcpy(tokenstr,"extfun_");
  for(tokenlen=7;tokenlen<TOKENMAX;) {
    c=getchar();
    if(c&~127) errx(1,"Unexpected character");
    if(!wordch[c]) break;
    tokenstr[tokenlen++]=c;
  }
  ungetc(c,stdin);
  tokenstr[tokenlen]=0;
  fun=dlsym(handle,tokenstr);
  if(!fun) errx(1,"Cannot load function");
  nam->kind=NK_FUNCTION;
  nam->call=0;
  nam->userdata=0;
  enc=asn1_create_encoder(fp);
  if(!enc) errx(1,"Unexpected error");
  if(nexttok()!=TOK_BRACE_BEGIN) errx(1,"Expected brace");
  while(nexttok()!=TOK_BRACE_END) do_one_item();
  fputc(0,fp);
  asn1_finish_encoder(enc);
  fclose(fp);
  if(!data) errx(1,"Unexpected error");
  enc=enc0;
  if(x=fun(&nam->call,&nam->userdata,&opt,data,length-1)) errx(1,"Error loading function: %s",x);
  free(data);
  if(!nam->call) errx(1,"Error loading function: Extension did not assign a function pointer");
  if(opt) nam->option=(*opt=='-'?0:*opt&0x7F);
  if(debugschema) fprintf(stderr,"Extension function \"%s\": (%p,%p,%p,0x%lX)\n",nam->name,handle,nam->call,nam->userdata,(unsigned long)nam->option);
}

static void data_function_call_1(const Name*nam,int mul) {
  ASN1_Encoder*enc0=enc;
  uint8_t*data=0;
  size_t len=0;
  FILE*fp=open_memstream((char**)&data,&len);
  enc=asn1_create_encoder(fp);
  if(!fp || !enc) errx(1,"Unexpected error");
  if(mul) {
    if(nexttok()!=TOK_BRACE_BEGIN) errx(1,"Expected brace");
    while(nexttok()!=TOK_BRACE_END) do_one_item();
    asn1_flush(enc);
    fputc(0,fp);
  } else {
    nexttok();
    do_one_item();
  }
  asn1_finish_encoder(enc);
  fclose(fp);
  if(!data) errx(1,"Unexpected error");
  enc=enc0;
  if(nam->call(enc,0,0,data,len-mul,nam->userdata)) errx(1,"Function call failed");
  free(data);
}

static void data_function_call_A(const Name*nam,uint32_t type) {
  ASN1 asn;
  ASN1_Encoder*enc0=enc;
  uint8_t*data=0;
  size_t len=0;
  FILE*fp=open_memstream((char**)&data,&len);
  enc=asn1_create_encoder(fp);
  if(!fp || !enc) errx(1,"Unexpected error");
  switch(nexttok()) {
    case TOK_START_TEXT_STRING: do_text_string(type); break;
    case TOK_START_HEX_STRING: asn1_implicit(enc,ASN1_UNIVERSAL,type); do_hex_string(); break;
    case TOK_START_BASE64_STRING: asn1_implicit(enc,ASN1_UNIVERSAL,type); do_base64_string(); break;
    default: errx(1,"Wrong token in this context");
  }
  asn1_finish_encoder(enc);
  fputc(0,fp);
  fclose(fp);
  if(!data) errx(1,"Unexpected error");
  enc=enc0;
  asn1_parse(data,len,&asn,0);
  if(nam->call(enc,&asn,1,0,0,nam->userdata)) errx(1,"Function call failed");
  free(data);
}

static void data_function_call_T(const Name*nam) {
  ASN1 asn={.class=ASN1_UNIVERSAL,.type=ASN1_VISIBLE_STRING,.data=tokenstr};
  nexttok();
  if(tokent!=TOK_NAME && tokent!=TOK_INTEGER && tokent!=TOK_REAL && tokent!=TOK_OID && tokent!=TOK_IMPLICIT) errx(1,"Wrong token in this context");
  asn.length=tokenlen;
  if(nam->call(enc,&asn,1,0,0,nam->userdata)) errx(1,"Function call failed");
}

static int do_name(void) {
  Name*nam=find_name();
  Name*nam2;
  int c;
  ASN1 asn;
  uint8_t buf[512];
  switch(nam->kind) {
    case NK_UNDEF:
      if(nexttok()!=TOK_EQUAL) errx(1,"Undefined name (%s)",nam->name);
      switch(nexttok()) {
        case TOK_OID:
          if(asn1_make_static_oid(tokenstr,buf,512,&asn)) errx(1,"Improper object identifier");
          nam->kind=NK_OBJECT;
          nam->oid=malloc(nam->oidlen=asn.length);
          if(!nam->oid) errx(1,"Memory error");
          memcpy(nam->oid,asn.data,asn.length);
          break;
        case TOK_NAME:
          nam2=find_name();
          if(nam2->kind==NK_OBJECT) {
            if(getchar()!='.') errx(1,"Wrong token in this context");
            goto longoid;
          } else if(nam2->kind==NK_EXTENSION) {
            define_extension_function(nam,nam2->handle);
          } else {
            errx(1,"Wrong name in this context");
          }
          break;
        case TOK_BRACE_BEGIN: define_schema(nam,ASN1_ENUMERATED,TOK_BRACE_END); break;
        case TOK_SEQ_BEGIN: define_schema(nam,ASN1_SEQUENCE,TOK_SEQ_END); break;
        case TOK_KV_BEGIN: define_schema(nam,ASN1_KEY_VALUE_LIST,TOK_KV_END); break;
        default: errx(1,"Wrong token in this context");
      }
      return 1;
    case NK_OBJECT:
      c=getchar();
      if(c=='.') {
        longoid:
        memcpy(tokenstr,"0.0.",4);
        for(tokenlen=4;tokenlen<TOKENMAX;tokenlen) {
          c=getchar();
          if((c>='0' && c<='9') || c=='.') {
            tokenstr[tokenlen++]=c;
          } else {
            if(c!=EOF) ungetc(c,stdin);
            break;
          }
        }
        tokenstr[tokenlen]=0;
        if(nam->kind==NK_OBJECT) {
          if(nam->oidlen>505 || asn1_make_static_oid(tokenstr,buf+nam->oidlen-1,512-nam->oidlen,&asn)) errx(1,"Improper object identifier");
          memcpy(buf,nam->oid,nam->oidlen);
          asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_OID,buf,nam->oidlen+asn.length-1);
        } else { // (nam->kind==NK_UNDEF && nam2->kind==NK_OBJECT)
          if(asn1_make_static_oid(tokenstr,buf,512,&asn)) errx(1,"Improper object identifier");
          nam->kind=NK_OBJECT;
          nam->oid=malloc(nam->oidlen=asn.length+nam2->oidlen-1);
          if(!nam->oid) errx(1,"Memory error");
          memcpy(nam->oid,nam2->oid,nam2->oidlen);
          memcpy(nam->oid+nam2->oidlen,asn.data+1,asn.length-1);
          return 1;
        }
      } else {
        if(c!=EOF) ungetc(c,stdin);
        asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_OID,nam->oid,nam->oidlen);
      }
      return 0;
    case NK_SCHEMA:
      do_schema_item(nam->schema);
      repeattoken=1;
      return 0;
    case NK_FUNCTION:
      switch(nam->option&0x7F) {
        case 0: errx(1,"Cannot use function \"%s\" directly",nam->name); break;
        case '0': if(nam->call(enc,0,0,0,0,nam->userdata)) errx(1,"Function call failed"); break;
        case '1': data_function_call_1(nam,0); break;
        case '2': data_function_call_1(nam,1); break;
        case 'A': data_function_call_A(nam,ASN1_IA5_STRING); break;
        case 'O': data_function_call_A(nam,ASN1_OCTET_STRING); break;
        case 'P': data_function_call_A(nam,ASN1_PRINTABLE_STRING); break;
        case 'T': data_function_call_T(nam); break;
        case 'V': data_function_call_A(nam,ASN1_VISIBLE_STRING); break;
        case 'i': if(nam->call(enc,0,0,0,0,nam->userdata)) errx(1,"Function call failed"); break;
        default: errx(1,"Function \"%s\" contains an improper option",nam->name); break;
      }
      return 0;
    default: errx(1,"Wrong name in this context");
  }
}

static void do_one_item(void) {
  char imp=0;
  char wrap=0;
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
      while(nexttok()!=TOK_KV_END) {
        do_one_item();
        if(nexttok()==TOK_KV_END) errx(1,"Improper number of items in key/value list");
        do_one_item();
      }
      asn1_end(enc);
      break;
    case TOK_WRAP:
      wrap=0;
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
      if(asn1_encode_oid(enc,tokenstr)) errx(1,"Error encoding object identifier");
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
    case TOK_START_BIT_STRING:
      do_bit_string();
      break;
    case TOK_PREFIX:
      do_prefixed();
      break;
    case TOK_REAL:
      do_real();
      break;
    case TOK_NAME:
      if(do_name()) {
        if(imp || wrap) errx(1,"A definition is not supposed to be preceded by an implicit type");
        nexttok(); goto again;
      }
      break;
    default: errx(1,"Wrong token in this context");
  }
}

static void do_load_extension(char*arg) {
  char*p;
  Name*nam;
  strncpy(tokenstr,arg,TOKENMAX);
  p=strchr(tokenstr,'=');
  if(!p) errx(1,"Improper command-line switch");
  *p++=0;
  nam=find_name();
  if(nam->kind) errx(1,"Extension name \"%s\" is already defined",tokenstr);
  nam->kind=NK_EXTENSION;
  nam->handle=dlopen(p,RTLD_LAZY);
  if(!nam->handle) errx(1,"Cannot open extension \"%s\": %s",tokenstr,dlerror());
}

int main(int argc,char**argv) {
  int c;
  while((c=getopt(argc,argv,"+Stx:"))>0) switch(c) {
    case 'S': debugschema=1; break;
    case 't': debugtokens=1; break;
    case 'x': do_load_extension(optarg); break;
    default: errx(1,"Improper command-line switch");
  }
  if(optind!=argc) errx(1,"Wrong number of arguments");
  enc=asn1_create_encoder(stdout);
  if(!enc) errx(1,"Unexpected error");
  nexttok();
  do_one_item();
  if(nexttok()) errx(1,"Expected end of file");
  asn1_finish_encoder(enc);
  return 0;
}

