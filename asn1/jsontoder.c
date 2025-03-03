#if 0
gcc -s -O2 -o ./jsontoder jsontoder.c asn1.o
exit
#endif

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "asn1.h"

static ASN1_Encoder*enc;

static void do_number(int c) {
  static char cc[128]={['-']=1,['+']=1,['e']=1,['E']=1,['.']=1,['0'...'9']=1};
  uint8_t in[256];
  uint8_t out[256];
  int n=1;
  int8_t si=0;
  uint8_t dec=0;
  int64_t ex=0;
  uint8_t inf=0;
  ASN1_Value v={.data=in,.class=ASN1_UNIVERSAL,.type=ASN1_REAL};
  *in=1;
  do {
    if(c&~127) errx(1,"Improper character in JSON data");
    if(!cc[c]) break;
    if(n>254) errx(1,"Too long number in JSON data");
    in[n++]=c;
  } while((c=getchar())>0);
  if(c>0) ungetc(c,stdin);
  v.length=n;
  if(asn1_decode_real_parts(&v,ASN1_REAL,out,256,&si,&dec,&ex,&inf,0)) errx(1,"Improper number");
  asn1_encode_real_parts(enc,out,256,si,dec,ex,inf);
}

static uint32_t hex_char(void) {
  int c=getchar();
  if(c>='0' && c<='9') return c-'0';
  if(c>='A' && c<='F') return c+10-'A';
  if(c>='a' && c<='f') return c+10-'a';
  errx(1,"Improper character in JSON string");
}

static void send_unicode(uint32_t u,FILE*f) {
  if(u<0x80) {
    fputc(u,f);
  } else if(u<0x800) {
    fputc((u>>6)+0xC0,f);
    fputc((u&0x3F)+0x80,f);
  } else if(u<0x10000) {
    fputc((u>>12)+0xE0,f);
    fputc(((u>>6)&0x3F)+0x80,f);
    fputc(((u>>0)&0x3F)+0x80,f);
  } else if(u<0x200000) {
    fputc((u>>18)+0xF0,f);
    fputc(((u>>12)&0x3F)+0x80,f);
    fputc(((u>>6)&0x3F)+0x80,f);
    fputc(((u>>0)&0x3F)+0x80,f);
  } else if(u<0x4000000) {
    fputc((u>>24)+0xF8,f);
    fputc(((u>>18)&0x3F)+0x80,f);
    fputc(((u>>12)&0x3F)+0x80,f);
    fputc(((u>>6)&0x3F)+0x80,f);
    fputc(((u>>0)&0x3F)+0x80,f);
  }
}

static void do_string(void) {
  int c;
  uint32_t u=0;
  uint32_t n;
  FILE*f=asn1_primitive_stream(enc,ASN1_UNIVERSAL,ASN1_UTF8_STRING);
  for(;;) {
    c=getchar();
    if(c<' ') errx(1,"Improper character in JSON string");
    if(c=='"') break;
    if(c!='\\') {
      fputc(c,f);
    } else {
      switch(c=getchar()) {
        case '/': case '\\': case '"': fputc(c,f); break;
        case 'b': fputc('\b',f); break;
        case 'f': fputc('\f',f); break;
        case 'n': fputc('\n',f); break;
        case 'r': fputc('\r',f); break;
        case 't': fputc('\t',f); break;
        case 'u':
          n=hex_char()<<12; n+=hex_char()<<8; n+=hex_char()<<4; n+=hex_char()<<0;
          if(n>=0xD800 && n<0xDC00) {
            u=n;
          } else if(u && n>=0xDC00 && n<0xE000) {
            send_unicode((n&0x3FF)+((u&0x3FF)<<10)+0x10000,f);
            u=0;
          } else {
            if(u) send_unicode(u,f);
            send_unicode(n,f);
            u=0;
          }
          break;
        default: errx(1,"Improper character in JSON string");
      }
    }
  }
  asn1_end(enc);
}

int main(int argc,char**argv) {
  int c;
  enc=asn1_create_encoder(stdout);
  while((c=getchar())>0) switch(c) {
    case ' ': case '\r': case '\n': case '\t': case ':': case ',': /* do nothing */ break;
    case '{': asn1_construct(enc,ASN1_UNIVERSAL,ASN1_KEY_VALUE_LIST,ASN1_KVSORT); break;
    case '[': asn1_construct(enc,ASN1_UNIVERSAL,ASN1_SEQUENCE,0); break;
    case '}': case ']': asn1_end(enc); break;
    case '-': case '0' ... '9': do_number(c); break;
    case '"': do_string(); break;
    case 't': if(getchar()!='r' || getchar()!='u' || getchar()!='e') goto bad; asn1_encode_boolean(enc,1); break;
    case 'f': if(getchar()!='a' || getchar()!='l' || getchar()!='s' || getchar()!='e') goto bad; asn1_encode_boolean(enc,0); break;
    case 'n': if(getchar()!='u' || getchar()!='l' || getchar()!='l') goto bad; asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_NULL,"",0); break;
    default: bad: errx(1,"Improper character in JSON data");
  }
  asn1_finish_encoder(enc);
  return 0;
}
