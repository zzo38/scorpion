#if 0
gcc -s -O2 -c base64.c
exit
#endif

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"

static const char base64alph[64]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int8_t base64alphd[80]={
  ['A'-43]=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,
  ['a'-43]=27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,
  ['0'-43]=53,54,55,56,57,58,59,60,61,62,
  ['+'-43]=63,
  ['/'-43]=64,
};

typedef struct {
  FILE*file;
  FILE*echo;
  uint32_t value;
  uint8_t width,maxwidth,phase,autoclose;
} Cookie_base64_enc;

static ssize_t write_base64_enc(void*cookie,const char*buf,size_t size) {
  Cookie_base64_enc*x=cookie;
  const uint8_t*b=buf;
  size_t n;
  if(x->echo) fwrite(buf,1,size,x->echo);
  for(n=0;n<size;n++) switch(x->phase) {
    case 0:
      x->value=b[n]<<16;
      x->phase=1;
      break;
    case 1:
      x->value|=b[n]<<8;
      x->phase=2;
      break;
    case 2:
      x->value|=b[n];
      fputc(base64alph[(x->value>>18)&63],x->file);
      fputc(base64alph[(x->value>>12)&63],x->file);
      fputc(base64alph[(x->value>>6)&63],x->file);
      fputc(base64alph[(x->value>>0)&63],x->file);
      if(x->maxwidth && ++x->width==x->maxwidth) x->width=0,fputc('\n',x->file);
      x->phase=0;
      break;
  }
  return size;
}

static int close_base64_enc(void*cookie) {
  Cookie_base64_enc*x=cookie;
  char y[64];
  switch(x->phase) {
    case 1:
      fputc(base64alph[(x->value>>18)&63],x->file);
      fputc(base64alph[(x->value>>12)&63],x->file);
      fputc('=',x->file);
      fputc('=',x->file);
      break;
    case 2:
      fputc(base64alph[(x->value>>18)&63],x->file);
      fputc(base64alph[(x->value>>12)&63],x->file);
      fputc(base64alph[(x->value>>6)&63],x->file);
      fputc('=',x->file);
      break;
  }
  if(x->width || x->phase || !x->maxwidth) fputc('\n',x->file);
  return x->autoclose?fclose(x->file):0;
}

FILE*open_base64_enc(FILE*f,uint8_t width,FILE*echo,char autoclose) {
  Cookie_base64_enc*x;
  if(!f) return 0;
  x=calloc(1,sizeof(Cookie_base64_enc));
  if(!x) return 0;
  x->file=f;
  x->maxwidth=width;
  x->echo=echo;
  x->autoclose=autoclose;
  f=fopencookie(x,"w",(cookie_io_functions_t){.write=write_base64_enc,.close=close_base64_enc});
  if(!f) free(x);
  return f;
}

typedef struct {
  FILE*file;
  const char*text;
  int(*filter)(FILE*,const char*,const char*);
  uint32_t value;
  char buffer[80];
  uint8_t phase,autoclose,outer,eof;
} Cookie_base64_dec;

static ssize_t read_base64_dec(void*cookie,char*buf,size_t size) {
  Cookie_base64_dec*x=cookie;
  size_t total=0;
  int c;
  while(total<size && !x->eof) {
    c=fgetc(x->file);
    if(c==EOF) x->eof=1;
    if(x->outer) {
      if(c==EOF) break;
      if(c=='\n' && x->phase>16 && x->phase<91) {
        c=x->phase-11;
        x->phase=0;
        if(!memcmp(x->buffer+c-5,"-----",5)) {
          x->buffer[c-5]=0;
          c=x->filter(x->file,x->text,x->buffer);
          if(c&BASE64_FILTER_MATCH) x->outer=0;
          if(c&BASE64_FILTER_LAST) {
            x->filter=0;
            x->eof=x->outer;
          }
        }
      } else if(c=='\n') {
        x->phase=0;
      } else if(x->phase<11 && "-----BEGIN "[x->phase]==c) {
        x->phase++;
      } else if(x->phase>10 && x->phase<91 && c>31) {
        x->buffer[x->phase-11]=c;
        x->phase++;
      } else {
        x->phase=255;
      }
    } else if(c=='-' || c==EOF) {
      x->outer=1;
      x->phase=1;
      if(!x->filter) x->eof=1;
    } else if(c>32 && c!='=') {
      if(c<43 || c>122 || !(c=base64alphd[c-43])) {
        x->eof=2;
        break;
      }
      x->buffer[x->phase++]=c-1;
      switch(x->phase) {
        case 2: buf[total++]=(x->buffer[0]<<2)|(x->buffer[1]>>4); break;
        case 3: buf[total++]=(x->buffer[1]<<4)|(x->buffer[2]>>2); break;
        case 4: buf[total++]=(x->buffer[2]<<6)|(x->buffer[3]>>0); x->phase=0;
      }
    }
  }
  return total?:ferror(x->file)?-1:x->eof==2?-1:0;
}

static int close_base64_dec(void*cookie) {
  Cookie_base64_dec*x=cookie;
  return x->autoclose?fclose(x->file):0;
}

FILE*open_base64_dec(FILE*f,char autoclose) {
  Cookie_base64_dec*x;
  if(!f) return 0;
  x=calloc(1,sizeof(Cookie_base64_dec));
  if(!x) return 0;
  x->file=f;
  x->autoclose=autoclose;
  f=fopencookie(x,"r",(cookie_io_functions_t){.read=read_base64_dec,.close=close_base64_dec});
  if(!f) free(x);
  return f;
}

static int default_pem_filter(FILE*f,const char*t1,const char*t2) {
  return t1?(strcmp(t1,t2)?0:BASE64_FILTER_MATCH):BASE64_FILTER_MATCH;
}

FILE*open_base64_pem_dec(FILE*f,const char*text,int(*filter)(FILE*,const char*,const char*),char autoclose) {
  Cookie_base64_dec*x;
  if(!f) return 0;
  x=calloc(1,sizeof(Cookie_base64_dec));
  if(!x) return 0;
  x->file=f;
  x->text=text;
  x->filter=filter?:default_pem_filter;
  x->autoclose=autoclose;
  x->outer=1;
  f=fopencookie(x,"r",(cookie_io_functions_t){.read=read_base64_dec,.close=close_base64_dec});
  if(!f) free(x);
  return f;
}
