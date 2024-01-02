#if 0
gcc -s -O2 -c scorpionlib.c
exit
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scorpionlib.h"

void scorpionlib_ask(const char*in,char*out,int len,const char*prompt) {
  if(scorpionlib_query(in,out,len)) return;
  printf("10 %s\r\n",prompt);
  exit(0);
}

void scorpionlib_bad_request(void) {
  puts("59 Bad request\r");
  exit(0);
}

void scorpionlib_begin(const char*type,const char*version) {
  printf("20 ? %s%s%s\r\n",type,version?" ":"",version?:"");
}

void scorpionlib_begin_size(char kind,unsigned long size,const char*type,const char*version) {
  printf("2%c %lu %s%s%s\r\n",kind,size,type,version?" ":"",version?:"");
}

void scorpionlib_error(const char*text) {
  printf("50 %s\r\n",text?:"Permanent error");
  exit(0);
}

void scorpionlib_forbid(void) {
  puts("54 Forbidden\r");
  exit(0);
}

int scorpionlib_fputc_pc(int code,FILE*file) {
  code&=255;
  if(!code) return -1;
  if(code<0x20) fputc(0x10,file),code+=0x40;
  return fputc(code,file);
}

int scorpionlib_fputc_tron8(unsigned int*state,unsigned long code,FILE*file) {
  unsigned int i;
  if(i=code>>16) {
    if(!state || (*state&0xFFFF)!=i) {
      if(state) *state=i;
      fputc(0xFE,file);
      while(i--) fputc(0xFE,file);
    }
    fputc(code>>8,file);
  }
  return fputc(code,file);
}

void scorpionlib_fputs_pc(const char*text,FILE*file) {
  const unsigned char*t=(const unsigned char*)text;
  while(*t) {
    if(*t>=0x20) {
      fputc(*t++,file);
    } else {
      fputc(0x10,file);
      fputc(*t++|0x40,file);
    }
  }
}

int scorpionlib_fputs_tron8(unsigned int*state,const char*text,FILE*file) {
  if(state) {
    const char*x;
    unsigned int i=0;
    while(i<(*state>>16) && text[i]==(char)0xFE) i++;
    if(i==(*state>>16) && text[i]==(char)(*state&255)) text+=i+1;
    if((x=strrchr(text,0xFE)) && x[1]) {
      *state=x[1]&255;
      while(x>text && x[-1]==(char)0xFE) x--,*state+=0x100;
    }
  }
  return fputs(text,file);
}

void scorpionlib_not_found(void) {
  puts("51 File not found\r");
  exit(0);
}

void scorpionlib_print_block(int type,const char*adata,int alen,const char*bdata,int blen) {
  scorpionlib_write_block(stdout,type,adata,alen,bdata,blen);
}

int scorpionlib_query(const char*in,char*out,int len) {
  int n=0;
  int c;
  for(;;) {
    if(*in=='#' || !*in) return 0;
    if(*in=='?') {
      in++;
      while(n<len) {
        if(*in=='#' || !*in) break;
        if(*in=='+') {
          out[n++]=' ';
          in++;
        } else if(*in!='%') {
          out[n++]=*in++;
        } else {
          in++;
          if(*in>='0' && *in<='9') c=*in++-'0';
          else if(*in>='A' && *in<='F') c=*in++-'A'+10;
          else if(*in>='a' && *in<='f') c=*in++-'a'+10;
          else scorpionlib_bad_request();
          c<<=4;
          if(*in>='0' && *in<='9') c|=*in++-'0';
          else if(*in>='A' && *in<='F') c|=*in++-'A'+10;
          else if(*in>='a' && *in<='f') c|=*in++-'a'+10;
          else scorpionlib_bad_request();
          out[n++]=c;
        }
      }
      return 1;
    }
    in++;
  }
}

int scorpionlib_receiver(const char*req,unsigned long*start,unsigned long*end,char*kind) {
  const char*p=req+1;
  if(*req!='R') return 0;
  if(*p!=' ') {
    if(!start || !end) return 0;
    *kind='1';
    *start=0;
    while(*p>='0' && *p<='9') *start=*start*10+*p++-'0';
    if(*p++!='-') return 0;
    if(*p==' ') return 1;
    *end=0;
    while(*p>='0' && *p<='9') *end=*end*10+*p++-'0';
  } else {
    *kind='0';
    if(start) *start=0;
  }
  return 1;
}

void scorpionlib_redirect(char perm,const char*target) {
  printf("3%c %s\r\n",perm?'1':'0',target);
  exit(0);
}

int scorpionlib_user_info(const char*req,char*user,int userlen,char*pass,int passlen) {
  unsigned int i,c;
  req=strchr(req,' ');
  if(!req) return 0;
  while(*req!=':') req++;
  while(*req=='/') req++;
  for(i=0;;) {
    if(*req=='@') {
      req++;
      user[i]=0;
      *pass=0;
      return 1;
    } else if(*req==':') {
      req++;
      user[i]=0;
      break;
    } else if(*req=='%') {
      if(i==userlen) return 0;
      req++;
      if(*req>='0' && *req<='9') c=*req++-'0';
      else if(*req>='A' && *req<='F') c=*req++-'A'+10;
      else if(*req>='a' && *req<='f') c=*req++-'a'+10;
      else return 0;
      c<<=4;
      if(*req>='0' && *req<='9') c|=*req++-'0';
      else if(*req>='A' && *req<='F') c|=*req++-'A'+10;
      else if(*req>='a' && *req<='f') c|=*req++-'a'+10;
      else return 0;
      user[i++]=c;
    } else if(*req=='/' || !*req) {
      return 0;
    } else {
      if(i==userlen) return 0;
      user[i++]=*req++;
    }
  }
  for(i=0;;) {
    if(*req=='@') {
      req++;
      pass[i]=0;
      return 2;
    } else if(*req=='%') {
      if(i==passlen) return 0;
      req++;
      if(*req>='0' && *req<='9') c=*req++-'0';
      else if(*req>='A' && *req<='F') c=*req++-'A'+10;
      else if(*req>='a' && *req<='f') c=*req++-'a'+10;
      else return 0;
      c<<=4;
      if(*req>='0' && *req<='9') c|=*req++-'0';
      else if(*req>='A' && *req<='F') c|=*req++-'A'+10;
      else if(*req>='a' && *req<='f') c|=*req++-'a'+10;
      else return 0;
      pass[i++]=c;
    } else if(*req=='/' || !*req) {
      return 0;
    } else {
      if(i==passlen) return 0;
      pass[i++]=*req++;
    }
  }
}

void scorpionlib_write_block(FILE*fp,int type,const char*adata,int alen,const char*bdata,int blen) {
  fputc(type,fp);
  fputc(alen>>8,fp); fputc(alen,fp);
  fwrite(adata,1,alen,fp);
  fputc(blen>>16,fp); fputc(blen>>8,fp); fputc(blen,fp);
  fwrite(bdata,1,blen,fp);
}

