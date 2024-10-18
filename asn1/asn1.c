#if 0
gcc -s -O2 -c -fwrapv asn1.c
exit
#endif

// Public domain implementation of ASN.1 BER/DER in C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "asn1.h"

int asn1_parse(const uint8_t*data,size_t length,ASN1*out,size_t*next) {
  char indef=0;
  int x;
  uint64_t y;
  size_t at=1;
  if(!out) return ASN1_ERROR;
  out->own=0;
  out->data=0;
  out->length=0;
  if(length<2) return ASN1_TOO_SHORT;
  if(!data) return ASN1_ERROR;
  out->class=*data>>6;
  out->constructed=(*data>>5)&1;
  out->type=*data&31;
  if(out->type==31) {
    out->type=0;
    do {
      if(at>=length) return ASN1_TOO_SHORT;
      if(out->type&0xFE000000L) return ASN1_IMPROPER_ENCODING;
      out->type<<=7;
      out->type|=data[at]&0x7F;
    } while(data[at++]&0x80);
  }
  if(at>=length) return ASN1_TOO_SHORT;
  if(data[at]<0x80) {
    out->length=data[at++];
  } else {
    if(data[at]==0x80) {
      if(!out->constructed) return ASN1_IMPROPER_ENCODING;
      indef=1;
    } else {
      if(data[at]==0xFF) return ASN1_IMPROPER_ENCODING;
      x=data[at++]&0x7F;
      if(at+x>length) return ASN1_TOO_SHORT;
      y=0;
      while(x--) {
        y=(y<<8)|data[at++];
        if(y&0xFFF0000000000000ULL) return ASN1_TOO_BIG;
      }
      if(at+y>length || (y!=(size_t)y)) return ASN1_TOO_SHORT;
      out->length=y;
    }
  }
  out->data=data+at;
  if(indef) {
    ASN1 rel;
    for(out->length=0;;) {
      if(at<length && !data[at]) {
        if(at+2>length) return ASN1_TOO_SHORT;
        if(data[at+1]) return ASN1_IMPROPER_ENCODING;
        break;
      } else if(length<=at+out->length) {
        return ASN1_TOO_SHORT;
      }
      if(x=asn1_parse(data+at+out->length,length-at-out->length,&rel,&out->length)) return x;
    }
  }
  if(next) *next+=at+out->length;
  return ASN1_OK;
}

int asn1_distinguished_parse(const uint8_t*data,size_t length,ASN1*out,size_t*next) {
  int x;
  uint64_t y;
  size_t at=1;
  if(!out) return ASN1_ERROR;
  out->own=0;
  out->data=0;
  out->length=0;
  if(length<2) return ASN1_TOO_SHORT;
  if(!data) return ASN1_ERROR;
  out->class=*data>>6;
  out->constructed=(*data>>5)&1;
  out->type=*data&31;
  if(out->type==31) {
    out->type=0;
    do {
      if(at>=length) return ASN1_TOO_SHORT;
      if(out->type&0xFE000000L) return ASN1_IMPROPER_ENCODING;
      out->type<<=7;
      out->type|=data[at]&0x7F;
    } while(data[at++]&0x80);
    if(out->type>30) return ASN1_IMPROPER_ENCODING;
  }
  if(at>=length) return ASN1_TOO_SHORT;
  if(data[at]<0x80) {
    out->length=data[at++];
  } else {
    if(data[at]==0x80 || data[at]==0xFF) return ASN1_IMPROPER_ENCODING;
    x=data[at++]&0x7F;
    if(at+x>length) return ASN1_TOO_SHORT;
    if(!data[at]) return ASN1_IMPROPER_ENCODING;
    y=0;
    while(x--) {
      y=(y<<8)|data[at++];
      if(y&0xFFF0000000000000ULL) return ASN1_TOO_BIG;
    }
    if(y<0x80) return ASN1_IMPROPER_ENCODING;
    if(at+y>length || (y!=(size_t)y)) return ASN1_TOO_SHORT;
    out->length=y;
  }
  out->data=data+at;
  if(next) *next+=at+out->length;
  return ASN1_OK;
}

void asn1_write_type(uint8_t constructed,uint8_t class,uint32_t type,FILE*stream) {
  fputc((type>30?31:type)|(class<<6)|(constructed?0x20:0x00),stream);
  if(type>30) {
    if(type>=(1ULL<<28)) fputc((type>>28)&0x7F,stream);
    if(type>=(1ULL<<21)) fputc((type>>21)&0x7F,stream);
    if(type>=(1ULL<<14)) fputc((type>>14)&0x7F,stream);
    if(type>=(1ULL<<7)) fputc((type>>7)&0x7F,stream);
    fputc(type&0x7F,stream);
  }
}

void asn1_write_length(uint64_t length,FILE*stream) {
  if(length<128) {
    fputc(length,stream);
  } else {
    uint8_t n=1;
    if(length>=0x100ULL) n=2;
    if(length>=0x10000ULL) n=3;
    if(length>=0x1000000ULL) n=4;
    if(length>=0x100000000ULL) n=5;
    if(length>=0x10000000000ULL) n=6;
    if(length>=0x1000000000000ULL) n=7;
    if(length>=0x100000000000000ULL) n=8;
    fputc(n+128,stream);
    while(n--) fputc(length>>(n*8),stream);
  }
}

static int convert_type(const ASN1*asn,ASN1*rel) {
  size_t s=0;
  int x;
  if(asn->class==ASN1_UNIVERSAL) {
    return 0;
  } else if(asn->class==ASN1_CONTEXT_SPECIFIC) {
    // Assume explicit type
    if(!asn->constructed) return ASN1_IMPROPER_TYPE;
    if(x=asn1_parse(asn->data,asn->length,rel,&s)) return x;
    if(s!=asn->length) return ASN1_IMPROPER_TYPE;
    return (rel->class==ASN1_UNIVERSAL?-1:ASN1_IMPROPER_TYPE);
  } else {
    return ASN1_IMPROPER_TYPE;
  }
}
#define CONVERT_TYPE ASN1 rel; if(!type) { int x=convert_type(asn,&rel); if(x>0) return x; if(x==-1) asn=&rel,type=rel.type; else type=asn->type; }

static size_t print_base128(const uint8_t*data,uint32_t adjust,FILE*stream) {
  uint8_t u[80];
  int8_t n=1;
  int8_t m;
  uint32_t x,y;
  size_t at=0;
  if(!*data) {
    fputc('0',stream);
    return 1;
  }
  *u=0;
  for(;;) {
    y=data[at]&0x7F;
    for(m=0;m<n;m++) {
      x=u[m]*128+y;
      u[m]=x%100;
      y=x/100;
    }
    while(y) {
      if(n==79) {
        fputc('?',stream);
        while(data[at]&0x80) at++;
        return at+1;
      }
      u[n++]=y%100;
      y/=100;
    }
    if(data[at]<0x80) break;
    at++;
  }
  if(y=adjust) {
    for(m=0;m<n;m++) {
      if(u[m]>=y) {
        u[m]-=y;
        break;
      } else {
        u[m]+=100-y;
        y=1;
      }
    }
    if(!u[n-1]) n--;
  }
  if(u[n-1]>9) fputc(u[n-1]/10+'0',stream);
  fputc(u[n-1]%10+'0',stream);
  for(m=n-2;m>=0;m--) {
    fputc(u[m]/10+'0',stream);
    fputc(u[m]%10+'0',stream);
  }
  return at+1;
}

int asn1_print_decimal_oid(const ASN1*asn,uint32_t type,FILE*stream) {
  size_t at=0;
  CONVERT_TYPE;
  if((type!=ASN1_OID && type!=ASN1_RELATIVE_OID) || asn->constructed) return ASN1_IMPROPER_TYPE;
  if(!asn->length || asn->data[0]==0x80 || (asn->length==1 && asn->data[0]>0x80)) return ASN1_IMPROPER_VALUE;
  if(asn->data[asn->length-1]&0x80) return ASN1_IMPROPER_VALUE;
  if(type==ASN1_OID) {
    if(asn->data[0]<120) {
      fprintf(stream,"%d.%d",asn->data[0]/40,asn->data[0]%40);
      at=1;
    } else {
      fwrite("2.",1,2,stream);
      at=print_base128(asn->data,80,stream);
    }
  } else {
    fputc('.',stream);
  }
  while(at<asn->length) {
    fputc('.',stream);
    if(asn->data[at]==0x80) {
      fputc('?',stream);
      fputc('?',stream);
      return ASN1_IMPROPER_VALUE;
    }
    at+=print_base128(asn->data+at,0,stream);
  }
  return ASN1_OK;
}

int asn1_get_bit(const ASN1*asn,uint32_t type,uint64_t which,int*out) {
  int x;
  uint64_t u;
  CONVERT_TYPE;
  switch(type) {
    case ASN1_BIT_STRING:
      if(asn->constructed) {
        ASN1 o;
        size_t n=0;
        while(n!=asn->length) {
          if(x=asn1_parse(asn->data,asn->length-n,&o,&n)) return x;
          if(n==asn->length) {
            u=(o.length-1)*8LL-(o.data[0]&7);
            if(which<u) {
              *out=(o.data[which/8+1]&(0x80>>(which&7)))?1:0;
              return ASN1_OK;
            }
          } else {
            u=o.length*8LL;
            if(which<u) {
              *out=(o.data[which/8]&(0x80>>(which&7)))?1:0;
              return ASN1_OK;
            }
          }
          which-=o.length*8LL;
        }
      } else {
        if(!asn->length) return ASN1_IMPROPER_VALUE;
        u=(asn->length-1)*8LL-(asn->data[0]&7);
        if(which<u) *out=(asn->data[which/8+1]&(0x80>>(which&7)))?1:0;
      }
      return ASN1_OK;
    case ASN1_OCTET_STRING:
      if(asn->constructed) {
        ASN1 o;
        size_t n=0;
        while(n!=asn->length) {
          if(x=asn1_parse(asn->data,asn->length-n,&o,&n)) return x;
          if(o.constructed) return ASN1_IMPROPER_VALUE;
          if(which<o.length*8LL) {
            *out=(o.data[which/8]&(1<<(which&7)))?1:0;
            return ASN1_OK;
          }
          which-=o.length;
        }
      } else {
        if(which<asn->length*8LL) *out=(asn->data[which/8]&(1<<(which&7)))?1:0;
      }
      return ASN1_OK;
    case ASN1_INTEGER:
      if(asn->constructed) return ASN1_IMPROPER_TYPE;
      if(!asn->length) return ASN1_IMPROPER_VALUE;
      if(which>=asn->length*8LL) which=asn->length*8-1;
      *out=(asn->data[asn->length-1-(which/8)]&(1<<(which&7)))?1:0;
      return ASN1_OK;
    case ASN1_BOOLEAN:
      if(asn->constructed) return ASN1_IMPROPER_TYPE;
      if(!asn->length) return ASN1_IMPROPER_VALUE;
      *out=(asn->data[0]?1:0);
      return ASN1_OK;
    default: return ASN1_IMPROPER_TYPE;
  }
}

int asn1_date_to_time(const ASN1_DateTime*in,time_t*out,uint32_t*nano) {
  const int16_t mon[12]={-1,30,58,89,119,150,180,211,242,272,303,333};
  int32_t leap;
  if(in->month<1 || in->month>12 || in->seconds>62) return ASN1_IMPROPER_VALUE;
  *out=(in->hours*60+in->minutes-in->zone)*60+(in->seconds<60?in->seconds:59);
  leap=in->year-(in->month<3);
  leap=(leap/4)-(leap/100)+(leap/400)-477;
  *out+=86400LL*(mon[in->month-1]+in->day+(in->year-1970)*365LL+leap);
  if(nano) *nano=in->nano+(in->seconds>59?(in->seconds-59)*1000000000L:0L);
  return ASN1_OK;
}

int asn1_time_to_date(time_t in,uint32_t nano,ASN1_DateTime*out) {
  struct tm tm;
  if(!gmtime_r(&in,&tm)) return ASN1_ERROR;
  out->seconds=tm.tm_sec;
  out->minutes=tm.tm_min;
  out->hours=tm.tm_hour;
  out->day=tm.tm_mday;
  out->month=tm.tm_mon+1;
  out->year=tm.tm_year+1900;
  if(nano>=1000000000L) {
    if(out->seconds!=59) return ASN1_IMPROPER_VALUE;
    out->seconds+=nano/1000000000L;
    nano%=1000000000L;
  }
  out->nano=nano;
  out->zone=0;
  return ASN1_OK;
}

int asn1_from_c_string(uint8_t class,uint32_t type,const char*data,ASN1*out) {
  if(!data || !out) return ASN1_ERROR;
  out->own=0;
  out->constructed=0;
  out->data=(const uint8_t*)data;
  out->length=strlen(data);
  out->class=class;
  out->type=type;
  return ASN1_OK;
}

static size_t make_oid_part(const char**text,uint8_t*buf,size_t maxlen,char add80) {
  // Converts ASCII base ten to base 128 and moves it to the beginning of the buffer.
  // Returns the number of output bytes, or 0 if it is too big.
  size_t m=maxlen-1;
  size_t n;
  uint32_t x,carry;
  if(!maxlen) return 0;
  buf[m]=0;
  while(**text>='0' && **text<='9') {
    carry=**text-'0';
    for(n=maxlen-1;;) {
      x=buf[n]*10+carry;
      buf[n]=x&0x7F;
      carry=x>>7;
      if(n==m) break; else n--;
    }
    if(carry) {
      if(!m) return 0;
      buf[--m]=carry;
      carry=0;
    }
    ++*text;
  }
  if(add80) {
    carry=80;
    for(n=maxlen-1;carry;) {
      x=buf[n]+carry;
      buf[n]=x&0x7F;
      carry=x>>7;
      if(n==m) break; else n--;
    }
    if(carry) {
      if(!m) return 0;
      buf[--m]=carry;
    }
  }
  for(n=m;n<maxlen;n++) buf[n-m]=buf[n]+(n==maxlen-1?0:0x80);
  return maxlen-m;
}

int asn1_make_static_oid(const char*text,uint8_t*buf,size_t maxlen,ASN1*out) {
  char c;
  size_t m;
  if(!text || !buf || !maxlen || !out) return ASN1_ERROR;
  out->data=buf;
  out->length=0;
  out->own=0;
  switch(c=*text) {
    case '0': case '1':
      if(text[1]!='.') return ASN1_IMPROPER_VALUE;
      c-='0';
      text+=2;
      if(*text<'0' || *text>'9') return ASN1_IMPROPER_VALUE;
      m=make_oid_part(&text,buf,1,0);
      if(*buf>=40) return ASN1_IMPROPER_VALUE;
      if(c) *buf+=40;
      goto more;
    case '2':
      if(text[1]!='.') return ASN1_IMPROPER_VALUE;
      text+=2;
      if(*text<'0' || *text>'9') return ASN1_IMPROPER_VALUE;
      m=make_oid_part(&text,buf,maxlen,1);
    more:
      if(!m) return ASN1_TOO_SHORT;
      buf+=m;
      out->length+=m;
      maxlen-=m;
      if(*text=='.') {
        ++text;
        if(*text<'0' || *text>'9') return ASN1_IMPROPER_VALUE;
        m=make_oid_part(&text,buf,maxlen,0);
        goto more;
      } else if(*text) {
        return ASN1_IMPROPER_VALUE;
      }
      break;
    default: return ASN1_IMPROPER_VALUE;
  }
  out->constructed=0;
  out->class=ASN1_UNIVERSAL;
  out->type=ASN1_OID;
  return ASN1_OK;
}

int asn1_make_oid(const char*text,ASN1*out) {
  uint8_t w[256];
  uint8_t*p;
  int x;
  if(x=asn1_make_static_oid(text,w,256,out)) {
    out->data=0;
    out->length=0;
    out->own=0;
    return x;
  }
  p=malloc(out->length);
  if(!p) {
    out->data=0;
    out->length=0;
    out->own=0;
    return ASN1_ERROR;
  }
  memcpy(p,out->data,out->length);
  out->data=p;
  out->own=1;
  return ASN1_OK;
}

void asn1_free(ASN1*obj) {
  if(obj->own) free((void*)(obj->data));
  obj->data=0;
  obj->length=0;
  obj->own=0;
}

// Decoding

#define UNSIGNED_DECODE(M) \
  size_t n; \
  uint64_t i; \
  CONVERT_TYPE; \
  if(asn->constructed || (type!=ASN1_INTEGER && type!=ASN1_ENUMERATED)) return ASN1_IMPROPER_TYPE; \
  *out=0; \
  if(!asn->length) return ASN1_IMPROPER_VALUE; \
  if(asn->data[0]&0x80) return ASN1_OVERFLOW; \
  for(i=0,n=asn->length-1;;n--,i+=8) { \
    if(i<M) *out|=((uint64_t)(asn->data[n]))<<i; else if(asn->data[n]) return ASN1_OVERFLOW; \
    if(!n) return ASN1_OK; \
  }

int asn1_decode_uint8(const ASN1*asn,uint32_t type,uint8_t*out) {
  UNSIGNED_DECODE(8);
}

int asn1_decode_uint16(const ASN1*asn,uint32_t type,uint16_t*out) {
  UNSIGNED_DECODE(16);
}

int asn1_decode_uint32(const ASN1*asn,uint32_t type,uint32_t*out) {
  UNSIGNED_DECODE(32);
}

int asn1_decode_uint64(const ASN1*asn,uint32_t type,uint64_t*out) {
  UNSIGNED_DECODE(64);
}

#define SIGNED_DECODE(M) \
  size_t n; \
  uint64_t i; \
  CONVERT_TYPE; \
  if(asn->constructed || (type!=ASN1_INTEGER && type!=ASN1_ENUMERATED)) return ASN1_IMPROPER_TYPE; \
  if(!asn->length) return ASN1_IMPROPER_VALUE; \
  if(asn->data[0]&0x80) { \
    *out=-1; \
    for(i=0,n=asn->length-1;;n--,i+=8) { \
      if(i>=M-8 && !(asn->data[n]&0x80)) return ASN1_OVERFLOW; \
      if(i<M) *out&=~(((uint64_t)(0xFF^asn->data[n]))<<i); else if(asn->data[n]!=0xFF) return ASN1_OVERFLOW; \
      if(!n) return ASN1_OK; \
    } \
  } else { \
    *out=0; \
    for(i=0,n=asn->length-1;;n--,i+=8) { \
      if(i>=M-8 && (asn->data[n]&0x80)) return ASN1_OVERFLOW; \
      if(i<M) *out|=((uint64_t)(asn->data[n]))<<i; else if(asn->data[n]) return ASN1_OVERFLOW; \
      if(!n) return ASN1_OK; \
    } \
  }

int asn1_decode_int8(const ASN1*asn,uint32_t type,int8_t*out) {
  SIGNED_DECODE(8);
}

int asn1_decode_int16(const ASN1*asn,uint32_t type,int16_t*out) {
  SIGNED_DECODE(16);
}

int asn1_decode_int32(const ASN1*asn,uint32_t type,int32_t*out) {
  SIGNED_DECODE(32);
}

int asn1_decode_int64(const ASN1*asn,uint32_t type,int64_t*out) {
  SIGNED_DECODE(64);
}

#define TWO_DIGITS(M,V) do { \
  if(asn->length<M+2 || asn->data[M]<'0' || asn->data[M]>'9' || asn->data[(M)+1]<'0' || asn->data[(M)+1]>'9') return ASN1_IMPROPER_VALUE; \
  V=(asn->data[M]-'0')*10+asn->data[(M)+1]-'0'; \
} while(0)

int asn1_decode_date(const ASN1*asn,uint32_t type,ASN1_DateTime*out) {
  int x,y;
  uint32_t z;
  CONVERT_TYPE;
  switch(type) {
    case ASN1_UTCTIME:
      out->nano=0;
      TWO_DIGITS(0,out->year);
      out->year+=(out->year<50?2000:1900);
      TWO_DIGITS(2,out->month);
      TWO_DIGITS(4,out->day);
      TWO_DIGITS(6,out->hours);
      TWO_DIGITS(8,out->minutes);
      if(asn->length>10 && (asn->data[10]=='Z' || asn->data[10]=='+' || asn->data[10]=='-')) {
        out->seconds=0;
        x=10;
      } else {
        TWO_DIGITS(10,out->seconds);
        x=12;
      }
      if(asn->length<=x) return ASN1_IMPROPER_VALUE;
    zone:
      if(asn->data[x]=='Z') {
        out->zone=0;
        x++;
      } else if(asn->data[x]=='+' || asn->data[x]=='-') {
        TWO_DIGITS(x+1,y);
        TWO_DIGITS(x+3,out->zone);
        out->zone+=y*60;
        if(asn->data[x]=='-') out->zone*=-1;
        x+=5;
      } else {
        return ASN1_IMPROPER_VALUE;
      }
      if(x==asn->length) return ASN1_OK; else return ASN1_IMPROPER_VALUE;
    case ASN1_GENERALIZEDTIME:
      out->nano=0;
      TWO_DIGITS(0,y);
      TWO_DIGITS(2,out->year);
      out->year+=100*y;
      TWO_DIGITS(4,out->month);
      TWO_DIGITS(6,out->day);
      TWO_DIGITS(8,out->hours);
      if(asn->length>10 && asn->data[10]>='0' && asn->data[10]<='9') {
        TWO_DIGITS(10,out->minutes);
        if(asn->length>12 && asn->data[12]>='0' && asn->data[12]<='9') {
          TWO_DIGITS(12,out->seconds);
          x=14;
        } else {
          out->seconds=0;
          x=12;
        }
      } else {
        out->minutes=out->seconds=0;
        x=10;
      }
      if(asn->length>x && (asn->data[x]=='.' || asn->data[x]==',')) {
        z=100000000;
        x++;
        while(asn->length>x && asn->data[x]>='0' && asn->data[x]<='9') {
          out->nano+=z*(asn->data[x++]-'0');
          z/=10;
        }
      }
      if(x==asn->length) return ASN1_OK; else goto zone;
    case ASN1_DATE:
      if(asn->length!=10) return ASN1_IMPROPER_VALUE;
      if(asn->data[4]!='-' || asn->data[7]!='-') return ASN1_IMPROPER_VALUE;
      TWO_DIGITS(0,y);
      TWO_DIGITS(2,out->year);
      out->year+=100*y;
      TWO_DIGITS(5,out->month);
      TWO_DIGITS(8,out->day);
      return ASN1_OK;
    case ASN1_TIME_OF_DAY:
      if(asn->length!=8) return ASN1_IMPROPER_VALUE;
      if(asn->data[2]!=':' || asn->data[5]!=':') return ASN1_IMPROPER_VALUE;
      TWO_DIGITS(0,out->hours);
      TWO_DIGITS(3,out->minutes);
      TWO_DIGITS(6,out->seconds);
      return ASN1_OK;
    case ASN1_DATE_TIME:
      if(asn->length!=19) return ASN1_IMPROPER_VALUE;
      if(asn->data[4]!='-' || asn->data[7]!='-' || asn->data[10]!='T' || asn->data[13]!=':' || asn->data[16]!=':') return ASN1_IMPROPER_VALUE;
      TWO_DIGITS(0,y);
      TWO_DIGITS(2,out->year);
      out->year+=100*y;
      TWO_DIGITS(5,out->month);
      TWO_DIGITS(8,out->day);
      TWO_DIGITS(11,out->hours);
      TWO_DIGITS(14,out->minutes);
      TWO_DIGITS(17,out->seconds);
      return ASN1_OK;
    default: return ASN1_IMPROPER_TYPE;
  }
}

int asn1_decode_time(const ASN1*asn,uint32_t type,int16_t zone,time_t*out,uint32_t*nano) {
  ASN1_DateTime d={.zone=zone};
  return asn1_decode_date(asn,type,&d)?:asn1_date_to_time(&d,out,nano);
}

int asn1_decode_real_parts(const ASN1*asn,uint32_t type,uint8_t*significand,size_t length,int8_t*sign,uint8_t*decimal,int64_t*exponent,uint8_t*infinite,uint8_t*exact) {
  // Not fully tested
  char d,k;
  int64_t q;
  size_t m,n;
  CONVERT_TYPE;
  if(exact) *exact=0;
  if(!length) return ASN1_IMPROPER_ARGUMENT;
  if(type==ASN1_REAL) {
    if(!asn->length) {
      memset(significand,0,length);
      *sign=1;
      *decimal=0;
      *infinite=0;
      *exponent=0;
      if(exact) *exact=1;
      return ASN1_OK;
    }
    if((asn->data[0]&0xC0)==0x40) {
      if(asn->length!=1) return ASN1_IMPROPER_VALUE;
      memset(significand,0,length);
      *decimal=0;
      *exponent=0;
      if(exact) *exact=1;
      switch(asn->data[0]) {
        case 0x40: *infinite=1; *sign=1; return ASN1_OK;
        case 0x41: *infinite=1; *sign=-1; return ASN1_OK;
        case 0x42: *infinite=1; *sign=0; return ASN1_OK;
        case 0x43: *infinite=0; *sign=-1; return ASN1_OK;
        default: if(exact) *exact=0; return ASN1_IMPROPER_VALUE;
      }
    }
    *infinite=0;
    if(asn->data[0]&0x80) {
      if(!(0x30&~asn->data[0])) return ASN1_IMPROPER_VALUE;
      *decimal=0;
      *sign=(asn->data[0]&0x40?-1:1);
      *exponent=(asn->data[0]>>2)&3; // scale factor
      n=(asn->data[0]&3)+1;
      if(n==4) {
        if(asn->length<2 || asn->length<asn->data[1]+2) return ASN1_IMPROPER_VALUE;
        if(asn->data[1]>8) return ASN1_OVERFLOW;
        q=(asn->data[2]&0x80)?-1:0;
        for(n=2;n<asn->data[1]+2;n++) q=128LL*q+asn->data[n];
        if((asn->data[0]&0x10) && (q>=0x2AAAAAAAAAAAAAAALL || q<=-0x2AAAAAAAAAAAAAAALL)) return ASN1_OVERFLOW;
        if((asn->data[0]&0x20) && (q>=0x1FFFFFFFFFFFFFFFLL || q<=-0x1FFFFFFFFFFFFFFFLL)) return ASN1_OVERFLOW;
      } else {
        if(asn->length<n+1) return ASN1_IMPROPER_VALUE;
        switch(n) {
          case 1: q=asn->data[1]; if(q&0x80) q-=0x100; break;
          case 2: q=(asn->data[1]<<8)|asn->data[2]; if(q&0x8000) q-=0x10000; break;
          case 3: q=(asn->data[1]<<16)|(asn->data[2]<<8)|asn->data[3]; if(q&0x800000) q-=0x1000000; break;
        }
        n++;
      }
      *exponent+=q*"\x01\x03\x04"[(asn->data[0]>>4)&3]-8LL*(asn->length-n);
      if(asn->length-n>length) {
        memcpy(significand,asn->data+n,length);
        if(exact) *exact=0;
      } else {
        memcpy(significand,asn->data+n,asn->length-n);
        if(asn->length-n<length) memset(significand+asn->length-n,0,length+n-asn->length);
        if(exact) *exact=1;
      }
    } else {
      if(asn->data[0]>3 || !asn->data[0]) return ASN1_IMPROPER_VALUE;
      *decimal=1;
      *sign=1;
      *exponent=0;
      memset(significand,0,length);
      for(n=1;n<asn->length && asn->data[n]==' ';n++);
      if(n==asn->length) return ASN1_IMPROPER_VALUE;
      if(asn->data[n]=='+') n++; else if(asn->data[n]=='-') n++,*sign=-1;
      d=1; k=1; m=0;
      while(n<asn->length && ((asn->data[n]>='0' && asn->data[n]<='9') || (d && asn->data[n]=='.'))) {
        if(asn->data[n]!='.') {
          if(m<length) {
            if(k) significand[m]=10*(asn->data[n]-'0'); else significand[m]+=asn->data[n]-'0';
          }
          m+=k^=1;
          *exponent+=d;
        } else {
          d=0;
        }
        n++;
      }
      if(n+1<asn->length && (asn->data[n]=='e' || asn->data[n]=='E')) {
        n++;
        k=0;
        q=0;
        if(asn->data[n]=='-') k=1,n++; else if(asn->data[n]=='+') n++;
        while(n<asn->length && asn->data[n]>='0' && asn->data[n]<='9') {
          if(q>99999999999999999LL) return ASN1_OVERFLOW;
          q=10LL*q+asn->data[n++]-'0';
        }
        *exponent+=(k?-q:q);
        if(k?(*exponent>q):(*exponent<q)) return ASN1_OVERFLOW;
      }
      if(n!=asn->length) return ASN1_IMPROPER_VALUE;
    }
  } else if(type==ASN1_INTEGER) {
    if(!asn->length) return ASN1_IMPROPER_VALUE;
    *decimal=0;
    *infinite=0;
    *exponent=8ULL*asn->length;
    if(exact) *exact=1;
    if(asn->length>length) {
      memcpy(significand,asn->data,length);
      if(exact) for(n=length;n<asn->length && *exact;n++) if(asn->data[n]) *exact=0;
    } else {
      memcpy(significand,asn->data,asn->length);
      if(asn->length<length) memset(significand+asn->length,0,length-asn->length);
    }
    if(asn->data[0]&0x80) {
      *sign=-1;
      for(n=0;n<length && n<asn->length;n++) significand[n]^=-1;
      if(length>=asn->length) {
        for(n=asn->length-1;;) {
          significand[n]++;
          if(significand[n--]) break;
        }
      } else {
        if(exact) *exact=0;
      }
    } else {
      *sign=1;
    }
  } else {
    return ASN1_IMPROPER_TYPE;
  }
  return ASN1_OK;
}

// Encoding

typedef struct Encoder {
  struct Encoder*next;
  FILE*file;
  char*mem;
  size_t size;
  uint8_t mode;
} Encoder;

struct ASN1_Encoder {
  FILE*file;
  Encoder*sub;
  uint32_t type;
  uint8_t class;
  uint8_t mode;
};

ASN1_Encoder*asn1_create_encoder(FILE*file) {
  ASN1_Encoder*enc;
  if(!file) return 0;
  enc=calloc(1,sizeof(ASN1_Encoder));
  if(!enc) return 0;
  enc->file=file;
  return enc;
}

int asn1_finish_encoder(ASN1_Encoder*enc) {
  int x;
  if(enc->sub) return ASN1_IMPROPER_MODE;
  x=fclose(enc->file)?ASN1_ERROR:ASN1_OK;
  free(enc);
  return x;
}

FILE*asn1_current_file(ASN1_Encoder*enc) {
  if(enc) return enc->file; else return 0;
}

int asn1_flush(ASN1_Encoder*enc) {
  if(enc) {
    if(fflush(enc->file)) return ASN1_ERROR;
  }
  return ASN1_OK;
}

int asn1_construct(ASN1_Encoder*enc,uint8_t class,uint32_t type,uint8_t mode) {
  Encoder e={.file=enc->file,.next=enc->sub,.mode=enc->mode};
  Encoder*p;
  FILE*f;
  if(mode&0xF3) return ASN1_IMPROPER_ARGUMENT;
  if(!(p=malloc(sizeof(Encoder)))) return ASN1_ERROR;
  *p=e;
  if(!(mode&ASN1_INDEFINITE)) {
    f=open_memstream(&p->mem,&p->size);
    if(!f) {
      free(p);
      return ASN1_ERROR;
    }
  }
  if(enc->class || enc->type) asn1_write_type(1,enc->class,enc->type,enc->file); else asn1_write_type(1,class,type,enc->file);
  if(mode&ASN1_INDEFINITE) fputc(128,enc->file); else enc->file=f;
  enc->sub=p;
  enc->mode=mode;
  enc->class=0;
  enc->type=0;
  return ASN1_OK;
}

int asn1_explicit(ASN1_Encoder*enc,uint8_t class,uint32_t type) {
  return asn1_construct(enc,class,type,ASN1_ONCE);
}

int asn1_implicit(ASN1_Encoder*enc,uint8_t class,uint32_t type) {
  if(enc->class || enc->type) return ASN1_IMPROPER_MODE;
  if(!class && !type) return ASN1_IMPROPER_ARGUMENT;
  enc->class=class;
  enc->type=type;
  return ASN1_OK;
}

int asn1_end(ASN1_Encoder*enc) {
  Encoder*p;
  again:
  p=enc->sub;
  if(!p) return ASN1_IMPROPER_MODE;
  if(enc->mode&ASN1_INDEFINITE) {
    fwrite("\0",1,2,enc->file);
  } else {
    if(fclose(enc->file) || (p->size && !p->mem)) {
      enc->sub=p->next;
      enc->mode=p->mode;
      enc->file=p->file;
      free(p->mem);
      free(p);
      return ASN1_ERROR;
    }
    asn1_write_length(p->size,p->file);
    if(p->size) fwrite(p->mem,1,p->size,p->file);
    free(p->mem);
  }
  enc->sub=p->next;
  enc->mode=p->mode;
  enc->file=p->file;
  free(p);
  if(enc->mode&ASN1_ONCE) goto again;
  return ASN1_OK;
}

int asn1_primitive(ASN1_Encoder*enc,uint8_t class,uint32_t type,const uint8_t*data,size_t length) {
  if(enc->class || enc->type) asn1_write_type(0,enc->class,enc->type,enc->file);
  else if(!class && !type) return ASN1_IMPROPER_TYPE;
  else asn1_write_type(0,class,type,enc->file);
  enc->class=0;
  enc->type=0;
  asn1_write_length(length,enc->file);
  if(length) fwrite(data,1,length,enc->file);
  return (enc->mode&ASN1_ONCE)?asn1_end(enc):ASN1_OK;
}

int asn1_encode(ASN1_Encoder*enc,const ASN1*value) {
  if(enc->class || enc->type) asn1_write_type(value->constructed,enc->class,enc->type,enc->file);
  else if(!value->class && !value->type) return ASN1_IMPROPER_TYPE;
  else asn1_write_type(value->constructed,value->class,value->type,enc->file);
  enc->class=0;
  enc->type=0;
  asn1_write_length(value->length,enc->file);
  if(value->length) fwrite(value->data,1,value->length,enc->file);
  return (enc->mode&ASN1_ONCE)?asn1_end(enc):ASN1_OK;
}

int asn1_wrap(ASN1_Encoder*enc) {
  Encoder e={.file=enc->file,.next=enc->sub,.mode=enc->mode};
  Encoder*p;
  FILE*f;
  if(!(p=malloc(sizeof(Encoder)))) return ASN1_ERROR;
  *p=e;
  f=open_memstream(&p->mem,&p->size);
  if(!f) {
    free(p);
    return ASN1_ERROR;
  }
  if(enc->class || enc->type) asn1_write_type(0,enc->class,enc->type,enc->file); else asn1_write_type(0,ASN1_UNIVERSAL,ASN1_OCTET_STRING,enc->file);
  enc->sub=p;
  enc->mode=ASN1_ONCE;
  enc->class=0;
  enc->type=0;
  return ASN1_OK;
}

FILE*asn1_primitive_stream(ASN1_Encoder*enc,uint8_t class,uint32_t type) {
  Encoder e={.file=enc->file,.next=enc->sub,.mode=enc->mode};
  Encoder*p;
  FILE*f;
  if(!(p=malloc(sizeof(Encoder)))) return 0;
  *p=e;
  f=open_memstream(&p->mem,&p->size);
  if(!f) {
    free(p);
    return 0;
  }
  if(enc->class || enc->type) asn1_write_type(0,enc->class,enc->type,enc->file); else asn1_write_type(0,class,type,enc->file);
  enc->sub=p;
  enc->mode=0;
  enc->class=0;
  enc->type=0;
  return f;
}

int asn1_encode_boolean(ASN1_Encoder*enc,int value) {
  return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_BOOLEAN,"\xFF"+(value?0:1),1);
}

int asn1_encode_oid(ASN1_Encoder*enc,const char*t) {
  uint8_t b[256];
  ASN1 x;
  return asn1_make_static_oid(t,b,256,&x)?:asn1_encode(enc,&x);
}

int asn1_encode_int8(ASN1_Encoder*enc,int8_t value) {
  return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_INTEGER,(uint8_t*)(&value),1);
}

int asn1_encode_int16(ASN1_Encoder*enc,int16_t value) {
  uint8_t x[2]={value>>8,value};
  int y=(x[0]==0xFF && x[1]>=0x80)?1:(x[0]==0x00 && x[1]<0x80)?1:0;
  return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_INTEGER,x+y,2-y);
}

int asn1_encode_int32(ASN1_Encoder*enc,int32_t value) {
  uint8_t x[4]={value>>030,value>>020,value>>010,value};
  int y=0;
  while(y!=3 && !x[y]) y++;
  return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_INTEGER,x+y,4-y);
}

int asn1_encode_int64(ASN1_Encoder*enc,int64_t value) {
  uint8_t x[8]={value>>070,value>>060,value>>050,value>>040,value>>030,value>>020,value>>010,value};
  int y=0;
  while(y!=7 && !x[y]) y++;
  return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_INTEGER,x+y,8-y);
}

int asn1_encode_uint16(ASN1_Encoder*enc,uint16_t value) {
  uint8_t x[3]={0,value>>8,value};
  int y=(value>=0x8000?0:value>=0x80?1:2);
  return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_INTEGER,x+y,3-y);
}

int asn1_encode_uint32(ASN1_Encoder*enc,uint32_t value) {
  uint8_t x[5]={0,value>>030,value>>020,value>>010,value};
  int y=(value>=0x80000000ULL?0:value>=0x800000?1:value>=0x8000?2:value>=0x80?3:4);
  return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_INTEGER,x+y,5-y);
}

int asn1_encode_uint64(ASN1_Encoder*enc,uint64_t value) {
  uint8_t x[9]={0,value>>070,value>>060,value>>050,value>>040,value>>030,value>>020,value>>010,value>>000};
  int y=(value>=0x8000000000000000?0:value>=0x80000000000000?1:value>=0x800000000000ULL?2:value>=0x8000000000ULL?3:value>=0x80000000ULL?4:value>=0x800000ULL?5:value>=0x8000ULL?6:value>=0x80ULL?7:8);
  return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_INTEGER,x+y,9-y);
}

int asn1_encode_real_parts(ASN1_Encoder*enc,const uint8_t*significand,size_t length,int8_t sign,uint8_t decimal,int64_t exponent,uint8_t infinite) {
  // Not fully tested
  FILE*f;
  size_t n;
  if(!sign && !infinite) return ASN1_IMPROPER_VALUE;
  while(length && !significand[length-1]) --length;
  if(!length && !infinite) {
    return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_REAL,"C",sign<0?1:0);
  } else if(infinite) {
    return asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_REAL,"@AB"+(sign>0?0:sign<0?1:2),1);
  } else if(decimal) {
    exponent-=2LL*length;
    f=asn1_primitive_stream(enc,ASN1_UNIVERSAL,ASN1_REAL);
    if(!f) return ASN1_ERROR;
    fputc(3,f);
    if(sign<0) fputc('-',f);
    for(n=0;n<length;n++) if(significand[n]) break;
    fprintf(f,"%d",significand[n]);
    for(n++;n<length-1;n++) fprintf(f,"%02d",significand[n]);
    if(significand[n]%10) {
      fprintf(f,"%02d",significand[n]);
    } else {
      --exponent;
      fputc(significand[n]/10+'0',f);
    }
    fprintf(f,".E%s%lld",exponent?"":"+",(long long)exponent);
    return asn1_end(enc);
  } else {
    //TODO
  }
}

int asn1_encode_date(ASN1_Encoder*enc,uint32_t type,const ASN1_DateTime*x) {
  char buf[64];
  int len;
  uint32_t g,n,i;
  if(x->month<1 || x->month>12 || x->day<1 || x->day>31 || x->hours>23 || x->minutes>59 || x->seconds>62 || x->nano>=1000000000) return ASN1_IMPROPER_VALUE;
  switch(type) {
    case ASN1_UTCTIME:
      if(x->year<1950 || x->year>2049) return ASN1_IMPROPER_VALUE;
      len=snprintf(buf,64,"%02d%02d%02d%02d%02d%02d%c",x->year%100,x->month,x->day,x->hours,x->minutes,x->seconds,x->zone?(x->zone<0?'-':'+'):'Z');
      if(x->zone) len+=snprintf(buf+len,64-len,"%02d%02d",abs(x->zone)/60,abs(x->zone)%60);
      break;
    case ASN1_GENERALIZEDTIME:
      len=snprintf(buf,64,"%04d%02d%02d%02d%02d%02d",x->year,x->month,x->day,x->hours,x->minutes,x->seconds);
      if(n=x->nano) {
        buf[len++]='.';
        g=1000000000;
        while(n && (g/=10)) {
          i=n/g;
          buf[len++]=i+'0';
          n-=g*i;
        }
      }
      if(x->zone) len+=snprintf(buf+len,64-len,"%c%02d%02d",x->zone<0?'-':'+',abs(x->zone)/60,abs(x->zone)%60); else buf[len++]='Z';
      break;
    case ASN1_DATE:
      len=snprintf(buf,64,"%04d-%02d-%02d",x->year,x->month,x->day);
      break;
    case ASN1_TIME_OF_DAY:
      len=snprintf(buf,64,"T%02d:%02d:%02d",x->hours,x->minutes,x->seconds);
      break;
    case ASN1_DATE_TIME:
      len=snprintf(buf,64,"%04d-%02d-%02dT%02d:%02d:%02d",x->year,x->month,x->day,x->hours,x->minutes,x->seconds);
      break;
//    case ASN1_UTC_TIMESTAMP:
//      //TODO
//      
//      break;
    default: return ASN1_IMPROPER_TYPE;
  }
  return asn1_primitive(enc,ASN1_UNIVERSAL,type,buf,len);
}

int asn1_encode_time(ASN1_Encoder*enc,uint32_t type,time_t value,uint32_t nano,int16_t zone) {
  ASN1_DateTime d;
  int i;
  if(type==ASN1_UTC_TIMESTAMP || type==ASN1_SI_TIMESTAMP) {
    value-=ASN1_TRON_EPOCH;
    if(nano) {
      uint8_t signif[5];
      if(type==ASN1_UTC_TIMESTAMP) {
        if(nano>=1000000000ULL && ((value+1)%60)) return ASN1_IMPROPER_VALUE;
        if(asn1_construct(enc,ASN1_UNIVERSAL,ASN1_UTC_TIMESTAMP,0)) return ASN1_ERROR;
        asn1_encode_int64(enc,value);
        signif[0]=(nano/100000000ULL)%100;
        signif[1]=(nano/1000000ULL)%100;
        signif[2]=(nano/10000ULL)%100;
        signif[3]=(nano/100ULL)%100;
        signif[4]=(nano/1ULL)%100;
        asn1_encode_real_parts(enc,signif,5,1,1,2,0);
        if(asn1_end(enc)) return ASN1_ERROR;
      } else {
        if(nano>=1000000000ULL) return ASN1_IMPROPER_VALUE;
        //TODO
      }
    } else {
      if(!enc->class || !enc->type) enc->class=ASN1_UNIVERSAL,enc->type=type;
      return asn1_encode_int64(enc,value);
    }
  }
  if(i=asn1_time_to_date(value+zone*60LL,nano,&d)) return i;
  d.zone=zone;
  return asn1_encode_date(enc,type,&d);
}

int asn1_encode_c_string(ASN1_Encoder*enc,uint32_t type,const char*text) {
  return text?asn1_primitive(enc,ASN1_UNIVERSAL,type,text,strlen(text)):ASN1_IMPROPER_VALUE;
}

