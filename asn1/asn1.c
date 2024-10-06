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
    *u+=data[at]&0x7F;
    if(data[at]<0x80) break;
    for(y=m=0;m<n;m++) {
      x=u[m]*128+y;
      u[m]=x%100;
      y=x/100;
    }
    while(y) {
      if(n==79) {
        fputc('?',stream);
        return at+1;
      }
      u[n++]=y%100;
      y/=100;
    }
    at++;
  }
  y=adjust;
  for(m=0;m<n;m++) {
    if((u[m]+=y)>99) {
      y=u[m]/100;
      u[m]%=100;
    } else {
      y=0;
    }
  }
  while(y) {
    if(n==79) {
      fputc('?',stream);
      return at+1;
    }
    u[n++]=y%100;
    y/=100;
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
      if(asn->length>x && asn->data[x]=='.') {
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

