#if 0
gcc -g -O0 -c x509.c
exit
#endif

#define _GNU_SOURCE
#include <err.h>
#include <search.h>
#include <stdlib.h>
#include <string.h>
#include "x509.h"

enum {
  Exd_KeyUsage,
  Exd_NeedKeyUsage,
  LastExd
};

static const char exdata[LastExd]={}; // (the contents of this array is unimportant; only the address is used)

// Built-in extensions

static int compare_extlist(const void*a,const void*b) {
  const X509_Extension*x=a;
  const X509_Extension*y=b;
  return x->oidlen<y->oidlen?-1:x->oidlen>y->oidlen?1:memcmp(x->oid,y->oid,x->oidlen);
}

static int bx_key_usage(const X509_Extension*ext,X509_Info*info,const X509_Options*option,const ASN1_Value*data,uint8_t crit) {
  uint8_t*p;
  if(data->constructed || data->class!=ASN1_UNIVERSAL || data->type!=ASN1_BIT_STRING || data->length<1) return ASN1_IMPROPER_TYPE;
  if(data->length>3) return X509_EXT_ERROR;
  p=x509_extra_find(info->out,exdata+Exd_KeyUsage,0,0,2);
  if(!p) return X509_ERROR;
  if(data->length>1) p[0]=data->data[1];
  if(data->length>2) p[1]=data->data[2];
  if(info->count && !(*p&4)) return X509_ACCESS_DENIED;
  if(!info->count && (p=x509_extra_find(info->in,exdata+Exd_NeedKeyUsage,0,0,0))) {
    if(p[0] && (data->length<2 || (p[0]&~data->data[1]))) return X509_ACCESS_DENIED;
    if(p[1] && (data->length<3 || (p[1]&~data->data[2]))) return X509_ACCESS_DENIED;
  }
  return X509_OK;
}

static int bx_basic_constraints(const X509_Extension*ext,X509_Info*info,const X509_Options*option,const ASN1_Value*data,uint8_t crit) {
  uint8_t*p;
  uint16_t limit;
  ASN1_Value a;
  int i;
  if(data->class!=ASN1_UNIVERSAL || data->type!=ASN1_SEQUENCE || !data->constructed) return ASN1_IMPROPER_TYPE;
  if(data->length) {
    if(i=asn1_first_of(&a,data)) return i;
    if(a.class!=ASN1_UNIVERSAL || a.type!=ASN1_BOOLEAN || a.length!=1 || a.constructed || a.data[0]!=0xFF) return X509_IMPROPER_FORMAT;
    if(i=asn1_next_of(&a,data)) {
      if(i!=ASN1_DONE) return i;
    } else {
      if(a.class!=ASN1_UNIVERSAL || a.type!=ASN1_INTEGER || a.length<1 || a.constructed || a.data[0]>=0x80) return X509_IMPROPER_FORMAT;
      if(a.length==1 && !a.data[0]) {
        if(info->count>1) return X509_ACCESS_DENIED;
      } else if(!asn1_decode_number(&a,ASN1_INTEGER,&limit)) {
        if(info->count && info->count-1>limit) return X509_ACCESS_DENIED;
      }
      if(asn1_next_of(&a,data)!=ASN1_DONE) return X509_IMPROPER_FORMAT;
    }
    if(p=x509_extra_find(info->in,exdata+Exd_KeyUsage,0,0,0)) *p&=~4;
    return X509_OK;
  } else {
    if((p=x509_extra_find(info->in,exdata+Exd_NeedKeyUsage,0,0,0)) && !(*p&4)) return X509_ACCESS_DENIED;
    return info->count?X509_ACCESS_DENIED:X509_OK;
  }
}

static int bx_extended_key_usage(const X509_Extension*ext,X509_Info*info,const X509_Options*option,const ASN1_Value*data,uint8_t crit) {
  return X509_NOT_IMPLEMENTED;
}

static const X509_Extension builtin_extlist[]={
  {.oidlen=3,.oid="\x55\x1D\x0F",.call=bx_key_usage,.flag=0},
  {.oidlen=3,.oid="\x55\x1D\x13",.call=bx_basic_constraints,.flag=0},
//  {.oidlen=3,.oid="\x55\x1D\x25",.call=bx_extended_key_usage,.flag=0},
};
#define builtin_extcount (sizeof(builtin_extlist)/sizeof(X509_Extension))

// Extra data functions

typedef struct ExtraData {
  const void*key;
  void(*destructor)(void*);
  char data[0] __attribute__((aligned(__BIGGEST_ALIGNMENT__)));
} ExtraData;

struct X509_ExtraData {
  void*root;
  X509_ExtraData*orig;
};

static int compare_node(const void*a,const void*b) {
  const ExtraData*x=a;
  const ExtraData*y=b;
  return x->key>y->key?1:x->key<y->key?-1:0;
}

static void free_node(void*node) {
  ExtraData*x=node;
  if(x->destructor) x->destructor(x->data);
  free(x);
}

void x509_extra_delete(X509_ExtraData*extra,const void*key) {
  ExtraData k={key};
  ExtraData*x;
  if(!extra || !key) return;
  if(x=tfind(&k,&extra->root,compare_node)) {
    if(x->destructor) x->destructor(x->data);
    tdelete(&k,&extra->root,compare_node);
  }
}

void x509_extra_destroy(X509_ExtraData*extra) {
  if(!extra) return;
  tdestroy(extra->root,free_node);
  free(extra);
}

void*x509_extra_destructor(X509_ExtraData*extra,const void*key) {
  ExtraData k={key};
  ExtraData*x;
  if(!extra || !key) return 0;
  if(x=tfind(&k,&extra->root,compare_node)) return x->destructor;
  return 0;
}

void*x509_extra_find(X509_ExtraData*extra,const void*key,void(*destructor)(void*),const void*data,size_t size) {
  ExtraData k={key};
  ExtraData**x;
  if(!extra || !key) return 0;
  repeat:
  if(destructor || size) x=tsearch(&k,&extra->root,compare_node); else x=tfind(&k,&extra->root,compare_node);
  if(x && *x==&k) {
    if(*x=malloc(sizeof(ExtraData)+size)) {
      k.destructor=destructor;
      if(size) {
        if(data) memcpy(k.data,data,size); else memset(k.data,0,size);
      }
      memcpy(*x,&k,sizeof(ExtraData));
    } else {
      tdelete(&k,&extra->root,compare_node);
      return 0;
    }
  }
  if(!x && !destructor && !data && !size && extra->orig) {
    extra=extra->orig;
    goto repeat;
  }
  if(x) return x[0]->data; else return 0;
}

X509_ExtraData*x509_extra_mirror(const X509_ExtraData*orig) {
  X509_ExtraData*x=calloc(1,sizeof(X509_ExtraData));
  if(x) x->orig=(X509_ExtraData*)orig;
  return x;
}

X509_ExtraData*x509_extra_new(void) {
  return calloc(1,sizeof(X509_ExtraData));
}

// Certificate reading

void x509_reset_info(X509_Info*info) {
  x509_extra_destroy(info->out);
  memset(info,0,sizeof(X509_Info));
}

int x509_read_certificate(const ASN1_Value*cert,const X509_Options*option,X509_ExtraData*extra,X509_Info*info) {
  uint8_t*eb=alloca(builtin_extcount+option->extcount);
  X509_Extension ek;
  const X509_Extension*ex;
  ASN1_Value a,b,c,d,tbs,alg,exl,ser;
  int i,n;
  uint8_t isca=1;
  if(!eb) return X509_ERROR;
  memset(eb,0,builtin_extcount+option->extcount);
  info->in=extra;
  if(i=asn1_first_of(&tbs,cert)) return i;
  if(!tbs.constructed || tbs.class!=ASN1_UNIVERSAL || tbs.type!=ASN1_SEQUENCE) return X509_IMPROPER_FORMAT;
  if(!info->out) info->out=x509_extra_new();
  // Version number
  if(i=asn1_first_of(&a,&tbs)) return i;
  if(a.constructed && a.class==ASN1_CONTEXT_SPECIFIC && a.type==0 && a.length==3 && !asn1_first_of(&b,&a) && b.class==ASN1_UNIVERSAL && b.type==ASN1_INTEGER && b.length==1 && !b.constructed) {
    if(b.data[0]==2 && (option->flag&X509_ASSUME_NOT_CA)) isca=0;
    if(b.data[0]!=1 && b.data[0]!=2) return X509_IMPROPER_FORMAT;
    if(i=asn1_next_of(&a,&tbs)) return i;
  }
  // Serial number
  if(a.class!=ASN1_UNIVERSAL || a.type!=ASN1_INTEGER || a.length<=0 || a.constructed) return X509_IMPROPER_FORMAT;
  if(a.data[0]&0x80) return X509_IMPROPER_FORMAT;
  if(!a.data[0] && (a.length<1 || a.data[1]<0x80)) return X509_IMPROPER_FORMAT;
  ser=a;
  // Signature algorithm (later checked to see if it matches the other copy)
  if(i=asn1_next_of(&a,&tbs)) return i;
  if(!a.constructed || a.class!=ASN1_UNIVERSAL || a.type!=ASN1_SEQUENCE || !a.length) return X509_IMPROPER_FORMAT;
  alg=a;
  // Issuer name
  if(i=asn1_next_of(&a,&tbs)) return i;
  info->issuer=a;
  info->issuer_id=(ASN1_Value){};
  if(!a.constructed || a.class!=ASN1_UNIVERSAL || a.type!=ASN1_SEQUENCE) return X509_IMPROPER_FORMAT;
  // Validity date/time
  if(i=asn1_next_of(&a,&tbs)) return i;
  if(!a.constructed || a.class!=ASN1_UNIVERSAL || a.type!=ASN1_SEQUENCE) return X509_IMPROPER_FORMAT;
  if(i=asn1_first_of(&b,&a)) return i;
  if(b.constructed || b.class!=ASN1_UNIVERSAL || (b.type!=ASN1_UTC_TIME && b.type!=ASN1_GENERALIZED_TIME)) return X509_IMPROPER_FORMAT;
  if(i=asn1_decode_time(&b,ASN1_AUTO,0,&info->starts,0)) return i;
  if(i=asn1_next_of(&b,&a)) return i;
  if(b.constructed || b.class!=ASN1_UNIVERSAL || (b.type!=ASN1_UTC_TIME && b.type!=ASN1_GENERALIZED_TIME)) return X509_IMPROPER_FORMAT;
  if(i=asn1_decode_time(&b,ASN1_AUTO,0,&info->expires,0)) return i;
  if(!(option->flag&X509_IGNORE_NOT_VALID_BEFORE) && option->now<info->starts) return X509_NOT_VALID_YET;
  if(!(option->flag&X509_IGNORE_NOT_VALID_AFTER) && option->now>info->expires) return X509_EXPIRED;
  // Subject name
  if(i=asn1_next_of(&a,&tbs)) return i;
  info->subject=a;
  info->subject_id=(ASN1_Value){};
  if(!a.constructed || a.class!=ASN1_UNIVERSAL || a.type!=ASN1_SEQUENCE) return X509_IMPROPER_FORMAT;
  // Public key
  if(i=asn1_next_of(&a,&tbs)) return i;
  info->publickey=a;
  if(!a.constructed || a.class!=ASN1_UNIVERSAL || a.type!=ASN1_SEQUENCE) return X509_IMPROPER_FORMAT;
  // Optional fields
  if(i=asn1_next_of(&a,&tbs)) {
    if(i!=ASN1_DONE) return i;
  } else {
    // Issuer ID
    if(!a.constructed && a.class==ASN1_CONTEXT_SPECIFIC && a.type==1 && a.length>0 && a.data[0]<8) {
      info->issuer_id=a;
      if((i=asn1_next_of(&a,&tbs)) && i!=ASN1_DONE) return i;
    }
    // Subject ID
    if(!i && !a.constructed && a.class==ASN1_CONTEXT_SPECIFIC && a.type==2 && a.length>0 && a.data[0]<8) {
      info->subject_id=a;
      if((i=asn1_next_of(&a,&tbs)) && i!=ASN1_DONE) return i;
    }
    // Extensions
    if(!i && a.constructed && a.class==ASN1_CONTEXT_SPECIFIC && a.type==3) {
      if(i=asn1_first_of(&exl,&a)) return i;
      if(!exl.constructed || exl.class!=ASN1_UNIVERSAL || exl.type!=ASN1_SEQUENCE) return ASN1_IMPROPER_TYPE;
      if(exl.data+exl.length!=a.data+a.length) return X509_IMPROPER_FORMAT;
      if(i=asn1_first_of(&b,&exl)) return i; // the list of extensions is not allowed to be empty if it is present
      for(;;) {
        if(i=asn1_first_of(&c,&b)) return i;
        if(c.constructed || c.class!=ASN1_UNIVERSAL || c.type!=ASN1_OBJECT_IDENTIFIER || !c.length) return ASN1_IMPROPER_TYPE;
        ek.oid=c.data;
        ek.oidlen=c.length;
        ex=bsearch(&ek,option->extlist,option->extcount,sizeof(X509_Extension),compare_extlist);
        if(!ex && !(option->flag&X509_NO_STANDARD_EXTENSIONS)) i=1,ex=bsearch(&ek,builtin_extlist,builtin_extcount,sizeof(X509_Extension),compare_extlist);
        if(ex) {
          n=(i?0:builtin_extcount)+(ex-(i?builtin_extlist:option->extlist));
          if(eb[n]&0x01) return X509_REPEATED_EXTENSION;
          eb[n]|=0x01;
          if(i=asn1_next_of(&c,&b)) return i;
          if(c.class==ASN1_UNIVERSAL && c.type==ASN1_BOOLEAN) {
            if(c.constructed || c.length!=1 || c.data[0]!=0xFF) return X509_IMPROPER_FORMAT;
            if(ex->flag&X509_REJECT_IF_CRITICAL) return X509_REJECTED_EXTENSION;
            eb[n]|=0x02;
            if(i=asn1_next_of(&c,&b)) return i;
          }
          if(c.class!=ASN1_UNIVERSAL || c.type!=ASN1_OCTET_STRING || !c.length) return ASN1_IMPROPER_TYPE;
          c.constructed=1;
          if(i=asn1_first_of(&d,&c)) return i;
          if(d.data+d.length!=c.data+c.length) return X509_IMPROPER_FORMAT;
          if(!(ex->flag&X509_SECOND_PHASE) && ((eb[n]&0x02) || !(ex->flag&X509_IGNORE_UNLESS_CRITICAL)) && (i=ex->call(ex,info,option,&d,(eb[n]>>1)&1))) {
            if(i==X509_DEFER_EXTENSION) eb[n]|=0x04; else return i;
          }
        } else if(!(option->flag&X509_IGNORE_EXTENSIONS)) {
          if(i=asn1_next_of(&c,&b)) return i;
          if(c.class==ASN1_UNIVERSAL && c.type==ASN1_BOOLEAN) return X509_UNKNOWN_EXTENSION;
          if(c.class!=ASN1_UNIVERSAL || c.type!=ASN1_OCTET_STRING) return ASN1_IMPROPER_TYPE;
        }
        if(ek.oidlen==3 && ek.oid[0]==0x55 && ek.oid[1]==0x1D && ek.oid[2]==0x13) isca=(c.length>2);
        if((i=asn1_next_of(&b,&exl)) && i!=ASN1_DONE) return i; else if(i) break;
      }
      if((i=asn1_next_of(&a,&tbs)) && i!=ASN1_DONE) return i;
    }
    // End of optional fields
    if((i=asn1_next_of(&a,&tbs))!=ASN1_DONE) return i?:X509_IMPROPER_FORMAT;
  }
  if(info->count && !isca && (option->flag&(X509_NO_STANDARD_EXTENSIONS|X509_ASSUME_NOT_CA))!=X509_NO_STANDARD_EXTENSIONS) return X509_ACCESS_DENIED;
  // Signature algorithm
  a=tbs;
  if(i=asn1_next_of(&a,cert)) return i;
  if(a.class!=alg.class || a.type!=alg.type || !a.constructed || a.length!=alg.length || memcmp(a.data,alg.data,a.length)) return X509_IMPROPER_FORMAT;
  // (The signature value is handled in x509_read_chain, not in this function.)
  // (This implementation deliberately allows further fields after the signature.)
  // Check if it is revoked
  if(option->check_revoked) {
    if(i=option->check_revoked(info,option,cert,&ser)) return i;
  }
  // Check for missing extensions and second phase
  for(i=n=0;n<builtin_extcount+option->extcount;n++) {
    ex=(n<builtin_extcount?builtin_extlist+n:option->extlist+n-builtin_extcount);
    if((ex->flag&(info->count?X509_REQUIRE_EXTENSION_CA:X509_REQUIRE_EXTENSION_END)) && !eb[n]) return X509_MISSING_EXTENSION;
    if(eb[n] && (ex->flag&X509_SECOND_PHASE)) i=1;
    if(eb[n]&0x04) i=1;
  }
  // Second phase of extensions (the "i" from above is used here; do not add anything else in between)
  if(i) {
    if(i=asn1_first_of(&b,&exl)) return i;
    for(;;) {
      if(i=asn1_first_of(&c,&b)) return i;
      ek.oid=c.data;
      ek.oidlen=c.length;
      ex=bsearch(&ek,option->extlist,option->extcount,sizeof(X509_Extension),compare_extlist);
      if(!ex && !(option->flag&X509_NO_STANDARD_EXTENSIONS)) i=1,ex=bsearch(&ek,builtin_extlist,builtin_extcount,sizeof(X509_Extension),compare_extlist);
      if(ex) {
        n=(i?builtin_extcount:0)+(ex-(i?builtin_extlist:option->extlist));
        if((eb[n]&0x04) || (ex->flag&X509_SECOND_PHASE)) {
          if(i=asn1_next_of(&c,&b)) return i;
          if(c.type==ASN1_BOOLEAN && (i=asn1_next_of(&c,&b))) return i;
          c.constructed=1;
          if(i=asn1_first_of(&d,&c)) return i;
          if(d.data+d.length!=c.data+c.length) return X509_IMPROPER_FORMAT;
          if(((eb[n]&0x02) || !(ex->flag&X509_IGNORE_UNLESS_CRITICAL)) && (i=ex->call(ex,info,option,&d,(eb[n]>>1)&1))) return i;
        }
      }
      if((i=asn1_next_of(&b,&exl)) && i!=ASN1_DONE) return i; else if(i) break;
    }
  }
  return option->check_info?option->check_info(info,option->userdata):X509_OK;
}

static inline int match_name(const ASN1_Value*a,const ASN1_Value*b) {
  return (a->length==b->length && !memcmp(a->data,b->data,a->length));
}

int x509_read_chain(const X509_Chain*chain,const X509_Options*option,X509_ExtraData*extra,X509_Info*info) {
  time_t starts,expires;
  const ASN1_Value*cert;
  ASN1_Value auth={};
  X509_Info iinf={};
  X509_Info sinf={};
  uint32_t n;
  uint32_t skip=0;
  int i;
  if(option->begin_chain && (i=option->begin_chain(chain,option,extra,info))) return i;
  x509_extra_destroy(info->in); info->in=0;
  x509_extra_destroy(info->out); info->out=0;
  sinf.in=x509_extra_mirror(extra);
  if(!sinf.in) return X509_ERROR;
  sinf.out=x509_extra_new();
  if(!sinf.out) {
    x509_extra_destroy(sinf.in);
    return X509_ERROR;
  }
  if((option->flag&X509_REVERSE_AUTHORITY) && option->find_authority) {
    for(n=0;n<chain->count;n++) {
      cert=chain->item+(option->flag&X509_ROOT_LAST?chain->count-n-1:n);
      sinf.count=chain->count-n-1;
      i=option->find_authority(&sinf,cert);
      if(i==X509_OK) {
        auth=*cert;
        auth.own=0;
        skip=n;
        break;
      } else if(i!=X509_UNKNOWN_AUTHORITY) {
        goto error;
      }
      x509_extra_destroy(sinf.out); sinf.out=0;
    }
    x509_extra_destroy(sinf.out); sinf.out=0;
  }
  for(n=skip;n<chain->count;n++) {
    if(n) {
      x509_extra_destroy(sinf.out); sinf.out=0;
      iinf=sinf;
      iinf.in=0;
    }
    cert=chain->item+(option->flag&X509_ROOT_LAST?chain->count-n-1:n);
    sinf.issuer=iinf.subject;
    sinf.issuer_id=iinf.subject_id;
    sinf.count=chain->count-n-1;
    if(i=x509_read_certificate(cert,option,extra,&sinf)) goto error;
    if(n==skip || starts<sinf.starts) starts=sinf.starts;
    if(n==skip || expires>sinf.expires) expires=sinf.expires;
    if(n!=skip) {
      if(!match_name(&sinf.issuer,&iinf.subject) && (i=X509_NAME_MISMATCH)) goto error;
      if(sinf.issuer_id.length && iinf.subject_id.length && !match_name(&sinf.issuer_id,&iinf.subject_id) && (i=X509_NAME_MISMATCH)) goto error;
      if(option->check_signature) {
        ASN1_Value a,b;
        size_t s;
        if(i=asn1_first_of(&a,cert)) goto error;
        s=a.data+a.length-cert->data;
        if(i=asn1_next_of(&a,cert)) goto error;
        b=a;
        if(i=asn1_next_of(&b,cert)) goto error;
        if(i=option->check_signature(&sinf,cert->data,s,&iinf.publickey,&a,&b)) goto error;
      }
    } else if(!n && !auth.length) {
      if(match_name(&sinf.issuer,&sinf.subject) && match_name(&sinf.issuer_id,&sinf.subject_id)) {
        // Self-signed certificate
        auth=*cert;
        auth.own=0;
        i=option->find_root?option->find_root(&sinf,&auth):X509_UNKNOWN_AUTHORITY;
      } else {
        // Not self-signed certificate
        i=option->find_issuer?option->find_issuer(&sinf,cert,&auth):X509_UNKNOWN_AUTHORITY;
      }
      if(i==X509_UNKNOWN_AUTHORITY) {
        auth.length=0;
        if(!option->find_authority || (option->flag&X509_REVERSE_AUTHORITY)) goto error;
        i=option->find_authority(&sinf,cert);
        if(!i) auth=*cert,auth.own=0;
      }
    }
  }
  info->starts=starts; info->expires=expires;
  i=X509_OK;
  error:
  info->in=extra;
  if(!sinf.count) info->out=sinf.out,sinf.out=0;
  x509_reset_info(&iinf);
  x509_reset_info(&sinf);
  asn1_free(&auth);
  return option->end_chain?option->end_chain(chain,option,extra,info,i):i;
}

uint16_t x509_get_key_usage(const X509_Info*info) {
  const uint8_t*p;
  if(p=x509_extra_find(info->out,exdata+Exd_KeyUsage,0,0,0)) return (p[0]<<8)|p[1]; else return 0xFFFF;
}

int x509_set_needed_key_usage(X509_Info*info,uint16_t usage) {
  uint8_t*p;
  if(usage) {
    if(!info->in) info->in=x509_extra_new();
    if(!info->in) return X509_ERROR;
    p=x509_extra_find(info->in,exdata+Exd_NeedKeyUsage,0,0,2);
    if(!p) return X509_ERROR;
    p[0]=usage>>8; p[1]=usage&255;
  } else {
    x509_extra_delete(info->in,exdata+Exd_NeedKeyUsage);
  }
  return X509_OK;
}

// Miscellaneous

int x509_accept_any_self_signed(const X509_Info*info) {
  return X509_OK;
}

void x509_sort_extlist(X509_Extension*extlist,uint32_t extcount) {
  qsort(extlist,extcount,sizeof(X509_Extension),compare_extlist);
}

