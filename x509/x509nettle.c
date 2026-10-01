#if 0
gcc -s -O2 -c x509nettle.c
exit
#endif

#include <alloca.h>
#include <nettle/rsa.h>
#include <stdlib.h>
#include <string.h>
#include "x509.h"

typedef struct {
  const struct nettle_hash*hash;
  int(*sign)(const struct rsa_private_key *key,void*hash,mpz_t signature);
  int(*verify)(const struct rsa_public_key *key,void*hash,const mpz_t signature);
  const uint8_t*oid;
  size_t oidlen;
} RSAfunct;

static const RSAfunct rsafunct[]={
  {&nettle_md5,nettle_rsa_md5_sign,nettle_rsa_md5_verify,"\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04",9},
  {&nettle_sha1,nettle_rsa_sha1_sign,nettle_rsa_sha1_verify,"\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05",9},
  {&nettle_sha256,nettle_rsa_sha256_sign,nettle_rsa_sha256_verify,"\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B",9},
  {&nettle_sha512,nettle_rsa_sha512_sign,nettle_rsa_sha512_verify,"\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0D",9},
};

static int der_to_mpz(ASN1_Value*seq,ASN1_Value*in,mpz_t*out) {
  if(asn1_next_of(in,seq) || in->class || in->constructed || in->type!=ASN1_INTEGER || in->length<1 || in->length>32767 || in->data[0]>127) return 1;
  mpz_init2(*out,in->length);
  mpz_import(*out,in->length,1,1,1,0,in->data);
  return 0;
}

static int rsa_check_signature(const X509_Algorithm*al,const X509_Info*info,const uint8_t*data,size_t len,const ASN1_Value*publickey,const ASN1_Value*algorithm,const ASN1_Value*signature) {
  ASN1_Value v0,v1;
  const RSAfunct*u=al->userdata;
  struct rsa_public_key k={};
  char*hash=alloca(u->hash->context_size);
  mpz_t s={};
  int i;
  if(signature->length>32767 || signature->length<1 || signature->data[0]) return X509_WRONG_SIGNATURE;
  if(asn1_first_of(&v1,publickey) || asn1_next_of(&v1,publickey)) return X509_IMPROPER_KEY;
  if(v1.class || v1.constructed || v1.type!=ASN1_BIT_STRING || v1.length<9 || v1.data[0]) return X509_IMPROPER_KEY;
  v0.data=v1.data; v0.length=1;
  if(asn1_next_of(&v0,&v1) || v0.class || v0.type!=ASN1_SEQUENCE || !v0.constructed) return X509_IMPROPER_KEY;
  v1.data=v0.data; v1.length=0;
  rsa_public_key_init(&k);
  if(der_to_mpz(&v1,&v0,&k.n) || der_to_mpz(&v1,&v0,&k.e)) {
    i=X509_IMPROPER_KEY;
    goto stop;
  }
  if(rsa_public_key_prepare(&k)) {
    u->hash->init(hash);
    u->hash->update(hash,len,data);
    mpz_init2(s,8L*signature->length-1);
    mpz_import(s,signature->length-1,1,1,1,0,signature->data+1);
    i=u->verify(&k,hash,s)?X509_OK:X509_WRONG_SIGNATURE;
    mpz_clear(s);
  } else {
    i=X509_IMPROPER_KEY;
  }
  stop:
  rsa_public_key_clear(&k);
  return i;
}

static int rsa_make_signature(const X509_Algorithm*al,const X509_Info*info,const uint8_t*data,size_t len,void*privatekey,const ASN1_Value*algorithm,ASN1_Value*signature) {
  ASN1_Value v0,v1;
  ASN1_Encoder*e;
  const RSAfunct*u=al->userdata;
  struct rsa_private_key k={};
  char*hash=alloca(u->hash->context_size);
  uint8_t*os;
  mpz_t s={};
  int i;
  uint32_t osize,w;
  v0=*(ASN1_Value*)privatekey;
  if(v0.class || v0.type!=ASN1_SEQUENCE || !v0.constructed || v0.length<3) return X509_IMPROPER_KEY;
  rsa_private_key_init(&k);
  if(i=asn1_first_of(&v1,&v0)) return i; // version number (always zero)
  if(v1.class || v1.type!=ASN1_INTEGER || v1.length!=1 || v1.data[0]) return X509_IMPROPER_KEY;
  if(i=asn1_next_of(&v1,&v0)) return i; // modulus
  k.size=osize=v1.length-!*v1.data;
  if(osize>2999999) goto bad;
  if(i=asn1_next_of(&v1,&v0)) return i; // skip modulus and public exponent
  if(der_to_mpz(&v1,&v0,&k.d) || der_to_mpz(&v1,&v0,&k.p) || der_to_mpz(&v1,&v0,&k.q) || der_to_mpz(&v1,&v0,&k.a) || der_to_mpz(&v1,&v0,&k.b) || der_to_mpz(&v1,&v0,&k.c)) {
    bad:
    rsa_private_key_clear(&k);
    return X509_IMPROPER_KEY;
  }
  if(rsa_private_key_prepare(&k)) {
    u->hash->init(hash);
    u->hash->update(hash,len,data);
    mpz_init(s);
    i=X509_ERROR;
    if(u->sign(&k,hash,s)) {
      w=(mpz_sizeinbase(s,2)+7)/8;
      if(w>osize) goto stop;
      os=calloc(1,osize+1);
      if(!os) goto stop;
      mpz_export(os+osize+1-w,0,1,1,1,0,s);
      e=asn1_start_encoding_value(signature);
      if(!e) goto stop;
      asn1_primitive(e,ASN1_UNIVERSAL,ASN1_BIT_STRING,os,osize+1);
      free(os);
      if(asn1_end(e)) goto stop;
      i=X509_OK;
    }
    mpz_clear(s);
  } else {
    i=X509_IMPROPER_KEY;
  }
  stop:
  rsa_private_key_clear(&k);
  return i;
}

static int rsa_make_public_key(const X509_Algorithm*al,const X509_Info*info,void*key,const ASN1_Value*keyalgorithm,ASN1_Encoder*enc) {
  ASN1_Value v,vv;
  int i;
  if(i=asn1_first_of(&v,key)) return i;
  if(i=asn1_next_of(&v,key)) return i;
  vv=v;
  if(i=asn1_next_of(&v,key)) return i;
  asn1_construct(enc,ASN1_UNIVERSAL,ASN1_SEQUENCE,0);
    asn1_construct(enc,ASN1_UNIVERSAL,ASN1_SEQUENCE,0);
      asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_OBJECT_IDENTIFIER,al->k_oid,al->k_oidlen);
      asn1_encode_null(enc);
    asn1_end(enc);
    asn1_wrap_bits(enc);
      asn1_construct(enc,ASN1_UNIVERSAL,ASN1_SEQUENCE,0);
        asn1_encode(enc,&vv);
        asn1_encode(enc,&v);
      asn1_end(enc);
  asn1_end(enc);
}

void x509nettle_alg_rsa(uint8_t id,X509_Algorithm*x) {
  const RSAfunct*y=rsafunct+id;
  x->userdata=(void*)y;
  x->s_oid=y->oid;
  x->s_oidlen=y->oidlen;
  x->k_oid="\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01";
  x->k_oidlen=9;
  x->check_signature=rsa_check_signature;
  x->make_public_key=rsa_make_public_key;
  x->make_signature=rsa_make_signature;
}

