#if 0
gcc -s -O2 -o ./makersakey makersakey.c asn1.o -lhogweed -lnettle -lgmp
exit
#endif

// This program uses Nettle to make RSA keys.

#define _GNU_SOURCE
#include <alloca.h>
#include <err.h>
#include <nettle/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "asn1.h"

// *** Implementation of base64

static const char base64alph[64]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct {
  FILE*file;
  uint32_t value;
  uint8_t width,phase,autoclose;
} Cookie_base64_enc;

static ssize_t write_base64_enc(void*cookie,const char*buf,size_t size) {
  Cookie_base64_enc*x=cookie;
  const uint8_t*b=buf;
  size_t n;
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
      if(++x->width==16) x->width=0,fputc('\n',x->file);
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
  if(x->width || x->phase) fputc('\n',x->file);
  return x->autoclose?fclose(x->file):0;
}

static FILE*open_base64_enc(FILE*f,char autoclose) {
  Cookie_base64_enc*x=calloc(1,sizeof(Cookie_base64_enc));
  if(!x) return 0;
  x->file=f;
  x->autoclose=autoclose;
  f=fopencookie(x,"w",(cookie_io_functions_t){.write=write_base64_enc,.close=close_base64_enc});
  if(!f) free(x);
  return f;
}

// *** End of implementation of base64

static FILE*randomfile;
static struct rsa_public_key public;
static struct rsa_private_key private;
static unsigned int n_size;
static unsigned int e_size;
static char binout;

static void randomcall(void*ctx,unsigned length,uint8_t*dst) {
  if(fread(dst,1,length,randomfile)!=length) err(1,"Out of random numbers");
}

static void mpz_to_der(ASN1_Encoder*enc,mpz_t z) {
  // Assumes that the number is positive
  uint8_t*buf=alloca(mpz_sizeinbase(z,2)/8+2);
  size_t count=0;
  *buf=0;
  mpz_export(buf+1,&count,1,1,1,0,z);
  asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_INTEGER,buf+1-(buf[1]>>7),count+(buf[1]>>7));
}

int main(int argc,char**argv) {
  ASN1_Encoder*enc;
  FILE*b64file;
  int i;
  if(argc<2) {
    fputs(
      "-b = Binary output instead of base64.\n"
      "-e = Desired size of the public exponent, in bits.\n"
      "-m = Desired size of the modulus, in bits.\n"
      "-r = Random file or device (e.g. /dev/random or /dev/urandom).\n"
      "-x = The exact value of the public exponent.\n"
      "\n"
      "The size of the modulus is mandatory.\n"
      "If neither -e nor -x is specified, then the public exponent is 65537.\n"
      "If -r is not specified, then it reads from /dev/urandom by default.\n"
      "\n"
      "(Passworded private keys is not implemented yet)\n"
    ,stderr);
    return 1;
  }
  rsa_public_key_init(&public);
  rsa_private_key_init(&private);
  mpz_set_ui(public.e,65537);
  while((i=getopt(argc,argv,"+be:m:r:x:"))>0) switch(i) {
    case 'b': binout=1; break;
    case 'e': e_size=strtol(optarg,0,10); break;
    case 'm': n_size=strtol(optarg,0,10); break;
    case 'r': if(!(randomfile=fopen(optarg,"r"))) err(1,"Cannot open random file"); break;
    case 'x': if(gmp_sscanf(optarg,"%Zu",public.e)<=0) errx(1,"Invalid number"); break;
    default: errx(1,"Unrecognized switch");
  }
  if(!n_size) errx(1,"Desired size of modulus is not specified");
  if(!randomfile) randomfile=fopen("/dev/urandom","r");
  if(!randomfile) err(1,"Cannot open random file");
  if(!rsa_generate_keypair(&public,&private,0,randomcall,0,0,n_size,e_size)) errx(1,"Error generating key pair");
  if(binout) {
    enc=asn1_start_encoding_file(stdout);
  } else {
    puts("-----BEGIN RSA PRIVATE KEY-----");
    enc=asn1_start_encoding_file(b64file=open_base64_enc(stdout,0));
  }
  if(!enc) err(1,"Unexpected error");
  asn1_construct(enc,ASN1_UNIVERSAL,ASN1_SEQUENCE,0);
    asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_INTEGER,"",1); // version number; always zero
    mpz_to_der(enc,public.n);
    mpz_to_der(enc,public.e);
    mpz_to_der(enc,private.d);
    mpz_to_der(enc,private.p);
    mpz_to_der(enc,private.q);
    mpz_to_der(enc,private.a);
    mpz_to_der(enc,private.b);
    mpz_to_der(enc,private.c);
  asn1_end(enc);
  asn1_finish_encoder(enc);
  if(!binout) {
    fclose(b64file);
    puts("-----END RSA PRIVATE KEY-----");
  }
  return 0;
}
