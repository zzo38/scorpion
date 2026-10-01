#if 0
gcc -s -O2 -o ~/bin/x509make x509make.c asn1.o base64.o x509.o x509nettle.o -lhogweed -lnettle -lgmp
exit
#endif

#define _GNU_SOURCE
#include <err.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "asn1.h"
#include "base64.h"
#include "x509.h"
#include "x509nettle.h"

typedef struct {
  char k[24];
  ASN1_Value v;
} Option;

static FILE*outfile;
static uint16_t testmode;
static char binout,enable_input;
static ASN1_Value privatekey;
static X509_Authority authority;
static X509_Subject subject;
static X509_Algorithm algorithms[4];
static X509_Options options;
static uint8_t algorithm_id=X509NETTLE_RSA_SHA256;
static uint8_t basic_option=0;
static int32_t basic_limit;
static void*coptions;

static int options_compare(const void*a,const void*b) {
  const Option*x=a;
  const Option*y=b;
  return strcmp(x->k,y->k);
}

static ASN1_Value*find_option(const char*key) {
  Option o;
  Option**t;
  strncpy(o.k,key,24);
  o.k[23]=0;
  t=tfind(&o,&coptions,options_compare);
  return t?&t->v:0;
}

static void add_option(const char*k,const ASN1_Value*v) {
  Option o;
  Option**t;
  int i;
  for(i=0;k[i] && k[i]!='=';i++) {
    if(i==23) errx(1,"Too long option name");
    if(k[i]<40 || k[i]>126) errx(1,"Invalid character in option name");
    o.k[i]=k[i];
  }
  o.k[i]=0;
  t=tsearch(&o,&coptions,options_compare);
  if(*t!=&o) errx(1,"Duplicate option name '%s'",k);
  *t=malloc(sizeof(Option));
  if(!*t) err(1,"Allocation failed");
  o.v=*v;
  **t=o;
}

static void option_test_1(const void*nodep,const VISIT which,const int depth) {
  Option**t=nodep;
  if(which==postorder || which==leaf) printf("%s (class=%u, type=%lu, length=%lu)\n",(*t)->k,(int)((*t)->v.class),(unsigned long)((*t)->v.type),(unsigned long)((*t)->v.length));
}

static void load_input_file(const char*name,const char*head,ASN1_Value*out) {
  FILE*f;
  if(*name=='=') f=fopen(name+1,"r"); else f=open_base64_pem_dec(fopen(name,"r"),head,0,1);
  if(!f) err(1,"Error opening private key file");
  if(asn1_read_item(f,out,0)) errx(1,"Error reading private key file");
  fclose(f);
}

int main(int argc,char**argv) {
  int i;
  while((i=getopt(argc,argv,"+B:S:T:bc:i:k:r"))>0) switch(i) {
    case 'B':
      basic_option=(*optarg=='c'?3:2);
      if(optarg[basic_option&1]=='-') basic_option|=4;
      basic_limit=strtol(optarg+(basic_option&1),0,10);
      break;
    case 'S':
      if(!strcmp(optarg,"md5")) algorithm_id=X509NETTLE_RSA_MD5;
      else if(!strcmp(optarg,"sha1")) algorithm_id=X509NETTLE_RSA_SHA1;
      else if(!strcmp(optarg,"sha256")) algorithm_id=X509NETTLE_RSA_SHA256;
      else if(!strcmp(optarg,"sha512")) algorithm_id=X509NETTLE_RSA_SHA512;
      else errx(1,"Unknown signature algorithm");
      break;
    case 'T': testmode=strtol(optarg,0,10); break;
    case 'b': binout=1; break;
    case 'c': if(strcmp(optarg,"ascii")) errx(1,"Unknown character encoding"); break;
    case 'i': load_input_file(optarg,"CERTIFICATE",&authority.certificate); break;
    case 'k': load_input_file(optarg,"RSA PRIVATE KEY",&privatekey); break;
    case 'r': enable_input=1; break;
    default: errx(1,"Unrecognized switch");
  }
  while(optind<argc) {
    ASN1_Value v={.class=ASN1_UNIVERSAL,.type=ASN1_VISIBLE_STRING};
    char*p=strchr(argv[optind],'=');
    if(!p) errx(1,"Invalid option syntax");
    p=strdup(p+1);
    if(!p) errx(1,"Allocation failed");
    v.length=strlen(p);
    add_option(argv[optind],p);
    optind++;
  }
  if(enable_input) {
    ASN1_Value v={};
    ASN1_Value u;
    char k[32];
    if(asn1_read_item(stdin,&v,0)) errx(1,"ASN.1 error on stdin");
    if(v.class!=ASN1_UNIVERSAL || v.type!=ASN1_KEY_VALUE_LIST || !v.constructed) errx(1,"Incorrect ASN.1 type on stdin");
    if(!asn1_first_of(&u,&v)) do {
      if(u.constructed || !u.length || u.length>23 || v.class!=ASN1_UNIVERSAL ||
       (u.type!=ASN1_VISIBLE_STRING && u.type!=ASN1_IA5_STRING && u.type!=ASN1_GRAPHIC_STRING && u.type!=ASN1_GENERAL_STRING
       && u.type!=ASN1_TELETEX_STRING && u.type!=ASN1_PRINTABLE_STRING && u.type!=ASN1_PC_STRING && u.type!=ASN1_UTF8_STRING)
       ) errx(1,"Incorrect ASN.1 type on stdin");
      snprintf(k,32,"%*.*s",u.length,u.length,u.data);
      if(asn1_next_of(&u,&v)) errx(1,"ASN.1 error on stdin");
      add_option(k,&u);
    } while(!asn1_next_of(&u,&v));
  }
  if(testmode&1) twalk(options,option_test_1);
  for(i=0;i<4;i++) x509nettle_rsa_alg(i,algorithms+i);
  x509_set_alglist(0,&options,&algorithms,4);
  
  if(binout) {
    outfile=stdout;
  } else {
    puts("-----BEGIN CERTIFICATE-----");
    outfile=open_base64_enc(stdout,0,0);
    if(!outfile) err(1,"Cannot open output");
  }
  
  if(!binout) {
    fclose(outfile);
    puts("-----END CERTIFICATE-----");
  }
  return 0;
}
