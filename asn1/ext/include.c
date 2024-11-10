#if 0
gcc -O2 -fPIC -shared -o include.so include.c
exit
#endif

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "asn1.h"

int fn_include(ASN1_Encoder*enc,const ASN1*values,int nvalues,const uint8_t*data,size_t length,void*userdata) {
  uint8_t q[0x2000];
  size_t s;
  uint8_t*buf=0;
  size_t len=0;
  FILE*f;
  FILE*g;
  if(!nvalues || values->type!=ASN1_OCTET_STRING) return 1;
  f=fopen(values->data,"r");
  if(!f) {
    warn("Cannot open file");
    return 1;
  }
  g=open_memstream((char**)&buf,&len);
  if(!g) errx(1,"Unexpected error");
  while(s=fread(q,1,0x2000,f)) fwrite(q,1,s,g);
  fclose(f);
  fclose(g);
  if(!buf) errx(1,"Unexpected error");
  if(userdata) {
    ASN1 v;
    if(asn1_parse(buf,len,&v,0)) {
      warnx("Cannot parse DER file");
      free(buf);
      return 1;
    }
    asn1_encode(enc,&v);
  } else {
    asn1_primitive(enc,ASN1_UNIVERSAL,ASN1_OCTET_STRING,buf,len);
  }
  free(buf);
  return 0;
}

const char*extfun_der(int(**funct)(ASN1_Encoder*,const ASN1*,int,const uint8_t*,size_t,void*),void**userdata,const char**option,uint8_t*data,size_t length) {
  if(length) return "This function definition should not have any argument";
  *funct=fn_include;
  *userdata="";
  *option="O";
  return 0;
}

const char*extfun_octet(int(**funct)(ASN1_Encoder*,const ASN1*,int,const uint8_t*,size_t,void*),void**userdata,const char**option,uint8_t*data,size_t length) {
  if(length) return "This function definition should not have any argument";
  *funct=fn_include;
  *option="O";
  return 0;
}

