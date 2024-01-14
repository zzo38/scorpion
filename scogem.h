
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Scogem_UlfiList {
  const char*name;
  uint32_t bit;
  void(*parameter)(void*,const char*,const struct Scogem_UlfiList*);
} Scogem_UlfiList;

typedef struct {
  const char*url;
  char*host;
  char port[8];
  char scheme[16];
  char*username;
  char*password;
  char*fragment;
  uint16_t userinfo_start,userinfo_end;
  uint16_t password_start,password_end;
  uint16_t resource_start,resource_end;
  uint16_t inner_start,inner_end;
  uint16_t portnumber,code;
} Scogem_URL;

typedef enum {
  SCOGEM_O_USERNAME,
  SCOGEM_O_PASSWORD, // also used for upload tokens with Gemini
  SCOGEM_O_URL,
  SCOGEM_O_FILE_VERSION, // used for upload tokens with Scorpion and for range requests
  SCOGEM_O_SIZE, // upload size
  SCOGEM_O_RANGE_START,
  SCOGEM_O_RANGE_END,
  SCOGEM_O_CLIENT_CERTIFICATE,
  SCOGEM_O_EXTRA_HEADERS, // used with HTTP
} Scogem_Option;

void scogem_ulfi_parse(const Scogem_UlfiList*list,int nlist,const char*text,uint8_t*bits,void*extra);

int scogem_parse_url(Scogem_URL*out,const char*url,uint32_t flag);
void scogem_free_url(Scogem_URL*obj);

int scogem_relative(FILE*out,const char*base,const char*url);
int scogem_relative_cwd(FILE*out,const char*url);

#define SCOGEM_SPACE_AS_PLUS 0x01
#define SCOGEM_CONTROL_STOP 0x02
#define SCOGEM_ALLOW_NULL 0x04
#define SCOGEM_NOENCODE_SLASH 0x08

void scogem_encode_c(uint8_t flag,FILE*out,uint8_t in);
void scogem_encode_f(uint8_t flag,FILE*out,FILE*in);
void scogem_encode_m(uint8_t flag,FILE*out,const char*in,size_t len);
void scogem_encode_s(uint8_t flag,FILE*out,const char*in);
int scogem_decode_f(uint8_t flag,FILE*out,FILE*in);
int scogem_decode_m(uint8_t flag,FILE*out,const char*in,size_t len);
int scogem_decode_s(uint8_t flag,FILE*out,const char*in);

