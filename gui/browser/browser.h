
#include "window.h"
#include "scogem.h"

typedef struct Browser Browser;
typedef struct CharsetID CharsetID;
typedef struct Document Document;
typedef struct DocumentClass DocumentClass;
typedef struct DocumentView DocumentView;

struct CharsetID {
  uint8_t class;
  union {
    uint32_t number;
    const char*name;
  };
};

struct Document {
  const DocumentClass*class;
  
  char unused[0] __attribute__((aligned(__BIGGEST_ALIGNMENT__)));
};

struct DocumentClass {
  Document*(*create)(const DocumentClass*class,const char*type);
  void(*destroy)(Document*doc);
  void(*ulfi_parameter)(void*v,const char*text,const struct Scogem_UlfiList*item);
  
};

struct DocumentView {
  
};

typedef struct {
#define B(n,t,d) t n;
#define C(n,t,d) char*n;
#define I(n,t,d) t n;
#define S(n,t,d) t n;
#include "config.inc"
#undef B
#undef C
#undef I
#undef S
} GlobalConfig;

extern GlobalConfig config;

FILE*fopenat(int fd,const char*name,const char*mode);

