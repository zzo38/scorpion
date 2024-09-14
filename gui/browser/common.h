#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "SDL.h"
#include "fonts.h"
#include "scogem.h"

enum {
  TF_NORMAL, // 'N'
  TF_STRONG, // 'S'
  TF_EMPHASIS, // 'E'
  TF_FIXPITCH, // 'F'
  TF_FURIGANA, // 'U'
  NUM_TEXT_FORMATS
};

enum {
  B_NORMAL,
  B_H1,
  B_H2,
  B_H3,
  B_H4,
  B_H5,
  B_H6,
  B_UNUSED_7,
  B_LINK,
  B_LINK_INPUT,
  B_LINK_INTERACT,
  B_LINK_ALTERNATE,
  B_QUOTE,
  B_PRE,
  B_UNUSED_E,
  B_METADATA,
  // The above are the standard Scorpion block types
  B_EOF,
  B_ERROR,
  B_INFO,
  B_SYSTEM,
  NUM_BLOCK_TYPES
};

enum {
  // Charset kinds
  CS_UNDEF,
  CS_NORMAL,
  CS_TRON,
  CS_MAPPED_TRON,
  CS_ALIAS,
};

typedef Uint32 Color;

typedef struct {
  Uint8 kind;
  Uint32*map;
  Uint8 link;
} CharsetInfo;

typedef struct {
  char*name;
  Uint8 id;
} CharsetName;

typedef struct {
  FontSet tron[NUM_TEXT_FORMATS];
  Font*others;
  Uint8*map;
  Uint8 xsc,ysc,oxsc,oysc,numcs;
  Uint16 other;
} FontGroup;

typedef struct {
  Uint8 lmargin,rmargin;
  Sint8 indent;
  Uint8 leading,height,depth;
  Uint16 group;
  Color color;
} BlockStyle;

typedef struct {
  FontGroup*group;
  BlockStyle bstyle[NUM_BLOCK_TYPES];
  CharsetInfo*charset;
  CharsetName*csnames;
  Uint8 ngroup,ncharset,ncsnames;
  Uint8 ui1,ui2;
} FontConfig;

typedef struct {
  Uint8*attr_data;
  Uint8*body_data;
  Uint32 attr_len,body_len;
  Uint32 ypos;
  Uint8 type,charset,flag;
} Block;

typedef struct DocumentClass DocumentClass;

typedef struct Document {
  DocumentClass*class;
  void*misc1;
  void*misc2;
  Uint32 misc3;
  Uint8*data;
  size_t size;
  Uint8*orig_data;
  size_t orig_size;
  Uint32 refcount;
} Document;

typedef struct DocumentClass {
  void(*initialize)(Document*doc);
  void(*finalize)(Document*doc);
  void(*clone)(Document*src,Document*dest);
  void(*unclone)(Document*doc);
} DocumentClass;

typedef struct {
#define B(n,t,d) t n;
#define I(n,t,d) t n;
#include "config.inc"
#undef B
#undef I
} Config;

extern SDL_Surface*screen;
extern int config_dir;
extern Config config;

extern FontConfig fontc;

Color parse_color(const char*x);
FILE*fopenat(int fd,const char*name,const char*mode);
void load_fontconfig(void);
int find_charset_by_name(const char*name);

