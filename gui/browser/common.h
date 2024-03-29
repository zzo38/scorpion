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
#include "smallxrm.h"
#include "quarks.h"
#include "scogem.h"

enum {
  TF_NORMAL,
  TF_STRONG,
  TF_EMPHASIS,
  TF_FIXPITCH,
  TF_FURIGANA,
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

typedef Uint32 Color;

typedef struct {
  Uint8*attr_data;
  Uint8*body_data;
  Uint32 attr_len,body_len;
  Uint32 ypos;
  Uint8 type,charset,flag;
} Block;

typedef struct {
  Uint8 kind;
  char*name;
  Uint16*map;
  Uint8 link;
} CharsetInfo;

typedef struct {
  FontSet tron[NUM_TEXT_FORMATS];
  Font*others;
  Uint8*map;
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
  
} FontConfig;

extern SDL_Surface*screen;
extern xrm_db*xrm;
extern xrm_quark xrmquery[16];
extern int config_dir;
extern FontConfig fontc;

FILE*fopenat(int fd,const char*name,const char*mode);
void load_fontconfig(FILE*);

