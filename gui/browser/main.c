#if 0
gcc -s -O2 -fwrapv -o ~/bin/dschubba main.c fonts.o scogem.o fontconfig.o `sdl-config --cflags --libs`
exit
#endif

#define MAIN_PROGRAM
#include "common.h"

SDL_Surface*screen;
int config_dir=-1;

Config config={
#define I(n,t,d) .n=d,
#include "config.inc"
#undef I
};

typedef struct {
  const char*name;
  char kind;
  char size;
  void*ptr;
} ConfigInfo;

static const ConfigInfo configinfo[]={
#define B(n,t,d) {#n,'B',sizeof(t),&config.n},
#define F(n,t,d) {#n,'F',sizeof(t),&config.n},
#define I(n,t,d) {#n,'I',sizeof(t),&config.n},
#define S(n,t,d) {#n,'S',sizeof(t),&config.n},
#include "config.inc"
#undef B
#undef F
#undef I
#undef S
};

Color parse_color(const char*x) {
  unsigned char r,g,b;
  if(*x=='#' && strlen(x)==7) {
    if(sscanf(x+1,"%2hhX%2hhX%2hhX",&r,&g,&b)!=3) goto bad;
    return SDL_MapRGB(screen->format,r,g,b);
  } else {
    bad: errx(1,"Improper colour code: %s",x);
  }
}

static int compare_configinfo(const void*a,const void*b) {
  const ConfigInfo*x=a;
  const ConfigInfo*y=b;
  return strcmp(x->name,y->name);
}

static void set_config(const char*s) {
  char buf[128];
  const char*q=strchr(s,'=');
  ConfigInfo*c;
  ConfigInfo k={buf,0,0,0};
  unsigned long long v;
  if(!q) errx(1,"Invalid configuration");
  snprintf(buf,q-s>126?126:q+1-s,"%s",s);
  c=bsearch(&k,configinfo,sizeof(configinfo)/sizeof(ConfigInfo),sizeof(ConfigInfo),compare_configinfo);
  if(!c) errx(1,"Unknown configuration option '%s'",buf);
  switch(c->kind) {
    case 'B': case 'I':
      v=strtoll(q+1,0,0);
      if(c->size==sizeof(int)) *(int*)(c->ptr)=v;
      else if(c->size==sizeof(Uint8)) *(Uint8*)(c->ptr)=v;
      else if(c->size==sizeof(Uint16)) *(Uint16*)(c->ptr)=v;
      else if(c->size==sizeof(Uint32)) *(Uint32*)(c->ptr)=v;
      else if(c->size==sizeof(long)) *(long*)(c->ptr)=v;
      else if(c->size==sizeof(long long)) *(long long*)(c->ptr)=v;
      else errx(1,"Unexpected error in configuration");
      break;
    case 'F':
      if(c->size==sizeof(float)) *(float*)(c->ptr)=strtod(q+1,0);
      else if(c->size==sizeof(double)) *(double*)(c->ptr)=strtod(q+1,0);
      else errx(1,"Unexpected error in configuration");
      break;
    case 'S':
      if(c->size==sizeof(char*)) *(char**)(c->ptr)=strdup(q+1);
      else errx(1,"Unexpected error in configuration");
      break;
  }
}

FILE*fopenat(int fd,const char*name,const char*mode) {
  int m;
  FILE*f;
  if(strchr(mode,'+')) m=O_RDWR; else if(*mode=='r') m=O_RDONLY; else m=O_WRONLY;
  if(*mode!='r') m|=O_CREAT;
  if(*mode=='a') m|=O_APPEND;
  if(strchr(mode,'x')) m|=O_EXCL;
  if(strchr(mode,'e')) m|=O_CLOEXEC;
  if(*mode=='w') m|=O_TRUNC;
  fd=openat(fd,name,m,0666);
  f=fdopen(fd,mode);
  if(fd!=-1 && !f) close(fd);
  return f;
}

static void init_video(void) {
  screen=SDL_SetVideoMode(config.width,config.height,32,SDL_SWSURFACE|SDL_RESIZABLE|SDL_ANYFORMAT);
  if(!screen) errx(1,"SDL error: %s",SDL_GetError());
  SDL_EnableUNICODE(1);
}

static void parse_main_config(FILE*f) {
  char*line=0;
  char*p;
  size_t linesize=0;
  while(getline(&line,&linesize,f)>0) {
    p=line+strlen(line);
    while(p>line && (p[-1]=='\r' || p[-1]=='\n' || p[-1]==' ' || p[-1]=='\t')) *--p=0;
    p=line;
    if(!*p || *p=='#' || *p==';') continue;
    set_config(p);
  }
  free(line);
}

static void load_configuration(void) {
  const char*h;
  char*v;
  FILE*f;
  if(h=getenv("DSCHUBBA_DIR")) {
    config_dir=open(h,O_RDONLY|O_DIRECTORY);
  } else if((h=getenv("HOME")) && *h) {
    v=malloc(strlen(h)+11);
    if(!v) err(1,"Allocation failed");
    sprintf(v,"%s%s.dschubba",h,h[strlen(h)-1]=='/'?"":"/");
    config_dir=open(v,O_RDONLY|O_DIRECTORY);
    free(v);
  }
  if(config_dir==-1) errx(1,"Cannot open configuration directory");
  // Main configuration file
  f=fopenat(config_dir,"config","r");
  if(!f) err(1,"Cannot open configuration file");
  parse_main_config(f);
  fclose(f);
}

int main(int argc,char**argv) {
  int c;
  load_configuration();
  while((c=getopt(argc,argv,"+c:"))>0) switch(c) {
    case 'c': set_config(optarg); break;
    default: return 1;
  }
  
  if(SDL_Init(SDL_INIT_VIDEO|SDL_INIT_TIMER)) errx(1,"Cannot initialize SDL: %s",SDL_GetError());
  atexit(SDL_Quit);
  init_video();
  load_fontconfig();
  
}
