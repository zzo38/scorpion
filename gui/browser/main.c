#if 0
gcc -s -O2 -fwrapv -o ~/bin/dschubba main.c fonts.o scogem.o smallxrm.o fontconfig.o `sdl-config --cflags --libs`
exit
#endif

#define MAIN_PROGRAM
#include "common.h"

SDL_Surface*screen;
xrm_db*xrm;
xrm_quark xrmquery[16];
int config_dir=-1;

FILE*fopenat(int fd,const char*name,const char*mode) {
  int m;
  FILE*f;
  if(strchr(mode,'+')) m=O_RDWR; else if(*mode=='r') m=O_RDONLY; else m=O_WRONLY;
  if(*mode!='r') m|=O_CREAT;
  if(*mode=='a') m|=O_APPEND;
  if(strchr(mode,'x')) m|=O_EXCL;
  if(strchr(mode,'e')) m|=O_CLOEXEC;
  if(*mode=='w') m|=O_TRUNC;
  fd=openat(fd,name,m);
  f=fdopen(fd,mode);
  if(fd!=-1 && !f) close(fd);
  return f;
}

static void init_video(void) {
  int w,h;
  xrmquery[0]=Q_screen;
  xrmquery[1]=Q_width;
  w=strtol(xrm_get_resource(xrm,xrmquery,xrmquery,2)?:"",0,10)?:640;
  xrmquery[1]=Q_height;
  h=strtol(xrm_get_resource(xrm,xrmquery,xrmquery,2)?:"",0,10)?:480;
  screen=SDL_SetVideoMode(w,h,32,SDL_SWSURFACE|SDL_RESIZABLE|SDL_ANYFORMAT);
  if(!screen) errx(1,"SDL error: %s",SDL_GetError());
  SDL_EnableUNICODE(1);
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
  if(xrm_load(xrm,f,0)) errx(1,"Cannot load configuration file");
  fclose(f);
  // Font configuration
  f=fopenat(config_dir,"fontconfig","r");
  if(!f) err(1,"Cannot open font configuration file");
  load_fontconfig(f);
  fclose(f);
  
}

int main(int argc,char**argv) {
  int c;
  if(xrm_init(realloc) || xrm_init_quarks(quarkslist)) errx(1,"Error initializing configuration database");
  xrm=xrm_create();
  if(!xrm) err(1,"Error initializing configuration database");
  while((c=getopt(argc,argv,"+R:"))>0) switch(c) {
    case 'R': if(xrm_load_line(xrm,optarg,1)) errx(1,"Improper X resource manager text"); break;
    default: return 1;
  }
  load_configuration();
  
  if(SDL_Init(SDL_INIT_VIDEO|SDL_INIT_TIMER)) errx(1,"Cannot initialize SDL: %s",SDL_GetError());
  atexit(SDL_Quit);
  init_video();
  
}
