#if 0
gcc -g -O0 -o ~/bin/dschubba main.c window.o -lX11
exit
#endif

#include "browser.h"
#include <fcntl.h>
#include <sys/stat.h>

static int configdir=-1;

GlobalConfig config={
#define B(n,t,d) d,
#define C(n,t,d) 0,
#define I(n,t,d) d,
#define S(n,t,d) d,
#include "config.inc"
#undef B
#undef C
#undef I
#undef S
};

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
  if(fd==-1) return 0;
  f=fdopen(fd,mode);
  if(!f) close(fd);
  return f;
}

static int config_getline(char**x,size_t*y,FILE*f) {
  char*z;
  long n;
  repeat:
  if((n=getline(x,y,f))<=0) return 1;
  if(**x=='#' || **x=='\n' || !**x) goto repeat;
  z=*x;
  while(n && (z[n-1]=='\n' || z[n-1]=='\r')) z[--n]=0;
  return 0;
}

static void load_config_from_file(FILE*f) {
  char*line=0;
  size_t line_len=0;
  int i;
#define X(n) for(;;) { if(config_getline(&line,&line_len,f)) goto end; if(strncmp(line,#n"=",sizeof(#n))) break;
#define B(n,t,d) X(n) i=line[sizeof(#n)]; if(i=='0') config.n=0; if(i=='1') config.n=1; break; }
#define C(n,t,d) X(n) config.n=strdup(line+sizeof(#n)); break; }
#define I(n,t,d) X(n) config.n=strtol(line+sizeof(#n),0,0); break; }
#define S(n,t,d) X(n) config.n=strdup(line+sizeof(#n)); break; }
#include "config.inc"
#undef B
#undef C
#undef I
#undef S
#undef X
  errx(1,"Unrecognized command or incorrect order in configuration file:  %s",line);
  end:
  free(line);
}

static void auto_configdir(void) {
  char buf[1024];
  char*v=getenv("HOME");
  if(!v) errx(1,"HOME environment variable not set");
  snprintf(buf,1024,"%s/.dschubba",v);
  configdir=open(buf,O_RDONLY|O_DIRECTORY);
  if(!configdir) err(1,"Cannot open configuration directory");
}

static void initialize(int argc,char**argv) {
  FILE*f;
  WindowConfig wc={};
  if(configdir==-1) auto_configdir();
  if(f=fopenat(configdir,"config","r")) {
    load_config_from_file(f);
    fclose(f);
  }
  wc.geom=config.geometry;
  wc.name=wc.class="Dschubba";
  wc.argc=argc;
  wc.argv=argv;
  wc.visualid=config.visual;
  wc.depth=config.depth;
  wc.private_colors=config.private_colors;
  init_window_system(&wc);
}

int main(int argc,char**argv) {
  int c;
  while((c=getopt(argc,argv,"+C:g:"))>0) switch(c) {
    case 'C': configdir=open(optarg,O_RDONLY|O_DIRECTORY); if(configdir==-1) err(1,"Cannot open '%s'",optarg); break;
    case 'g': config.geometry=optarg; break;
    default: errx(1,"Improper switch");
  }
  initialize(argc,argv);
  return 0;
}
