#if 0
gcc -s -O2 -o ~/bin/scorpiond -fwrapv scorpiond.c
exit
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
  const char*suffix;
  const char*type;
} MimeDef;
#include "scorpiond.config"

#ifdef CONFIG_SAFE_FILENAMES
static const char safech[128]={
  ['0']=1,1,1,1,1,1,1,1,1,1,
  ['A']=1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  ['a']=1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  ['-']=1, ['_']=1, ['.']=1,
};
#endif

static char req[CONFIG_MAX_REQUEST+4];
static char name[CONFIG_MAX_NAME+4];
static unsigned int reqn=0;
static char*url;
static struct stat stats;

static int percent_decode(const char*p) {
  int r;
  if(*p>='0' && *p<='9') r=*p++-'0';
  else if(*p>='a' && *p<='f') r=*p++-'a'+10;
  else if(*p>='A' && *p<='F') r=*p++-'A'+10;
  else goto bad;
  r<<=4;
  if(*p>='0' && *p<='9') r+=*p-'0';
  else if(*p>='a' && *p<='f') r+=*p-'a'+10;
  else if(*p>='A' && *p<='F') r+=*p-'A'+10;
  else goto bad;
  if(r) return r;
  bad: printf("59 Bad request\r\n"); exit(0);
}

static int comparemime(const void*a,const void*b) {
  const MimeDef*x=a;
  const MimeDef*y=b;
  return strcmp(x->suffix,y->suffix);
}

#ifdef CONFIG_DIRLIST
static void send_link(const char*name) {
  size_t s=strlen(name);
  if(s>CONFIG_MAX_NAME) return;
  putchar(CONFIG_FILENAME_CHARSET|0x08);
  putchar(s>>8); putchar(s);
  fwrite(name,1,s+1,stdout);
  putchar(s>>8); putchar(s);
  fwrite(name,1,s,stdout);
}
#endif

static void dirlist(void) {
#ifdef CONFIG_DIRLIST
  glob_t g;
  typeof(g.gl_pathc) i;
  int e;
  if(req[1]!=' ') {
    printf("59 Range request not implemented\r\n");
    exit(0);
  }
  g.gl_pathc=0; g.gl_pathv=0; g.gl_offs=0;
  e=glob("*",GLOB_MARK|GLOB_ERR,0,&g);
  if(e && e!=GLOB_NOMATCH) {
    printf("41 " CONFIG_UNEXPECTED_ERROR_TIME " Unexpected error reading directory\r\n");
    exit(0);
  }
  printf("20 ? document:scorpion\r\n");
  fflush(stdout);
  send_link("../");
  if(e!=GLOB_NOMATCH) for(i=0;i<g.gl_pathc;i++) send_link(g.gl_pathv[i]);
#else
  printf("54 Directory listing not allowed\r\n");
#endif
  exit(0);
}

static void normal(const char*suffix) {
  MimeDef key;
  MimeDef*mime=0;
  off_t begin,end;
  int fd;
  char h=0;
  if(req[1]!=' ') {
    char*p=req+1;
    begin=end=0;
    while(*p>='0' && *p<='9') begin=10*begin+*p++-'0';
    if(*p++!='-') {
      printf("59 Bad request\r\n");
      exit(0);
    }
    if(*p==' ') {
      h=2;
    } else {
      h=1;
      while(*p>='0' && *p<='9') end=10*end+*p++-'0';
      if(*p!=' ' || end<=begin) {
        printf("59 Bad request\r\n");
        exit(0);
      }
    }
  }
  key.suffix=suffix;
  mime=bsearch(&key,mimetypes,sizeof(mimetypes)/sizeof(MimeDef),sizeof(MimeDef),comparemime);
  fd=open(name,O_RDONLY);
  if(fd==-1) {
    if(errno==EACCES) printf("54 Forbidden\r\n");
    else printf("41 " CONFIG_UNEXPECTED_ERROR_TIME " Cannot open file\r\n");
    exit(0);
  }
  flock(fd,LOCK_NB|LOCK_SH);
  fstat(fd,&stats);
  printf("2%c %llu %s\r\n",h?'1':'0',(unsigned long long)stats.st_size,mime?mime->type:CONFIG_DEFAULT_MIMETYPE);
  fflush(stdout);
  if(h==0) {
    sendfile(1,fd,0,stats.st_size);
  } else if(h==1) {
    sendfile(1,fd,&begin,end-begin);
  } else if(h==2) {
    sendfile(1,fd,&begin,stats.st_size);
  }
  close(fd);
  exit(0);
}

int main(int argc,char**argv) {
  char*p;
  char*s;
  int b,c,n;
#ifdef CONFIG_MAINTENANCE
  fwrite(CONFIG_MAINTENANCE,1,sizeof(CONFIG_MAINTENANCE)-1,stdout);
#else
#ifdef CONFIG_TIMELIMIT
  alarm(CONFIG_TIMELIMIT);
#endif
  // Read request
  for(n=0;;) {
    c=getchar();
    if(c==EOF) return 0;
    if(c=='\r') {
      c=getchar();
      if(c!='\n') return 0;
    }
    if(c=='\n') break;
    if(reqn==CONFIG_MAX_REQUEST-1) {
      printf("59 Too long request\r\n");
      return 0;
    }
    if(c==' ') n=(n?2:1);
    if(c>=0 && c<32) n=2;
    req[reqn++]=c;
  }
  if(n!=1) goto bad;
  url=strchr(req,' ');
  if(!url || !url[1]) goto bad;
  p=++url;
  c=0;
  while(c<8 && *p=="scorpion"[c]) c++,p++;
  if(c!=8) goto badproxy;
  if(*p=='s') p++;
  if(*p++!=':') goto badproxy;
  if(*p++!='/') goto badproxy;
  if(*p++!='/') goto badproxy;
  // Change directory
  if(chdir(argc>1?argv[1]:CONFIG_ROOT)) goto notfound;
  // Read host:port, possibly preceded by username:password
  for(c=n=0;;) {
    if(c==CONFIG_MAX_NAME) goto toolong;
    switch(*p) {
      case 0: *p++='/'; *p=0; goto endhost;
      case '/': p++; goto endhost;
      case ':':
        // Port or password follows, and will be ignored
        goto port;
      case '@':
        // Username has been read; read host name next
        atsign:
        if(n) goto bad;
        n=1; c=0; p++;
        break;
      case '%':
        name[c++]=percent_decode(p+1);
        p+=3;
        break;
      default:
        name[c++]=*p++;
    }
  }
  port:
  for(;;) {
    switch(*p) {
      case 0: *p++='/'; *p=0; goto endhost;
      case '@': goto atsign;
      case '/': p++; goto endhost;
      default: p++;
    }
  }
  endhost:
  if(!c) goto bad;
  if(name[c-1]=='.') name[c-1]=0;
  name[c]=0;
  if(*name=='.') goto badproxy;
  for(c=0;name[c];c++) {
    if(name[c]>='A' && name[c]<='Z') name[c]+='a'-'A';
    if(name[c]!='-' && (name[c]<'0' || name[c]>'9') && name[c]!='.' && (name[c]<'a' || name[c]>'z')) goto badproxy;
  }
  if(chdir(name)) {
    goto badproxy;
  }
  // Read path and file name
  for(c=n=0;;) {
    switch(c=*p) {
      case 0: case '?': case '#': case '/':
        name[n]=0;
        if(!n) {
          if(c=='/') goto bad;
#ifdef CONFIG_DEFAULT_FILENAME
          strcpy(name,CONFIG_DEFAULT_FILENAME);
#else
          if(*req!='R') goto badsub;
          dirlist();
          return 0;
#endif
        } else {
          if(name[0]=='.' && (name[1]=='.' || name[1]=='_' || name[1]=='-' || !name[1])) goto bad;
        }
        if(stat(name,&stats)) {
#ifdef CONFIG_DEFAULT_FILENAME
          if(!n && errno==ENOENT) {
            if(*req!='R') goto badsub;
            dirlist();
            return 0;
          }
#endif
          if(errno==ENOENT || errno==ENOTDIR) goto notfound;
          if(errno==EACCES) goto forbid;
          goto internal;
        }
        if((stats.st_mode&(S_IRGRP|S_IROTH))!=(S_IRGRP|S_IROTH)) goto forbid;
        if(S_ISDIR(stats.st_mode)) {
          if(c!='/') {
            // Redirect
            printf("31 %.*s/%s\r\n",(int)(p-url),url,p);
            return 0;
          }
          if(chdir(name)) goto internal;
        } else if(S_ISREG(stats.st_mode)) {
          if(*req!='R') goto badsub;
#ifdef CONFIG_ALLOW_CGI
          if((stats.st_mode&(S_IXGRP|S_IXOTH))==(S_IXGRP|S_IXOTH)) {
#ifdef CONFIG_CANCEL_ALARM
            alarm(0);
#endif
            execl(name,name,req,p,(char*)0);
            printf("50 File cannot be executed\r\n");
            return 0;
          }
#endif
          if(c=='/') goto notfound;
          normal(s);
          return 0;
        } else {
          goto forbid;
        }
        n=0;
        p++;
        s=0;
        break;
      case '%':
        c=percent_decode(p+1);
        p+=2;
        if(c=='/') goto bad;
        // fall through
      default:
        if(n==CONFIG_MAX_NAME) goto toolong;
#ifdef CONFIG_SAFE_FILENAMES
        if((c&~127) || !safech[c]) goto bad;
#endif
        name[n++]=c;
        if(c=='.') s=name+n;
        p++;
    }
  }
#endif
  return 0;
  bad: printf("59 Bad request\r\n"); return 0;
  badproxy: printf("53 Refused proxy\r\n"); return 0;
  badsub: printf("59 Improper subprotocol\r\n"); return 0;
  notfound: printf("51 File not found\r\n"); return 0;
  forbid: printf("54 Forbidden\r\n"); return 0;
  toolong: printf("59 Name too long\r\n"); return 0;
  internal: printf("41 " CONFIG_UNEXPECTED_ERROR_TIME " Unexpected internal error\r\n"); return 0;
}

