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
#include <sys/select.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

typedef struct {
  const char*suffix;
  const char*type;
} MimeDef;
#include "scorpiond.config"
#ifdef CONFIG_USER_DIR
#include <pwd.h>
#endif

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
#ifdef CONFIG_USER_DIR
static struct passwd*userinfo;
#endif

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
static void send_link(const char*n) {
  size_t s=strlen(n);
  if(s>CONFIG_MAX_NAME) return;
  putchar(CONFIG_FILENAME_CHARSET|0x08);
  putchar(s>>8); putchar(s);
  fwrite(n,1,s+1,stdout);
  putchar(s>>8); putchar(s);
  fwrite(n,1,s,stdout);
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
  key.suffix=suffix?:"";
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

#ifdef CONFIG_ALLOW_SOCKET
static int send_counted_string(int fd,long len,const void*data) {
  unsigned char buf[4]={len>>24,len>>16,len>>8,len};
  if(send(fd,buf,4,0)==-1 || send(fd,data,len,0)==-1) return -1;
  return 0;
}

static int do_socket(const char*req2) {
  unsigned char buf[CONFIG_BUF_SIZE];
  ssize_t x,y,z;
  fd_set set;
  const char*p;
  int fd=socket(AF_UNIX,SOCK_STREAM,0);
  struct sockaddr_un sa={};
  if(fd==-1) return -1;
  sa.sun_family=AF_UNIX;
  strncpy(sa.sun_path,name,sizeof(sa.sun_path)-1);
  if(connect(fd,(void*)(&sa),sizeof(sa))) return -1;
  send_counted_string(fd,req2-req,req);
  send_counted_string(fd,strlen(req2),req2);
  if(p=getenv("REMOTE_HOST")) send_counted_string(fd,strlen(p),p); else send_counted_string(fd,0,"");
  send_counted_string(fd,0,""); // reserved for client certificate
#ifdef CONFIG_CANCEL_ALARM
  alarm(0);
#endif
  for(;;) {
    FD_ZERO(&set);
    FD_SET(0,&set);
    FD_SET(fd,&set);
    if(select(fd+1,&set,0,0,0)<=0) break;
    if(FD_ISSET(0,&set)) {
      z=read(0,buf,CONFIG_BUF_SIZE);
      if(z<=0) break;
      for(y=0;y<z;) {
        x=write(fd,buf+y,z);
        if(x<0) break;
        y+=x;
      }
    }
    if(FD_ISSET(fd,&set)) {
      z=read(fd,buf,CONFIG_BUF_SIZE);
      if(z<=0) break;
      for(y=0;y<z;) {
        x=write(1,buf+y,z);
        if(x<0) break;
        y+=x;
      }
    }
  }
  return 0;
}
#endif

#ifdef CONFIG_LOG_FILE
static void write_to_log_file(void) {
  char buf[256];
  int f=open(CONFIG_LOG_FILE,O_WRONLY|O_APPEND|O_CREAT,0666);
  if(f==-1) return;
  flock(f,LOCK_EX);
  write(f,buf,snprintf(buf,256,"%lld (%s) ",(long long)time(0),getenv("REMOTE_HOST")?:""));
  write(f,req,reqn);
  write(f,"\n",1);
  flock(f,LOCK_UN);
  close(f);
}
#endif

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
#ifdef CONFIG_LOG_FILE
  write_to_log_file();
#endif
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
#ifdef CONFIG_USER_DIR
        if(*name=='~') {
          userinfo=getpwnam(name+1);
          if(!userinfo || chdir(userinfo->pw_dir)) goto notfound;
          strcpy(name,CONFIG_USER_DIR);
        }
#endif
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
        if((stats.st_mode&(CONFIG_FILEMODE_ACCESS))!=(CONFIG_FILEMODE_ACCESS)) goto forbid;
        if(S_ISDIR(stats.st_mode)) {
          if(c!='/') {
            // Redirect
            printf("31 %.*s/%s\r\n",(int)(p-url),url,p);
            return 0;
          }
          if(chdir(name)) goto internal;
        } else if(S_ISREG(stats.st_mode)) {
#ifdef CONFIG_ALLOW_CGI
          if((stats.st_mode&(CONFIG_FILEMODE_EXECUTE))==(CONFIG_FILEMODE_EXECUTE)) {
#ifdef CONFIG_USER_DIR
#ifndef CONFIG_ALLOW_USER_CGI
            if(userinfo) goto noexec;
#endif
#endif
#ifdef CONFIG_CANCEL_ALARM
            alarm(0);
#endif
            execl(name,name,req,p,(char*)0);
            noexec:
            printf("50 File cannot be executed\r\n");
            return 0;
          }
#endif
          if(*req!='R') goto badsub;
          if(c=='/') goto notfound;
#ifdef CONFIG_DEFAULT_FILENAME
          if(!n) { s=strchr(CONFIG_DEFAULT_FILENAME,'.'); s=s?s+1:""; }
#endif
          normal(s);
          return 0;
#ifdef CONFIG_ALLOW_SOCKET
        } else if(S_ISSOCK(stats.st_mode)) {
#ifndef CONFIG_ALLOW_USER_SOCKET
          if(userinfo) goto noexec;
#endif
          if(do_socket(p)) goto internal;
          return 0;
#endif
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
#ifdef CONFIG_USER_DIR
        if(c=='~' && !n) {
          if(stats.st_mode) goto bad;
          name[n++]='~';
          p++;
          break;
        }
#endif
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

