#if 0
gcc -s -O2 -o ~/bin/astroget -Wno-multichar astroget.c scogem.o hash.o simpletls.o -lssl
exit
#endif

#define NO_LIMIT 0x7FFFFFFFFFFFFFFFULL

#define ERR_ARGUMENT 4
#define ERR_MEMORY 5
#define ERR_URL 6
#define ERR_NOT_IMPLEMENTED 7
#define ERR_IO_ERROR 8
#define ERR_UNKNOWN 9
#define ERR_NET 10
#define ERR_PROTOCOL 11
#define ERR_EXISTS 12
#define ERR_RESTRICTED 13

#include "scogem.h"
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "simpletls.h"
#include "hash.h"

static FILE*memfile;
static char*membuf;
static size_t membufsize;

static char*baseurl;
static char*url;
static Scogem_URL urlinfo;
static uint16_t option;
static FILE*upfile;
static const char*uptype;
static const char*upversion;
static const char*upversion2;
static uint64_t range_start=0;
static uint64_t range_end=NO_LIMIT;
static struct sockaddr_in forced_address;
static const char*tlsoption;
static uint64_t progress_amount=0;
static const char*outfilename;
static Certificate certificate;
static uint8_t address_restrict=0;
static uint8_t redirectlimit=0;
static uint8_t redirectflag=0;
static char*redirecturl;

static void base64encode(FILE*f,...) {
  static const char e[64]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  uint32_t v=0;
  const unsigned char*s;
  int n=16;
  va_list ap;
  va_start(ap,f);
  while(s=va_arg(ap,unsigned char*)) {
    while(*s) {
      v|=*s++<<n;
      if(n) {
        n-=8;
      } else {
        fputc(e[(v>>18)&63],f);
        fputc(e[(v>>12)&63],f);
        fputc(e[(v>>6)&63],f);
        fputc(e[(v>>0)&63],f);
        n=16;
        v=0;
      }
    }
  }
  va_end(ap);
  if(n==0) {
    fputc(e[(v>>18)&63],f);
    fputc(e[(v>>12)&63],f);
    fputc(e[(v>>6)&63],f);
    fputc('=',f);
  } else if(n==8) {
    fputc(e[(v>>18)&63],f);
    fputc(e[(v>>12)&63],f);
    fputc('=',f);
    fputc('=',f);
  }
}

static char*relative_to_absolute(const char*t) {
  size_t s=0;
  char*o=0;
  FILE*f=open_memstream(&o,&s);
  if(!f) err(ERR_MEMORY,"Cannot open memory stream");
  if(baseurl?scogem_relative(f,baseurl,t):scogem_relative_cwd(f,t)) errx(ERR_URL,"Cannot convert relative to absolute URL (%s)",t);
  fclose(f);
  if(!o) err(ERR_MEMORY,0);
  return o;
}

static void ulfi_callback(void*extra,const char*data,const Scogem_UlfiList*info) {
  printf("%s[%s]\n",info->name,data);
}

static int do_ulfi(char*arg) {
  Scogem_UlfiList*list=0;
  int nlist=0;
  uint8_t*bits=0;
  char*line=0;
  size_t linesize=0;
  int i;
  while(getline(&line,&linesize,stdin)>0) {
    list=realloc(list,(nlist+1)*sizeof(Scogem_UlfiList));
    if(!list) err(ERR_MEMORY,"Allocation failed");
    *strchrnul(line,'\n')=0;
    list[nlist].name=strdup(line);
    if(!list[nlist].name) err(ERR_MEMORY,"Allocation failed");
    list[nlist].bit=nlist;
    list[nlist].parameter=ulfi_callback;
    nlist++;
  }
  bits=calloc(1,(nlist+1)>>8);
  if(!bits) err(ERR_MEMORY,"Allocation failed");
  scogem_ulfi_parse(list,nlist,arg,bits,0);
  for(i=0;i<nlist;i++) if(bits[i>>3]&(1<<(i&7))) puts(list[i].name);
  return 0;
}

static void show_parsed_url(void) {
  if(urlinfo.url) printf("URL: %s\n",urlinfo.url);
  if(urlinfo.host) printf("Host: %s\n",urlinfo.host);
  if(*urlinfo.port) printf("Port: %s\n",urlinfo.port);
  if(*urlinfo.scheme) printf("Scheme: %s\n",urlinfo.scheme);
  if(urlinfo.username) printf("Username: %s\n",urlinfo.username);
  if(urlinfo.password) printf("Password: %s\n",urlinfo.password);
  if(urlinfo.fragment) printf("Fragment: %s\n",urlinfo.fragment);
  printf("Userinfo offset: %d-%d\n",urlinfo.userinfo_start,urlinfo.userinfo_end);
  printf("Password offset: %d-%d\n",urlinfo.password_start,urlinfo.password_end);
  printf("Resource offset: %d-%d\n",urlinfo.resource_start,urlinfo.resource_end);
  printf("Inner URL offset: %d-%d\n",urlinfo.inner_start,urlinfo.inner_end);
  printf("Port number: %d\n",urlinfo.portnumber);
  printf("Code: %d\n",urlinfo.code);
}

typedef struct {
  uint64_t start,end;
  void*obj;
  int(*header)(void*obj,const char*data);
  ssize_t(*write)(void*obj,const char*data,size_t length);
} Receiver;

typedef struct {
  void*obj;
  char delete;
  uint64_t total;
  const char*type;
  const char*version;
  const char*nversion;
  int(*header)(void*obj,const char*data);
  int(*read)(void*obj,char*data,size_t length);
} Sender;

typedef struct {
  const char*name;
  int(*receive)(const Scogem_URL*u,Receiver*z);
  int(*receive_range)(const Scogem_URL*u,Receiver*z);
  int(*send)(const Scogem_URL*u,Sender*z);
} ProtocolInfo;

static const ProtocolInfo*find_protocol(const Scogem_URL*u);

static void status_ok(Receiver*z,char k,uint64_t total,const char*mime) {
  char buf[0x1000];
  if(z->header) {
    snprintf(buf,0x1000,"2%c %llu %s",k,(unsigned long long)total,mime);
    z->header(z->obj,buf);
  }
}

static void check_address_restriction(const struct sockaddr_in*a) {
  const uint8_t*b=(const void*)&a->sin_addr.s_addr;
  static uint32_t s=0;
  if(address_restrict&1) {
    if(b[0]==255 && b[1]==255 && b[2]==255 && b[3]==255) errx(ERR_RESTRICTED,"Broadcast address is restricted");
    if(!b[0] && !b[1] && !b[2] && !b[3]) errx(ERR_RESTRICTED,"Broadcast address is restricted");
    if(b[0]==127) errx(ERR_RESTRICTED,"Loopback address is restricted");
  }
  if((address_restrict&2) && b[0]==10) errx(ERR_RESTRICTED,"Private address is restricted");
  if((address_restrict&4) && b[0]==172 && b[1]>=16 && b[1]<32) errx(ERR_RESTRICTED,"Private address is restricted");
  if((address_restrict&8) && b[0]==192 && b[1]==168) errx(ERR_RESTRICTED,"Private address is restricted");
  if(address_restrict&128) {
    if(s && s!=a->sin_addr.s_addr) errx(ERR_RESTRICTED,"Redirect to a different IP address");
    s=a->sin_addr.s_addr;
  }
}

static int dial(const char*host,uint16_t port) {
  char b[8];
  struct addrinfo h={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM,.ai_flags=AI_ADDRCONFIG};
  struct addrinfo*ai=0;
  int i,f;
  if(option&0x0040) fputs("\rc ; ",stderr);
  if(option&0x0020) {
    f=socket(AF_INET,SOCK_STREAM,0);
    if(f==-1) err(ERR_MEMORY,"Cannot open socket");
    i=connect(f,(void*)&forced_address,sizeof(struct sockaddr_in));
    if(i<0) err(ERR_NET,"Cannot connect to '%s:%u'",host,port);
  } else {
    snprintf(b,8,"%u",port);
    if(i=getaddrinfo(host,b,&h,&ai)) errx(ERR_NET,"%s",gai_strerror(i));
    if(address_restrict) check_address_restriction((void*)ai->ai_addr);
    if(option&0x0040) fputs("\rx ; ",stderr);
    f=socket(AF_INET,SOCK_STREAM,0);
    if(f==-1) err(ERR_MEMORY,"Cannot open socket");
    i=connect(f,ai->ai_addr,sizeof(struct sockaddr_in));
    if(i<0) err(ERR_NET,"Cannot connect to '%s:%u'",host,port);
    freeaddrinfo(ai);
  }
  if(option&0x0040) fputs("\rC ; ",stderr);
  return f;
}

static int dial_secure(const char*host,int16_t port,const Certificate*cert) {
  char b[8];
  struct addrinfo h={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM,.ai_flags=AI_ADDRCONFIG};
  struct addrinfo*ai=0;
  int i,f;
  if(option&0x0040) fputs("\rcs; ",stderr);
  if(option&0x0020) {
    f=secure_socket((void*)&forced_address,host,tlsoption,cert);
    if(f==-1) errx(ERR_MEMORY,"Cannot open secure socket");
  } else {
    snprintf(b,8,"%u",port);
    if(i=getaddrinfo(host,b,&h,&ai)) errx(ERR_NET,"%s",gai_strerror(i));
    if(address_restrict) check_address_restriction((void*)ai->ai_addr);
    f=secure_socket(ai->ai_addr,host,tlsoption,cert);
    if(f==-1) errx(ERR_MEMORY,"Cannot open secure socket");
    freeaddrinfo(ai);
  }
  if(option&0x0040) fputs("\rCs; ",stderr);
  return f;
}

static int raw_download_from(int f,Receiver*z) {
  ssize_t s;
  char buf[0x4000];
  while((s=recv(f,buf,0x4000,0))>0) z->write(z->obj,buf,s);
  return s;
}

static int limited_download_from(int f,Receiver*z,uint64_t t) {
  ssize_t s;
  char buf[0x4000];
  while(t && (s=recv(f,buf,t>0x4000?0x4000:t,0))>0) z->write(z->obj,buf,s),t-=s;
  return s;
}

static void send_data(int f,const char*p,size_t r) {
  ssize_t s;
  while(r) {
    s=send(f,p,r,MSG_NOSIGNAL);
    if(s<=0 || s>r) err(ERR_NET,"Error sending data");
    p+=s;
    r-=s;
  }
}

static void raw_upload_to(int f,Sender*z) {
  uint64_t q=z->total;
  uint64_t r;
  char buf[0x4000];
  while(q) {
    if(q>0x4000) r=0x2000; else r=q;
    if(z->read(z->obj,buf,r)) return;
    send_data(f,buf,r);
    q-=r;
  }
}

static int recv_byte(int f) {
  unsigned char b[1];
  ssize_t s=recv(f,b,1,MSG_WAITALL);
  if(s<0) err(ERR_NET,"Error receiving data");
  return s?*b:EOF;
}

static void send_mem(int f) {
  ssize_t s;
  size_t r;
  char*p;
  r=ftell(memfile);
  fflush(memfile);
  if(!membuf) errx(ERR_MEMORY,"Memory error");
  p=membuf;
  while(r) {
    s=send(f,p,r,MSG_NOSIGNAL);
    if(s<=0 || s>r) err(ERR_NET,"Error sending data");
    p+=s;
    r-=s;
  }
  if(membufsize>0x2000) {
    fclose(memfile);
    free(membuf);
    membuf=0;
    membufsize=0;
    memfile=open_memstream(&membuf,&membufsize);
    if(!memfile) err(ERR_MEMORY,"Cannot open stream");
  }
  rewind(memfile);
}

static int head_mem(Receiver*z) {
  int i=0;
  if(z->header) {
    fputc(0,memfile);
    fflush(memfile);
    if(!membuf) errx(ERR_MEMORY,"Memory error");
    i=z->header(z->obj,membuf);
  }
  rewind(memfile);
  return i;
}

static int head_mem_sender(Sender*z) {
  int i=0;
  if(z->header) {
    fputc(0,memfile);
    fflush(memfile);
    if(!membuf) errx(ERR_MEMORY,"Memory error");
    i=z->header(z->obj,membuf);
  }
  rewind(memfile);
  return i;
}

static signed char b64invs[]={
  62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
  59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
  6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
  29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
  43, 44, 45, 46, 47, 48, 49, 50, 51
};

static int r_data(const Scogem_URL*u,Receiver*z) {
  char mime[0x1000];
  FILE*f;
  const char*p;
  char a,b;
  uint64_t s=0;
  uint32_t t;
  f=fmemopen(mime,0x1000,"w");
  if(!f) err(ERR_MEMORY,"Error with fmemopen");
  p=strchr(u->url,',');
  if(!p) errx(ERR_URL,"Invalid data: URL without a comma");
  b=(p>=u->url+12 && !memcmp(p-7,";base64",7))?7:0;
  if(scogem_decode_m(SCOGEM_CONTROL_STOP,f,u->url+5,p-u->url-5-b)) errx(ERR_URL,"Invalid data: URL");
  if(fputc(0,f)) errx(ERR_URL,"Invalid data: URL");
  fclose(f);
  p++;
  while(*p) {
    if(b && *p=='=') break;
    if(*p=='%' && p[1] && p[2]) p+=3; else p++;
    s++;
  }
  if(b) s-=(s+2)/4;
  status_ok(z,'0',s,*mime?mime:"text/plain");
  p=strchr(u->url,',')+1;
  if(b) {
    a=t=0;
    while(*p) {
      if(*p=='%') {
        sscanf(p+1,"%02hhX",&b);
        p+=3;
      } else {
        b=*p++;
      }
      if(b=='=' || b<'+' || b>'z') break;
      t|=((uint32_t)b64invs[b-'+'])<<(18-a*6);
      if(++a==4) {
        mime[0]=t>>020; mime[1]=t>>010; mime[2]=t>>000;
        z->write(z,mime,3);
        a=t=0;
      }
    }
    if(a>1) {
      mime[0]=t>>020; mime[1]=t>>010; mime[2]=t>>000;
      z->write(z,mime,a-1);
    }
  } else {
    f=fopencookie(z->obj,"w",(cookie_io_functions_t){.write=z->write});
    if(!f) err(ERR_MEMORY,"Error with fopencookie");
    scogem_decode_s(SCOGEM_CONTROL_STOP|SCOGEM_ALLOW_NULL,f,p);
    fclose(f);
  }
  return 0;
}

static int r_file_1(const Scogem_URL*u,Receiver*z,int isr) {
  struct stat s;
  ssize_t q;
  size_t r;
  int f,e;
  char buf[0x4000];
  const char*p;
  if(address_restrict&1) errx(ERR_RESTRICTED,"Cannot use file: with -q");
  if(u->host && u->host[0] && strcmp(u->host,"localhost")) {
    if(z->header) z->header(z->obj,"53 Incorrect host name for local files");
    return 0;
  }
  e=u->resource_end;
  if(p=strchr(u->url+u->resource_start,'?')) {
    if(p-u->url<u->resource_end) e=p-u->url;
  }
  if(scogem_decode_m(SCOGEM_CONTROL_STOP|SCOGEM_NOENCODE_SLASH,memfile,u->url+u->resource_start,e-u->resource_start)) errx(ERR_URL,"Cannot decode URL");
  fputc(0,memfile);
  fflush(memfile);
  if(!membuf) errx(ERR_MEMORY,"Memory error");
  f=open(membuf,O_RDONLY|O_NOCTTY);
  if(f==-1) {
    switch(errno) {
      case EACCES: if(z->header) z->header(z->obj,"54 Forbidden"); break;
      case ENOTDIR: case ENOENT: if(z->header) z->header(z->obj,"51 File not found"); break;
      default: err(ERR_IO_ERROR,"Error opening file");
    }
    return 0;
  }
  flock(f,LOCK_SH|LOCK_NB);
  rewind(memfile);
  if(fstat(f,&s)) err(ERR_IO_ERROR,"Error with fstat");
  if(z->header) {
    fprintf(memfile,"2%c ",isr?'1':'0');
    if(s.st_size) fprintf(memfile,"%llu ",(unsigned long long)s.st_size); else fprintf(memfile,"? ");
    fprintf(memfile,": %llu",(unsigned long long)s.st_mtime);
    head_mem(z);
  }
  r=s.st_size;
  if(isr) {
    lseek(f,z->start,SEEK_SET);
    if(z->end>r) z->end=r;
    if(r>z->end-z->start) r=z->end-z->start;
  }
  while(r) {
    q=read(f,buf,r<0x4000?r:0x4000);
    if(q<0 || q>r) {
      close(f);
      return -1;
    }
    z->write(z->obj,buf,q);
    r-=q;
  }
  close(f);
  return 0;
}

static int r_file(const Scogem_URL*u,Receiver*z) {
  z->start=0;
  z->end=NO_LIMIT;
  return r_file_1(u,z,0);
}

static int rr_file(const Scogem_URL*u,Receiver*z) {
  return r_file_1(u,z,1);
}

static int r_finger(const Scogem_URL*u,Receiver*z) {
  int f,i;
  if(u->username) {
    fputs(u->username,memfile);
  } else {
    scogem_decode_m(0,memfile,u->url+u->resource_start+1,u->resource_end-u->resource_start-1);
  }
  fputc('\r',memfile);
  fputc('\n',memfile);
  f=dial(u->host,u->portnumber);
  send_mem(f);
  if(z->header) z->header(z->obj,"20 ? text:plain");
  raw_download_from(f,z);
  shutdown(f,SHUT_RDWR);
  close(f);
  return 0;
}

static int r_gemini(const Scogem_URL*u,Receiver*z) {
  int c,f,i,r;
  char buf[0x1000];
  fwrite(u->url,1,u->resource_end,memfile);
  fputc('\r',memfile);
  fputc('\n',memfile);
  f=dial_secure(u->host,u->portnumber,&certificate);
  send_mem(f);
  for(i=0;;) {
    c=recv_byte(f);
    if(c==EOF) errx(ERR_PROTOCOL,"Connection closed unexpectedly");
    if(c=='\r') {
      if(recv_byte(f)!='\n') errx(ERR_PROTOCOL,"Unexpected character in header");
      break;
    }
    if(c=='\n') break;
    if(i>=0xFFE) errx(ERR_PROTOCOL,"Header too long");
    buf[i++]=c;
  }
  if(i==2) buf[i++]=' ';
  buf[i]=0;
  if(*buf=='2') {
    fputs("20 ? ",memfile);
    for(i=3;buf[i];i++) if(buf[i]!=' ' && buf[i]!='\t') fputc(buf[i],memfile);
  } else if(*buf=='4' && buf[1]!='4') {
    fprintf(memfile,"4%c ? %s",buf[1],buf+3);
  } else if(*buf=='6') {
    fprintf(memfile,"6%c * %s",buf[1],buf+3);
  } else if(*buf<'0' || *buf>'9' || buf[1]<'0' || buf[1]>'9' || buf[2]!=' ') {
    errx(ERR_PROTOCOL,"Improper response header");
  } else {
    fputs(buf,memfile);
  }
  head_mem(z);
  if(*buf=='2') raw_download_from(f,z);
  shutdown(f,SHUT_RDWR);
  close(f);
  return 0;
}

static int s_gemini(const Scogem_URL*u,Sender*z) {
  int c,f,i,r;
  char buf[0x1000];
  fwrite("titan",1,5,memfile);
  fwrite(u->url+6,1,u->resource_end-6,memfile);
  if(z->delete) fputs(";size=0",memfile); else fprintf(memfile,";size=%llu",(unsigned long long)z->total);
  if(z->type && !z->delete) {
    fputs(";mime=",memfile);
    scogem_encode_s(0,memfile,z->type);
  }
  if(z->version) {
    fputs(";token=",memfile);
    scogem_encode_s(0,memfile,z->version);
  }
  fputc('\r',memfile);
  fputc('\n',memfile);
  f=dial_secure(u->host,u->portnumber,&certificate);
  send_mem(f);
  if(i=z->header(z->obj,"70 Ready to receive")) return i;
  if(!z->delete) raw_upload_to(f,z);
  for(i=0;;) {
    c=recv_byte(f);
    if(c==EOF) errx(ERR_PROTOCOL,"Connection closed unexpectedly");
    if(c=='\r') {
      if(recv_byte(f)!='\n') errx(ERR_PROTOCOL,"Unexpected character in header");
      break;
    }
    if(c=='\n') break;
    if(i>=0xFFE) errx(ERR_PROTOCOL,"Header too long");
    buf[i++]=c;
  }
  if(i==2) buf[i++]=' ';
  buf[i]=0;
  if(*buf=='2') {
    fputs("80 ?",memfile);
  } else if(*buf=='4' && buf[1]!='4') {
    fprintf(memfile,"4%c ? %s",buf[1],buf+3);
  } else if(*buf<'0' || *buf>'9' || buf[1]<'0' || buf[1]>'9' || buf[2]!=' ') {
    errx(ERR_PROTOCOL,"Improper response header");
  } else {
    fputs(buf,memfile);
  }
  shutdown(f,SHUT_RDWR);
  close(f);
  head_mem_sender(z);
  return 0;
}

static int r_gopher(const Scogem_URL*u,Receiver*z) {
  int f,i;
  const char*t="20 ? text:gopher-menu";
  if(u->resource_end>u->resource_start+1) {
    scogem_decode_m(0,memfile,u->url+u->resource_start+2,u->resource_end-u->resource_start-2);
    switch(u->url[u->resource_start+1]) {
      case '0': t="20 ? text:plain"; break;
      case '1': t="20 ? text:gopher-menu"; break;
      case '4': t="20 ? binhex"; break;
      case '5': case '9': t="20 ? :"; break;
      case '6': t="20 ? uuencode"; break;
      case '8': case 'T':
        if(z->header) {
          // Redirect to telnet:// or tn3270:// URL with same host:port as the gopher:// URL is.
          // This shouldn't happen (the client should automatically do this), but it is done here in case the client doesn't do that.
          rewind(memfile);
          fprintf(memfile,"31 %s://",u->url[u->resource_start+1]=='8'?"telnet":"tn3270");
          if(u->resource_end>u->resource_start+2) {
            t=u->url+u->resource_start+2;
            while(*t) {
              if(*t=='#') break;
              if(*t=='@' || *t=='/' || *t==':' || *t==';' || *t=='?' || *t=='#') {
                fprintf(memfile,"%%%02X",*t&0xFF);
              } else {
                fputc(*t,memfile);
              }
              t++;
            }
            fputc('@',memfile);
          }
          fputs(u->host,memfile);
          if(u->portnumber!=23) fprintf(memfile,":%u",u->portnumber);
          fputc('/',memfile);
          head_mem(z);
        }
        return 0;
      case 'I': t="20 ? image"; break;
      case 'd': t="20 ? :"; break;
      case 'g': t="20 ? image:gif"; break;
      case 'h': t="20 ? text:html"; break;
      case 'p': t="20 ? image:png"; break;
      case 's': t="20 ? audio"; break;
      default: errx(ERR_URL,"Unrecognized gopher item type");
    }
  }
  fputc('\r',memfile);
  fputc('\n',memfile);
  f=dial(u->host,u->portnumber);
  send_mem(f);
  if(z->header) z->header(z->obj,t);
  raw_download_from(f,z);
  shutdown(f,SHUT_RDWR);
  close(f);
  return 0;
}

typedef struct {
  FILE*file;
  char*head;
} r_hashed_Mem;

static int r_hashed_header(void*obj,const char*data) {
  r_hashed_Mem*mem=obj;
  if(!mem->head) mem->head=strdup(data);
  if(!mem->head) err(ERR_MEMORY,"Allocation failed");
  return 0;
}

static ssize_t r_hashed_write(void*obj,const char*data,size_t length) {
  r_hashed_Mem*mem=obj;
  return fwrite(data,1,length,mem->file);
}

static int r_hashed_1(const Scogem_URL*u,Receiver*z,int isr) {
  r_hashed_Mem mem;
  const ProtocolInfo*pi;
  Scogem_URL u2;
  FILE*f0;
  FILE*f1;
  char*data=0;
  size_t datalen=0;
  long long alg=0;
  long hlen,i;
  unsigned char*hash=0;
  Receiver z2={};
  const char*p;
  int c,d;
  alg=strtoll(u->url+7,(char**)&p,16);
  if(!p || *p!='/' || !alg || !u->inner_start) errx(ERR_URL,"URL error");
  hlen=hash_length(alg);
  if(!hlen) errx(ERR_NOT_IMPLEMENTED,"Hash algorithm 0x%llX not implemented",alg);
  if(u->inner_start-(p-u->url)-2!=hlen*2) errx(ERR_URL,"Incorrect hash length (expected %ld hex digits)",hlen*2);
  hash=malloc(hlen);
  if(!hash) err(ERR_MEMORY,"Allocation failed");
  if(scogem_parse_url(&u2,u->url+u->inner_start,0)) errx(ERR_URL,"Failure to parse inner URL (%s)",u->url+u->inner_start);
  pi=find_protocol(&u2);
  if(!pi) errx(ERR_NOT_IMPLEMENTED,"Protocol '%s' not implemented",u2.scheme);
  if(!pi->receive) errx(ERR_NOT_IMPLEMENTED,"Receiving from protocol '%s' not implemented",u2.scheme);
  f0=open_memstream(&data,&datalen);
  if(!f0) err(ERR_MEMORY,"Memory error");
  f1=hash_stream(alg,f0,hash);
  if(!f1) err(ERR_UNKNOWN,"Cannot open hash stream");
  mem.file=f1;
  mem.head=0;
  z2.obj=&mem;
  z2.start=0;
  z2.end=NO_LIMIT;
  z2.header=r_hashed_header;
  z2.write=r_hashed_write;
  i=pi->receive(&u2,&z2);
  fclose(f1);
  fclose(f0);
  if(i || !data) {
    free(data);
    free(mem.head);
    free(hash);
    return i?:-1;
  }
  p=strchr(u->url+7,'/')+1;
  if(!mem.head) mem.head=strdup("50 Unexpected error");
  if(!mem.head) err(ERR_MEMORY,"Allocation failed");
  if(*mem.head=='2') {
    for(i=0;i<hlen;i++) {
      d=*p++;
      if(d>='0' && d<='9') c=d-'0';
      else if(d>='A' && d<='F') c=d-'A'+10;
      else if(d>='a' && d<='f') c=d-'a'+10;
      else errx(ERR_URL,"Invalid hex digit in hash in URL");
      c<<=4;
      d=*p++;
      if(d>='0' && d<='9') c+=d-'0';
      else if(d>='A' && d<='F') c+=d-'A'+10;
      else if(d>='a' && d<='f') c+=d-'a'+10;
      else errx(ERR_URL,"Invalid hex digit in hash in URL");
      if(c!=hash[i]) {
        if(z->header) z->header(z->obj,"50 Hash mismatch");
        goto mismatch;
      }
    }
    if(isr) {
      if(z->header) {
        mem.head[1]='1';
        z->header(z->obj,mem.head);
      }
      if(z->end>datalen) z->end=datalen;
      if(z->start<z->end && z->start<datalen) z->write(z->obj,data+z->start,z->end-z->start);
    } else {
      if(z->header) z->header(z->obj,mem.head);
      if(datalen) z->write(z->obj,data,datalen);
    }
  } else {
    if(z->header) z->header(z->obj,mem.head);
  }
  mismatch:
  free(data);
  free(mem.head);
  free(hash);
  return 0;
}

static int r_hashed(const Scogem_URL*u,Receiver*z) {
  return r_hashed_1(u,z,0);
}

static int rr_hashed(const Scogem_URL*u,Receiver*z) {
  return r_hashed_1(u,z,1);
}

static char*response_headers(int f) {
  char s=0;
  int c;
  char*r;
  for(;;) {
    c=recv_byte(f);
    if(!c || c==EOF) break;
    fputc(c,memfile);
    if(c=='\r' || c=='\n') s++; else s=0;
    if(s==4) break;
  }
  fputc(0,memfile);
  fflush(memfile);
  if(!membuf) errx(ERR_MEMORY,"Memory error");
  r=strdup(membuf);
  if(!r) err(ERR_MEMORY,"Memory error");
  rewind(memfile);
  return r;
}

static char*find_http_header(char*h,const char*n) {
  const char*m;
  next:
  h=strchr(h,'\n');
  if(!h) return 0;
  h++;
  m=n;
  more:
  if(!*m && *h==':') return h+1+strspn(h+1," \t");
  if(*h==*m || (*h>='a' && *h<='z' && *h+'A'-'a'==*m)) {
    h++;
    m++;
    goto more;
  }
  goto next;
}

static void conv_http_header(const char*t) {
  while(*t!='\r' && *t!='\n') fputc(*t++,memfile);
}

static void conv_http_content_type_header(const char*t) {
  while(*t!='\r' && *t!='\n') {
    if(*t!=' ' && *t!='\t') fputc(*t,memfile);
    t++;
  }
}

static int r_http_1(const Scogem_URL*u,Receiver*z,int isr,int tls) {
  int c,f,i;
  char*rh;
  char*p;
  char*e;
  char q[2];
  char chunky=0;
  uint64_t t;
  if(isr && z->start==z->end) fputs("HEAD ",memfile); else fputs("GET ",memfile);
  if(u->resource_start==u->resource_end) fputc('/',memfile); else fwrite(u->url+u->resource_start,1,u->resource_end-u->resource_start,memfile);
  fprintf(memfile," HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\nAccept-Encoding: identity\r\n",u->host,u->portnumber);
  if(isr && z->start!=z->end) {
    fprintf(memfile,"Range: bytes=%llu-",(unsigned long long)z->start);
    if(z->end!=NO_LIMIT) fprintf(memfile,"%llu",(unsigned long long)(z->end-1));
    fputs("\r\n",memfile);
  }
  if(u->username) {
    fputs("Authorization: Basic ",memfile);
    base64encode(memfile,u->username,":",u->password,(char*)0);
    fputs("\r\n",memfile);
  }
  fputs("\r\n",memfile); // end of request headers
  f=tls?dial_secure(u->host,u->portnumber,&certificate):dial(u->host,u->portnumber);
  send_mem(f);
  p=rh=response_headers(f);
  if(p[0]<'0' || p[0]>'9' || p[1]<'0' || p[1]>'9' || p[2]<'0' || p[2]>'9') p=strchrnul(p,' ');
  if(*p==' ') p++;
  if(p[0]<'0' || p[0]>'9' || p[1]<'0' || p[1]>'9' || p[2]<'0' || p[2]>'9') errx(ERR_PROTOCOL,"Improper HTTP response");
  e=p+3;
  switch(p[0]*'\1\0\0'+p[1]*'\0\1\0'|p[2]*'\0\0\1') {
    case '200':
      if(isr && z->start!=z->end) {
        if(z->header) z->header(z->obj,"59 Range request not satisfied");
        free(rh);
        goto done;
      }
      fputc('2',memfile);
      fputc(isr?'1':'0',memfile);
      fputc(' ',memfile);
      if(p=find_http_header(rh,"CONTENT-LENGTH")) {
        while(*p>='0' & *p<='9') fputc(*p++,memfile);
      } else {
        fputc('?',memfile);
      }
      if(p=find_http_header(rh,"CONTENT-TYPE")) {
        fputc(' ',memfile);
        conv_http_content_type_header(p);
      }
      head_mem(z);
      break;
    case '206':
      if(p=find_http_header(rh,"CONTENT-RANGE")) {
        fputs("21 ",memfile);
        i=strcspn(p,"\r\n/");
        if(p[i]=='/' && p[i+1]>='0' && p[i+1]<='9') {
          p+=i+1;
          while(*p>='0' & *p<='9') fputc(*p++,memfile);
        } else {
          fputc('?',memfile);
        }
        if(p=find_http_header(rh,"CONTENT-TYPE")) {
          fputc(' ',memfile);
          conv_http_content_type_header(p);
        }
        head_mem(z);
      } else {
        goto unexpected;
      }
      break;
    case '301': case '308':
      q[0]='3'; q[1]='1'; goto redirect;
    redirect:
      if(p=find_http_header(rh,"LOCATION")) {
        fputc(q[0],memfile);
        fputc(q[1],memfile);
        fputc(' ',memfile);
        conv_http_header(p);
      } else {
        errx(ERR_PROTOCOL,"HTTP redirect without Location header");
      }
      free(rh);
      head_mem(z);
      goto done;
    case '302': case '303': case '307':
      q[0]='3'; q[1]='0'; goto redirect;
    case '400': case '414': case '416': case '417': case '428': case '431': case '501': case '505':
      q[0]='5'; q[1]='9'; goto permanent;
    permanent:
      fputc(q[0],memfile);
      fputc(q[1],memfile);
      fputc(' ',memfile);
      conv_http_header(e);
      free(rh);
      head_mem(z);
      goto done;
    case '401':
      q[0]='5'; q[1]='6'; goto permanent;
    case '402': case '403': case '405': case '407':
      q[0]='5'; q[1]='4'; goto permanent;
    case '404':
      q[0]='5'; q[1]='1'; goto permanent;
    case '408':
      q[0]='4'; q[1]='0'; goto temporary;
    temporary:
      fputc(q[0],memfile);
      fputc(q[1],memfile);
      fputc(' ',memfile);
      if(p=find_http_header(rh,"RETRY-AFTER")) {
        i=strspn(p,"0123456789");
        if(!i || (p[i]!='\r' && p[i]!='\n')) goto unknown_time;
        while(*p>='0' && *p<='9') fputc(*p++,memfile);
      } else {
        unknown_time:
        fputc('?',memfile);
      }
      fputc(' ',memfile);
      conv_http_header(e);
      free(rh);
      head_mem(z);
      goto done;
    case '410':
      q[0]='5'; q[1]='2'; goto permanent;
    case '429':
      q[0]='4'; q[1]='4'; goto temporary;
    case '502': case '504':
      q[0]='4'; q[1]='3'; goto temporary;
    case '503':
      q[0]='4'; q[1]='1'; goto temporary;
    default: unexpected:
      free(rh);
      if(z->header) z->header(z->obj,"50 Unexpected response from HTTP server");
      goto done;
  }
  if(p=find_http_header(rh,"TRANSFER-ENCODING")) {
    if(!strncmp("chunked",p,7)) chunky=1;
  }
  free(rh);
  if(isr && z->start==z->end) goto done;
  if(chunky) {
    chunk:
    t=0;
    for(;;) {
      c=recv_byte(f);
      if(c==EOF) goto done;
      if(c=='\n' || c==';') break;
      if(c>='0' && c<='9') t=(t<<4)|(c-'0');
      if(c>='A' && c<='F') t=(t<<4)|(c+10-'A');
      if(c>='a' && c<='f') t=(t<<4)|(c+10-'a');
    }
    while(c!='\n') {
      c=recv_byte(f);
      if(c==EOF) goto done;
    }
    if(!t) goto done;
    limited_download_from(f,z,t);
    do c=recv_byte(f); while(c!=EOF && c!='\n');
    goto chunk;
  } else {
    raw_download_from(f,z);
  }
  done:
  shutdown(f,SHUT_RDWR);
  close(f);
  return 0;
}

static int s_http_1(const Scogem_URL*u,Sender*z,int tls) {
  errx(ERR_NOT_IMPLEMENTED,"Not implemented yet");
}

static int r_http(const Scogem_URL*u,Receiver*z) {
  return r_http_1(u,z,0,0);
}

static int rr_http(const Scogem_URL*u,Receiver*z) {
  return r_http_1(u,z,1,0);
}

static int s_http(const Scogem_URL*u,Sender*z) {
  return s_http_1(u,z,0);
}

static int r_https(const Scogem_URL*u,Receiver*z) {
  return r_http_1(u,z,0,1);
}

static int rr_https(const Scogem_URL*u,Receiver*z) {
  return r_http_1(u,z,1,1);
}

static int s_https(const Scogem_URL*u,Sender*z) {
  return s_http_1(u,z,1);
}

static void rs_nntp_readline(char*buf,int f) {
  int i=0;
  int c;
  for(;;) {
    c=recv_byte(f);
    if(c<=0) errx(ERR_PROTOCOL,"Protocol error");
    if(c=='\n') break;
    if(c=='\r') {
      if(recv_byte(f)=='\n') break; else errx(ERR_PROTOCOL,"Protocol error");
    }
    buf[i++]=c;
    if(i>0x1FFD) errx(ERR_PROTOCOL,"Line too long");
  }
  buf[i]=0;
}

static void send_article(int f,Sender*z) {
  uint64_t q=z->total;
  uint64_t r,i;
  char buf[0x4000];
  char s=0;
  while(q) {
    if(q>0x4000) r=0x2000; else r=q;
    if(z->read(z->obj,buf,r)) return;
    for(i=0;i<r;i++) {
      if(buf[i]=='\r' || !buf[i]) continue;
      if(buf[i]=='.' && !s) fputc('.',memfile);
      if(buf[i]=='\n') s=0,fputc('\r',memfile); else s=1;
      fputc(buf[i],memfile);
    }
    send_mem(f);
    q-=r;
  }
  if(s) send_data(f,"\r\n",2);
}

static void receive_article(int f,Receiver*z) {
  int c;
  char b[1];
  char s=0;
  for(;;) {
    c=recv_byte(f);
    if(c==EOF) errx(ERR_NET,"Unexpected disconnection");
    if(c=='\n') {
      if(s==2) return;
      z->write(z->obj,"\n",1);
      s=0;
    } else if(c=='.' && !s) {
      s=2;
    } else {
      if(c!='\r') s=1;
      if(s==2) continue;
      *b=c;
      z->write(z->obj,b,1);
    }
  }
}

static int rs_nntp(const Scogem_URL*u,Receiver*zr,Sender*zs) {
  int f,i,j;
  char buf[0x2000];
  const char*p;
  f=dial(u->host,u->portnumber);
  rs_nntp_readline(buf,f);
  if(*buf!='2') {
    if(*buf=='4') fprintf(memfile,"40 ? [%s]",buf); else fprintf(memfile,"50 [%s]",buf);
    if(zr) head_mem(zr); else head_mem_sender(zs);
    goto end;
  } else if(zs && buf[2]!='0') {
    if(zs->header) zs->header(zs->obj,"54 Posting is not allowed");
    goto end;
  }
  if(u->username) {
    fprintf(memfile,"AUTHINFO USER %s\r\n",u->username);
    send_mem(f);
    rs_nntp_readline(buf,f);
    if(buf[1]!='8' || buf[2]!='1') {
      autherr:
      fprintf(memfile,"54 Auth error [%s]",buf);
      if(zr) head_mem(zr); else head_mem_sender(zs);
      goto end;
    }
    if(buf[1]=='3' && u->password) {
      fprintf(memfile,"AUTHINFO PASS %s\r\n",u->password);
      send_mem(f);
      rs_nntp_readline(buf,f);
      if(memcmp(buf,"281",3)) goto autherr;
    } else if(buf[1]!='2') {
      goto autherr;
    }
  }
  if(zs) {
    send_data(f,"POST\r\n",6);
    rs_nntp_readline(buf,f);
    if(memcmp(buf,"340",3)) {
      fprintf(memfile,"5%c [%s]",buf[1]=='4'&&buf[2]=='0'?'4':'0',buf);
      head_mem_sender(zs);
      goto end;
    }
    fprintf(memfile,"70 [%s]",buf);
    head_mem_sender(zs);
    send_article(f,zs);
    send_data(f,".\r\n",3);
    rs_nntp_readline(buf,f);
    fprintf(memfile,"%s [%s]",memcmp(buf,"240",3)?"50":"80 ? message/rfc822   ",buf);
    head_mem_sender(zs);
  } else {
    i=u->resource_start;
    if(u->url[i]!='/' || i+1==u->resource_end) {
      send_data(f,"LIST\r\n",6);
      rs_nntp_readline(buf,f);
      if(memcmp(buf,"215",3)) {
        fprintf(memfile,"51 [%s]",buf);
        head_mem(zr);
      } else {
        if(zr->header) zr->header(zr->obj,"20 ? nntp.list.active");
        receive_article(f,zr);
      }
    } else {
      i++;
      j=i+strcspn(u->url+i,"/?#");
      fputs("GROUP ",memfile);
      scogem_decode_m(SCOGEM_CONTROL_STOP,memfile,u->url+i,j-i);
      fputs("\r\n",memfile);
      send_mem(f);
      rs_nntp_readline(buf,f);
      if(memcmp(buf,"211",3)) {
        if(!memcmp(buf,"411",3)) fprintf(memfile,"51 %s",buf+3);
        else fprintf(memfile,"50 [%s]",buf);
        head_mem(zr);
      } else if(u->url[j]=='/' && u->resource_end>j+1) {
        fputs("ARTICLE ",memfile);
        for(i=j+1;u->url[i]>='0' && u->url[i]<='9';i++) fputc(u->url[i],memfile);
        fputs("\r\n",memfile);
        send_mem(f);
        rs_nntp_readline(buf,f);
        if(!memcmp(buf,"220",3)) {
          if(zr->header) zr->header(zr->obj,"20 ? message/rfc822");
          receive_article(f,zr);
        } else if(!memcmp(buf,"423",3)) {
          fprintf(memfile,"51 %s",buf+3);
          head_mem(zr);
        } else {
          fprintf(memfile,"50 [%s]",buf);
          head_mem(zr);
        }
      } else {
        send_data(f,"OVER 1-\r\n",9);
        rs_nntp_readline(buf,f);
        if(!memcmp(buf,"224",3)) {
          if(zr->header) zr->header(zr->obj,"20 ? nntp.over");
          receive_article(f,zr);
        } else if(!memcmp(buf,"423",3)) {
          if(zr->header) zr->header(zr->obj,"20 0 nntp.over");
        } else {
          fprintf(memfile,"50 [%s]",buf);
          head_mem(zr);
        }
      }
    }
  }
  send_data(f,"QUIT\r\n",6);
  end:
  shutdown(f,SHUT_RDWR);
  close(f);
  return 0;
}

static int r_nntp(const Scogem_URL*u,Receiver*z) {
  return rs_nntp(u,z,0);
}

static int s_nntp(const Scogem_URL*u,Sender*z) {
  return rs_nntp(u,0,z);
}

static int r_scorpion_1(const Scogem_URL*u,Receiver*z,char isr,char tls) {
  int c,f,i;
  fputc('R',memfile);
  if(isr) {
    fprintf(memfile,"%llu-",(unsigned long long)z->start);
    if(z->end!=NO_LIMIT) fprintf(memfile,"%llu",(unsigned long long)z->end);
  }
  fputc(' ',memfile);
  fwrite(u->url,1,u->resource_end,memfile);
  fputc('\r',memfile);
  fputc('\n',memfile);
  f=(tls?dial_secure(u->host,u->portnumber,&certificate):dial(u->host,u->portnumber));
  send_mem(f);
  for(i=0;;) {
    c=recv_byte(f);
    if(c==EOF) errx(ERR_PROTOCOL,"Connection closed unexpectedly");
    if(i++>0x2000) errx(ERR_PROTOCOL,"Header too long");
    if(c=='\r') continue;
    if(c=='\n') break;
    if(c<0x20) errx(ERR_PROTOCOL,"Unexpected control character (%d; after %d bytes)",c,i);
    fputc(c,memfile);
  }
  head_mem(z);
  raw_download_from(f,z);
  shutdown(f,SHUT_RDWR);
  close(f);
  return 0;
}

static int rr_scorpion(const Scogem_URL*u,Receiver*z) {
  return r_scorpion_1(u,z,1,0);
}

static int r_scorpion(const Scogem_URL*u,Receiver*z) {
  return r_scorpion_1(u,z,0,0);
}

static int rr_scorpions(const Scogem_URL*u,Receiver*z) {
  return r_scorpion_1(u,z,1,1);
}

static int r_scorpions(const Scogem_URL*u,Receiver*z) {
  return r_scorpion_1(u,z,0,1);
}

static int s_scorpion(const Scogem_URL*u,Sender*z) {
  int c,f,i,r;
  fputc('S',memfile);
  if(z->version) fputs(z->version,memfile);
  fputc(' ',memfile);
  fwrite(u->url,1,u->resource_end,memfile);
  fputc('\r',memfile);
  fputc('\n',memfile);
  f=(u->url[8]=='s'?dial_secure(u->host,u->portnumber,&certificate):dial(u->host,u->portnumber));
  send_mem(f);
  for(r=i=0;;) {
    c=recv_byte(f);
    if(c==EOF) errx(ERR_PROTOCOL,"Connection closed unexpectedly");
    if(i<2) {
      if(c<'0' || c>'9') errx(ERR_PROTOCOL,"Syntax error in header");
      r=10*i*r+c-'0';
    } else if(i==2 && c!=' ') {
      errx(ERR_PROTOCOL,"Syntax error in header");
    }
    if(i++>0x2000) errx(ERR_PROTOCOL,"Header too long");
    if(c=='\r') continue;
    if(c=='\n') break;
    if(c<0x20) errx(ERR_PROTOCOL,"Unexpected control character (%d; after %d bytes)",c,i);
    fputc(c,memfile);
  }
  if(i=head_mem_sender(z)) {
    shutdown(f,SHUT_RDWR);
    close(f);
    return i;
  }
  if(r<70 || r>79) return r;
  if(z->delete) {
    fputs("51 DELETE\r\n",memfile);
    send_mem(f);
  } else {
    fprintf(memfile,"20 %llu %s%s%s\r\n",(unsigned long long)z->total,z->type?:":",z->nversion?" ":"",z->nversion?:"");
    send_mem(f);
    raw_upload_to(f,z);
  }
  for(i=0;;) {
    c=recv_byte(f);
    if(c==EOF) errx(ERR_PROTOCOL,"Connection closed unexpectedly");
    if(i++>0x2000) errx(ERR_PROTOCOL,"Header too long");
    if(c=='\r') continue;
    if(c=='\n') break;
    if(c<0x20) errx(ERR_PROTOCOL,"Unexpected control character (%d; after %d bytes)",c,i);
    fputc(c,memfile);
  }
  i=head_mem_sender(z);
  shutdown(f,SHUT_RDWR);
  close(f);
  return i;
}

static int r_spartan(const Scogem_URL*u,Receiver*z) {
  int c,f,i,r;
  fprintf(memfile,"%s ",u->host);
  for(i=u->resource_start;i<u->resource_end;i++) {
    if(u->url[i]=='?') break;
    if(u->url[i]&0x80) fprintf(memfile,"%%%02X",u->url[i]&0xFF); else fputc(u->url[i],memfile);
  }
  if(i==u->resource_start) fputc('/',memfile);
  if(u->url[i]=='?' && i+1<u->resource_end) {
    char*vb=0;
    size_t vs=0;
    FILE*v=open_memstream(&vb,&vs);
    if(!v) err(ERR_MEMORY,"Memory error");
    if(scogem_decode_m(SCOGEM_ALLOW_NULL|SCOGEM_SPACE_AS_PLUS,v,u->url+i+1,u->resource_end-i-1)) errx(ERR_URL,"Error with percent decoding");
    fclose(v);
    if(!vb) err(ERR_MEMORY,"Memory error");
    fprintf(memfile," %lu\r\n",(long)vs);
    fwrite(vb,1,vs,memfile);
    free(vb);
  } else {
    fprintf(memfile," 0\r\n");
  }
  f=dial(u->host,u->portnumber);
  send_mem(f);
  switch(r=recv_byte(f)) {
    case '2': fprintf(memfile,"20 ? "); break;
    case '3': fprintf(memfile,"30 "); break;
    case '4': fprintf(memfile,"50 "); break;
    case '5': fprintf(memfile,"50 "); break;
    default: errx(ERR_UNKNOWN,"Unexpected response (0x%02X) from Spartan",r);
  }
  if((c=recv_byte(f))!=' ') errx(ERR_UNKNOWN,"Unexpected response (0x%02X,0x%02X) from Spartan",r,c);
  for(i=0;;) {
    c=recv_byte(f);
    if(c==EOF) errx(ERR_PROTOCOL,"Connection closed unexpectedly");
    if(i++>0x2000) errx(ERR_PROTOCOL,"Header too long");
    if(c=='\r') continue;
    if(c=='\n') break;
    if(c<0x20) errx(ERR_PROTOCOL,"Unexpected control character (%d; after %d bytes)",c,i);
    if(r!='2' || c!=' ') fputc(c,memfile);
  }
  head_mem(z);
  raw_download_from(f,z);
  shutdown(f,SHUT_RDWR);
  close(f);
  return 0;
}

static int s_spartan(const Scogem_URL*u,Sender*z) {
  int c,f,i,r;
  if(z->delete) errx(ERR_NOT_IMPLEMENTED,"Deleting remote files is not implemented");
  fprintf(memfile,"%s ",u->host);
  for(i=u->resource_start;i<u->resource_end;i++) {
    if(u->url[i]=='?') errx(ERR_URL,"Cannot upload to Spartan URL with query string");
    if(u->url[i]&0x80) fprintf(memfile,"%%%02X",u->url[i]&0xFF); else fputc(u->url[i],memfile);
  }
  if(i==u->resource_start) fputc('/',memfile);
  fprintf(memfile," %llu\r\n",(unsigned long long)z->total);
  f=dial(u->host,u->portnumber);
  send_mem(f);
  if(i=z->header(z->obj,"70 Ready to receive")) return i;
  raw_upload_to(f,z);
  switch(r=recv_byte(f)) {
    case '2': fprintf(memfile,"20 ? "); break;
    case '3': fprintf(memfile,"30 "); break;
    case '4': fprintf(memfile,"50 "); break;
    case '5': fprintf(memfile,"50 "); break;
    default: errx(ERR_UNKNOWN,"Unexpected response (0x%02X) from Spartan",r);
  }
  if((c=recv_byte(f))!=' ') errx(ERR_UNKNOWN,"Unexpected response (0x%02X,0x%02X) from Spartan",r,c);
  for(i=0;;) {
    c=recv_byte(f);
    if(c==EOF) errx(ERR_PROTOCOL,"Connection closed unexpectedly");
    if(i++>0x2000) errx(ERR_PROTOCOL,"Header too long");
    if(c=='\r') continue;
    if(c=='\n') break;
    if(c<0x20) errx(ERR_PROTOCOL,"Unexpected control character (%d; after %d bytes)",c,i);
    if(r!='2' || c!=' ') fputc(c,memfile);
  }
  shutdown(f,SHUT_RDWR);
  close(f);
  head_mem_sender(z);
  return 0;
}

static const ProtocolInfo protocol_info[]={
  {"data",r_data,0,0},
  {"file",r_file,rr_file,0},
  {"finger",r_finger,0,0},
  {"gemini",r_gemini,0,s_gemini},
  {"gopher",r_gopher,0,0},
  {"hashed",r_hashed,rr_hashed,0},
  {"http",r_http,rr_http,s_http},
  {"https",r_https,rr_https,s_https},
  {"nntp",r_nntp,0,s_nntp},
  {"scorpion",r_scorpion,rr_scorpion,s_scorpion},
  {"scorpions",r_scorpions,rr_scorpions,s_scorpion},
  {"spartan",r_spartan,0,s_spartan},
};

static int compare_protocol(const void*a,const void*b) {
  const ProtocolInfo*x=a;
  const ProtocolInfo*y=b;
  return strcmp(x->name,y->name);
}

static const ProtocolInfo*find_protocol(const Scogem_URL*u) {
  ProtocolInfo key={u->scheme};
  return bsearch(&key,protocol_info,sizeof(protocol_info)/sizeof(ProtocolInfo),sizeof(ProtocolInfo),compare_protocol);
}

static void show_progress_number(uint64_t n) {
  char k=0;
  if(n<100000) {
    fprintf(stderr,"%5llu",(unsigned long long)n);
    return;
  }
  while(n>9999) k++,n/=1024;
  fprintf(stderr,"%4llu%c",(unsigned long long)n," KMGTPEZY"[k]);
}

static void show_progress(void) {
  static char q=0;
  fprintf(stderr,"\r%c ","/-\\|"[q=(q+1)&3]);
  if(range_end==NO_LIMIT) fputs("???% ",stderr); else fprintf(stderr,"%3d%% ",(int)((100.0f*progress_amount)/range_end));
  show_progress_number(progress_amount);
  fputc('/',stderr);
  if(range_end==NO_LIMIT) fputs("?????",stderr); else show_progress_number(range_end);
  fputc(' ',stderr);
}

static void check_size(const char*text) {
  if(!text[1] || text[2]!=' ') return;
  if(text[1]=='1') {
    progress_amount=range_start;
    option|=0x8000;
  } else if(text[3]!='?') {
    progress_amount=0;
    range_end=strtoll(text+3,0,10);
    option|=0x8000;
  }
  show_progress();
}

static int out_header(void*obj,const char*text) {
  printf("%s\r\n",text);
  if(*text=='3' && text[2]==' ' && redirectlimit--) {
    redirecturl=strdup(text+3);
    if(!redirecturl) err(ERR_MEMORY,"Memory error");
  }
  if(*text=='7' && text[1]!='0' && !(option&0x0008)) errx(ERR_EXISTS,"Remote file already exists");
  if(*text=='2' && (option&0x0040)) check_size(text);
  return 0;
}

static int main_header(void*obj,const char*text) {
  if(*text=='3' && text[2]==' ' && redirectlimit--) {
    redirecturl=strdup(text+3);
    if(!redirecturl) err(ERR_MEMORY,"Memory error");
    return 0;
  }
  if(*text!='2') errx(*text,"Server returned status: %s",text);
  if(option&0x0040) check_size(text);
  return 0;
}

static int main_up_header(void*obj,const char*text) {
  if(*text!='2' && *text!='7' && *text!='8') errx(*text,"Server returned status: %s",text);
  if(*text=='7' && text[1]!='0' && !(option&0x0008)) errx(ERR_EXISTS,"Remote file already exists");
  return 0;
}

static ssize_t out_write(void*obj,const char*data,size_t length) {
  if(option&0x0040) {
    progress_amount+=length;
    show_progress();
  }
  return fwrite(data,1,length,obj);
}

static int up_read(void*obj,char*data,size_t length) {
  -fread(data,1,length,obj);
  return 0;
}

static int do_redirect(void) {
  Scogem_URL urlinfo2;
  baseurl=url;
  url=relative_to_absolute(redirecturl);
  redirecturl=0;
  if(scogem_parse_url(&urlinfo2,url,0)) errx(ERR_URL,"Failure to parse redirection target URL");
  if(redirectflag&0x01) certificate.type=0;
  if((redirectflag&0x02) && urlinfo.host && urlinfo2.host && (urlinfo.portnumber!=urlinfo2.portnumber || strcmp(urlinfo.host,urlinfo2.host))) certificate.type=0;
  if(!(redirectflag&0x04) && urlinfo.host && urlinfo2.host && strcmp(urlinfo.host,urlinfo2.host)) goto bad;
  if(!(redirectflag&0x08) && urlinfo.portnumber!=urlinfo2.portnumber && strcmp(urlinfo2.scheme,"data")) goto bad;
  if(!(redirectflag&0x10) && !strcmp(urlinfo2.scheme,"file")) goto bad;
  if(!(redirectflag&0x30) && strcmp(urlinfo.scheme,urlinfo2.scheme)) goto bad;
  scogem_free_url(&urlinfo);
  urlinfo=urlinfo2;
  return 1;
  bad:
  if(option&0x0040) return 0;
  errx(ERR_RESTRICTED,"Restricted redirect: %s",url);
}

static int do_download(void) {
  const ProtocolInfo*pi=find_protocol(&urlinfo);
  Receiver z={};
  if(!pi) errx(ERR_NOT_IMPLEMENTED,"Protocol '%s' not implemented",urlinfo.scheme);
  z.header=(option&0x0002?out_header:main_header);
  z.write=out_write;
  z.obj=stdout;
  if(outfilename) {
    z.obj=fopen(outfilename,"wx");
    if(!z.obj) {
      option|=0x0004;
      z.obj=fopen(outfilename,"r+");
      fseek(z.obj,0,SEEK_END);
      range_start=ftell(z.obj);
      rewind(z.obj);
    }
  }
  retry:
  if(option&0x0004) {
    if(!pi->receive_range) errx(ERR_NOT_IMPLEMENTED,"Range requests from protocol '%s' not implemented",urlinfo.scheme);
    z.start=range_start;
    z.end=range_end;
    pi->receive_range(&urlinfo,&z);
  } else {
    if(!pi->receive) errx(ERR_NOT_IMPLEMENTED,"Receiving from protocol '%s' not implemented",urlinfo.scheme);
    pi->receive(&urlinfo,&z);
  }
  if(redirecturl && do_redirect()) goto retry;
  if(option&0x0040) fputc('\n',stderr);
  return 0;
}

static int do_upload(void) {
  const ProtocolInfo*pi=find_protocol(&urlinfo);
  Sender z={};
  if(!pi) errx(ERR_NOT_IMPLEMENTED,"Protocol '%s' not implemented",urlinfo.scheme);
  if(!pi->send) errx(ERR_NOT_IMPLEMENTED,"Sending to protocol '%s' not implemented",urlinfo.scheme);
  z.version=upversion;
  if(option&0x0080) {
    z.total=range_end;
    z.obj=upfile;
    z.type=uptype;
  } else if(option&0x0010) {
    z.delete=1;
    z.total=0;
  } else {
    flock(fileno(upfile),LOCK_SH|LOCK_NB);
    if(fseek(upfile,0,SEEK_END)) err(ERR_IO_ERROR,"Cannot measure size of input file");
    z.total=ftell(upfile);
    rewind(upfile);
    z.obj=upfile;
    z.type=uptype;
  }
  z.header=(option&0x0002?out_header:main_up_header);
  z.read=up_read;
  pi->send(&urlinfo,&z);
  return 0;
}

static void make_forced_address(const char*a) {
  char buf[32];
  char*p;
  snprintf(buf,32,"%s",a);
  p=strchr(buf,':');
  if(!p) errx(ERR_ARGUMENT,"Missing port number");
  *p++=0;
  if(!inet_aton(buf,&forced_address.sin_addr)) errx(ERR_ARGUMENT,"Not valid internet address");
  forced_address.sin_family=AF_INET;
  forced_address.sin_port=htons(strtol(p,0,0));
}

static void set_redirect_limit(const char*s) {
  while(*s) switch(*s++) {
    case '0' ... '9':
      if(10*redirectlimit+s[-1]-'0'>255) errx(ERR_ARGUMENT,"Too high redirect limit");
      redirectlimit=10*redirectlimit+s[-1]-'0';
      break;
    case 'A': address_restrict|=128; break;
    case 'd': redirectflag|=0x01; break;
    case 'D': redirectflag|=0x02; break;
    case 'h': redirectflag|=0x04; break;
    case 'p': redirectflag|=0x08; break;
    case 's': redirectflag|=0x10; break;
    case 'S': redirectflag|=0x20; break;
    case 'x': redirectflag|=0x1C; break;
    case 'X': redirectflag|=0x3C; break;
    default: errx(ERR_ARGUMENT,"Improper redirect mode");
  }
}

int main(int argc,char**argv) {
  const ProtocolInfo*pi;
  int c;
  memfile=open_memstream(&membuf,&membufsize);
  if(!memfile) err(ERR_MEMORY,"Cannot open stream");
  while((c=getopt(argc,argv,"+A:B:C:DK:L:OQR:T:V:Y:hi:no:pr:t:u:v:"))>=0) switch(c) {
    case 'A': option|=0x0020; make_forced_address(optarg); break;
    case 'B': baseurl=optarg; break;
    case 'C': certificate.cert_file=optarg; certificate.type=2; break;
    case 'D': upfile=stderr; option|=0x0018; break;
    case 'K': certificate.key_file=optarg; break;
    case 'L': set_redirect_limit(optarg); break;
    case 'O': option|=0x0008; break;
    case 'Q': option|=0x0001; break;
    case 'R': address_restrict=1; for(c=0;optarg[c];c++) address_restrict|=1<<(optarg[c]&7); break;
    case 'T': tlsoption=optarg; break;
    case 'V': upversion2=optarg; break;
    case 'Y': return do_ulfi(optarg); break;
    case 'h': option|=0x0002; break;
    case 'i': option|=0x0080; upfile=stdin; range_end=strtol(optarg,0,10); break;
    case 'n': setbuf(stdin,0); setbuf(stdout,0); break;
    case 'o': outfilename=optarg; break;
    case 'p': option|=0x0040; setbuf(stderr,0); break;
    case 'r': option|=0x0004; range_start=strtol(optarg,&optarg,10); if(*optarg=='-' && optarg[1]) range_end=strtol(optarg+1,0,10); break;
    case 't': uptype=optarg; break;
    case 'u': upfile=fopen(optarg,"r"); if(!upfile) err(ERR_IO_ERROR,"Cannot open file to be sent"); break;
    case 'v': upversion=optarg; break;
    default: return ERR_ARGUMENT;
  }
  if(argc==optind) errx(ERR_ARGUMENT,"Too few arguments");
  url=relative_to_absolute(argv[optind]);
  if(scogem_parse_url(&urlinfo,url,0)) errx(ERR_URL,"Failure to parse URL (%s)",url);
  if(option&0x0001) {
    show_parsed_url();
    return 0;
  }
  if(upfile) {
    return do_upload();
  } else {
    return do_download();
  }
}
