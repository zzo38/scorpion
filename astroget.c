#if 0
gcc -s -O2 -o ~/bin/astroget astroget.c scogem.o simpletls.o -lssl
exit
#endif

// Can you tell me how to work TLS properly with this? I could not get it to work.

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

#include "scogem.h"
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "simpletls.h"

static FILE*memfile;
static char*membuf;
static size_t membufsize;

static char*baseurl;
static char*url;
static Scogem_URL urlinfo;
static uint16_t option;
static FILE*upfile;
static const char*uptype;
static uint64_t range_start=0;
static uint64_t range_end=NO_LIMIT;

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
  int(*header)(void*obj,const char*data);
  int(*read)(void*obj,char*data,size_t length);
} Sender;

typedef struct {
  const char*name;
  int(*receive)(const Scogem_URL*u,Receiver*z);
  int(*receive_range)(const Scogem_URL*u,Receiver*z);
  int(*send)(const Scogem_URL*u,Sender*z);
} ProtocolInfo;

static void status_ok(Receiver*z,char k,uint64_t total,const char*mime) {
  char buf[0x1000];
  if(z->header) {
    snprintf(buf,0x1000,"2%c %llu %s",k,(unsigned long long)total,mime);
    z->header(z->obj,buf);
  }
}

static int dial(const char*host,uint16_t port) {
  char b[8];
  struct addrinfo h={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM,.ai_flags=AI_ADDRCONFIG};
  struct addrinfo*ai=0;
  int i,f;
  snprintf(b,8,"%u",port);
  if(i=getaddrinfo(host,b,&h,&ai)) errx(ERR_NET,"%s",gai_strerror(i));
  f=socket(AF_INET,SOCK_STREAM,0);
  if(f==-1) err(ERR_MEMORY,"Cannot open socket");
  i=connect(f,ai->ai_addr,sizeof(struct sockaddr_in));
  if(i<0) err(ERR_NET,"Cannot connect to '%s:%u'",host,port);
  freeaddrinfo(ai);
  return f;
}

static int dial_secure(const char*host,int16_t port,const Certificate*cert) {
  char b[8];
  struct addrinfo h={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM,.ai_flags=AI_ADDRCONFIG};
  struct addrinfo*ai=0;
  int i,f;
  snprintf(b,8,"%u",port);
  if(i=getaddrinfo(host,b,&h,&ai)) errx(ERR_NET,"%s",gai_strerror(i));
  f=secure_socket(ai->ai_addr,host,0,cert);
  if(f==-1) errx(ERR_MEMORY,"Cannot open secure socket");
  freeaddrinfo(ai);
  return f;
}

static int raw_download_from(int f,Receiver*z) {
  ssize_t s;
  char buf[0x4000];
  while((s=recv(f,buf,0x4000,0))>0) z->write(z->obj,buf,s);
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

static int r_gemini(const Scogem_URL*u,Receiver*z) {
  int c,f,i,r;
  char buf[0x1000];
  fwrite(u->url,1,u->resource_end,memfile);
  fputc('\r',memfile);
  fputc('\n',memfile);
  f=dial_secure(u->host,u->portnumber,0);
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
  f=dial_secure(u->host,u->portnumber,0);
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
  f=(tls?dial_secure(u->host,u->portnumber,0):dial(u->host,u->portnumber));
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
  fputc('\r',memfile);
  fputc('\n',memfile);
  f=(u->url[8]=='s'?dial_secure(u->host,u->portnumber,0):dial(u->host,u->portnumber));
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
    fprintf(memfile,"20 %llu %s%s%s\r\n",(unsigned long long)z->total,z->type?:":",z->version?" ":"",z->version?:"");
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
  {"gemini",r_gemini,0,s_gemini},
  {"gopher",r_gopher,0,0},
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

static int out_header(void*obj,const char*text) {
  printf("%s\r\n",text);
  if(*text=='7' && text[1]!='0' && !(option&0x0008)) errx(ERR_EXISTS,"Remote file already exists");
  return 0;
}

static int main_header(void*obj,const char*text) {
  if(*text!='2') errx(*text,"Server returned status: %s",text);
  return 0;
}

static int main_up_header(void*obj,const char*text) {
  if(*text!='2' && *text!='7' && *text!='8') errx(*text,"Server returned status: %s",text);
  if(*text=='7' && text[1]!='0' && !(option&0x0008)) errx(ERR_EXISTS,"Remote file already exists");
  return 0;
}

static ssize_t out_write(void*obj,const char*data,size_t length) {
  return fwrite(data,1,length,stdout);
}

static int up_read(void*obj,char*data,size_t length) {
  -fread(data,1,length,obj);
  return 0;
}

static int do_download(void) {
  const ProtocolInfo*pi=find_protocol(&urlinfo);
  Receiver z={};
  if(!pi) errx(ERR_NOT_IMPLEMENTED,"Protocol '%s' not implemented",urlinfo.scheme);
  z.header=(option&0x0002?out_header:main_header);
  z.write=out_write;
  if(option&0x0004) {
    z.start=range_start;
    z.end=range_end;
    if(!pi->receive_range) errx(ERR_NOT_IMPLEMENTED,"Range requests from protocol '%s' not implemented",urlinfo.scheme);
    pi->receive_range(&urlinfo,&z);
  } else {
    if(!pi->receive) errx(ERR_NOT_IMPLEMENTED,"Receiving from protocol '%s' not implemented",urlinfo.scheme);
    pi->receive(&urlinfo,&z);
  }
  return 0;
}

static int do_upload(void) {
  const ProtocolInfo*pi=find_protocol(&urlinfo);
  Sender z={};
  if(!pi) errx(ERR_NOT_IMPLEMENTED,"Protocol '%s' not implemented",urlinfo.scheme);
  if(!pi->send) errx(ERR_NOT_IMPLEMENTED,"Sending to protocol '%s' not implemented",urlinfo.scheme);
  if(option&0x0010) {
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

int main(int argc,char**argv) {
  const ProtocolInfo*pi;
  int c;
  memfile=open_memstream(&membuf,&membufsize);
  if(!memfile) err(ERR_MEMORY,"Cannot open stream");
  while((c=getopt(argc,argv,"+B:DOQY:hr:t:u:"))>=0) switch(c) {
    case 'B': baseurl=optarg; break;
    case 'D': upfile=stderr; option|=0x0018; break;
    case 'O': option|=0x0008; break;
    case 'Q': option|=0x0001; break;
    case 'Y': return do_ulfi(optarg); break;
    case 'h': option|=0x0002; break;
    case 'r': option|=0x0004; range_start=strtol(optarg,&optarg,10); if(*optarg=='-' && optarg[1]) range_end=strtol(optarg+1,0,10); break;
    case 't': uptype=optarg; break;
    case 'u': upfile=fopen(optarg,"r"); if(!upfile) err(ERR_IO_ERROR,"Cannot open file to be sent"); break;
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
