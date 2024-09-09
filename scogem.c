#if 0
gcc -s -O2 -c scogem.c
exit
#endif

#include "scogem.h"

static char urlbuf[0x2000];
static FILE*urlfile;
static uint32_t urlcolon;

static int ulfi_comp(const void*a,const void*b) {
  const Scogem_UlfiList*x=a;
  const Scogem_UlfiList*y=b;
  return strcmp(x->name,y->name);
}

static const Scogem_UlfiList*ulfi_set(const Scogem_UlfiList*list,int nlist,char*buf,uint8_t*bits,void*extra) {
  Scogem_UlfiList key={buf,0,0};
  char*q;
  const Scogem_UlfiList*item=bsearch(&key,list,nlist,sizeof(Scogem_UlfiList),ulfi_comp);
  if(!item && (q=strchr(buf,'/')) && q[1]) {
    q[1]='*';
    q[2]=0;
    item=bsearch(&key,list,nlist,sizeof(Scogem_UlfiList),ulfi_comp);
  }
  if(item) bits[item->bit>>3]|=1<<(item->bit&7);
  return item;
}

void scogem_ulfi_parse(const Scogem_UlfiList*list,int nlist,const char*text,uint8_t*bits,void*extra) {
  const char*plus=0;
  char c;
  char buf[256];
  int u=0;
  const Scogem_UlfiList*st;
  for(;;) {
    switch(c=*text++) {
      case ' ':
        continue;
      case 0: case '>': case '\r': case '\n':
        buf[u]=0;
        if(u) ulfi_set(list,nlist,buf,bits,extra);
        return;
      case '+':
        buf[u]=0;
        if(u) ulfi_set(list,nlist,buf,bits,extra);
        buf[u++]='.';
        break;
      case ':':
        buf[u]=0;
        if(u) ulfi_set(list,nlist,buf,bits,extra);
        u=0;
        break;
      case '[': case '<':
        if(c=='<') c='>'; else c=']';
        if(u) {
          buf[u]=0;
          u=0;
          if((st=ulfi_set(list,nlist,buf,bits,extra)) && st->parameter) {
            strncpy(buf,text,255);
            buf[255]=0;
            *strchrnul(buf,c)=0;
            st->parameter(extra,buf,st);
          }
        }
        text=strchrnul(text,c);
        if(*text) text++;
        break;
      case '/':
        goto mime;
      default:
        if(u<255) buf[u++]=c;
    }
  }
  mime:
  if(u>=255) return;
  buf[u++]='/';
  for(;;) {
    switch(c=*text++) {
      case ' ':
        continue;
      case 0: case '\r': case '\n':
        buf[u]=0;
        if(u) ulfi_set(list,nlist,buf,bits,extra);
        goto final;
      case ';':
        buf[u]=0;
        if((st=ulfi_set(list,nlist,buf,bits,extra)) && st->parameter) {
          strncpy(buf,text,255);
          buf[255]=0;
          st->parameter(extra,text,st);
        }
        goto final;
      case '+':
        if(!plus) plus=text;
        break;
      default:
        if(u<255) buf[u++]=c;
    }
  }
  final:
  if(plus) {
    text--;
    *buf='+';
    u=1;
    while(u<255 && *plus && plus<text) buf[u++]=*plus++;
    buf[u]=0;
    if((st=ulfi_set(list,nlist,buf,bits,extra)) && *text==';' && st->parameter) {
      strncpy(buf,text,255);
      buf[255]=0;
      st->parameter(extra,text+1,st);
    }
  }
}

typedef struct {
  uint8_t id;
  const char*name;
  uint16_t port;
  uint16_t flag;
} Scheme;

#define SCHF_NOHOST 0x0001
#define SCHF_INTERNET 0x0002
#define SCHF_LOCAL 0x0004
#define SCHF_PASSWORD 0x0008
#define SCHF_TLS 0x0010
#define SCHF_COMPOUND 0x0020
#define SCHF_SEND 0x0040
#define SCHF_ABNORMAL 0x0080
#define SCHF_NORELATIVE 0x0100
#define SCHF_INACCESSIBLE 0x8000

enum {
  SCH_1FILE,
  SCH_ABOUT,
  SCH_DATA,
  SCH_FILE,
  SCH_FINGER,
  SCH_GEMINI,
  SCH_GOPHER,
  SCH_HASHED,
  SCH_HTTP,
  SCH_HTTPS,
  SCH_JAR,
  SCH_MAILTO,
  SCH_NEWS,
  SCH_NEX,
  SCH_NNTP,
  SCH_SCORPION,
  SCH_SCORPIONS,
  SCH_SPARTAN,
  SCH_TELNET,
  SCH_TITAN,
  SCH_VIEW_SOURCE,
  SCH_WAIS,
};

static const Scheme schemes[]={
  {SCH_1FILE,"\x01""file",0,SCHF_INACCESSIBLE|SCHF_LOCAL},
  {SCH_ABOUT,"about",0,SCHF_NOHOST|SCHF_INACCESSIBLE|SCHF_LOCAL},
  {SCH_DATA,"data",0,SCHF_NOHOST|SCHF_ABNORMAL|SCHF_NORELATIVE},
  {SCH_FILE,"file",0,SCHF_LOCAL|SCHF_SEND},
  {SCH_FINGER,"finger",79,SCHF_INTERNET|SCHF_ABNORMAL|SCHF_PASSWORD},
  {SCH_GEMINI,"gemini",1965,SCHF_INTERNET|SCHF_TLS|SCHF_SEND},
  {SCH_GOPHER,"gopher",70,SCHF_INTERNET|SCHF_ABNORMAL},
  {SCH_HASHED,"hashed",0,SCHF_COMPOUND|SCHF_NOHOST|SCHF_ABNORMAL},
  {SCH_HTTP,"http",80,SCHF_INTERNET|SCHF_PASSWORD|SCHF_SEND},
  {SCH_HTTPS,"https",443,SCHF_INTERNET|SCHF_TLS|SCHF_PASSWORD|SCHF_SEND},
  {SCH_JAR,"jar",0,SCHF_COMPOUND|SCHF_NOHOST},
  {SCH_MAILTO,"mailto",0,SCHF_NOHOST|SCHF_ABNORMAL|SCHF_INACCESSIBLE|SCHF_SEND|SCHF_NORELATIVE},
  {SCH_NEWS,"news",119,SCHF_INTERNET|SCHF_NOHOST|SCHF_ABNORMAL|SCHF_SEND},
  {SCH_NEX,"nex",1900,SCHF_INTERNET},
  {SCH_NNTP,"nntp",119,SCHF_INTERNET|SCHF_PASSWORD|SCHF_SEND},
  {SCH_SCORPION,"scorpion",1517,SCHF_INTERNET|SCHF_PASSWORD|SCHF_SEND},
  {SCH_SCORPIONS,"scorpions",1517,SCHF_INTERNET|SCHF_PASSWORD|SCHF_TLS|SCHF_SEND},
  {SCH_SPARTAN,"spartan",300,SCHF_INTERNET|SCHF_SEND},
  {SCH_TELNET,"telnet",23,SCHF_INTERNET|SCHF_PASSWORD},
  {SCH_TITAN,"titan",1965,SCHF_INTERNET|SCHF_TLS|SCHF_SEND},
  {SCH_VIEW_SOURCE,"view-source",0,SCHF_COMPOUND|SCHF_NOHOST},
  {SCH_WAIS,"wais",210,SCHF_INTERNET},
};

static int scheme_comp(const void*a,const void*b) {
  const Scheme*x=a;
  const Scheme*y=b;
  return strcmp(x->name,y->name);
}

static char*urlpart(const char*s,char e,char p) {
  int n=0;
  int c;
  rewind(urlfile);
  urlcolon=0;
  while(*s && *s!=e) {
    if(p && *s=='%') {
      s++;
      if(*s>='0' && *s<='9') c=*s++-'0';
      else if(*s>='A' && *s<='F') c=*s++-'A'+10;
      else if(*s>='a' && *s<='f') c=*s++-'a'+10;
      else return 0;
      c<<=4;
      if(*s>='0' && *s<='9') c+=*s++-'0';
      else if(*s>='A' && *s<='F') c+=*s++-'A'+10;
      else if(*s>='a' && *s<='f') c+=*s++-'a'+10;
      else return 0;
      if(!c) return 0;
      fputc(c,urlfile);
    } else {
      if(*s==':' && (!p || !urlcolon)) urlcolon=n;
      fputc(*s++,urlfile);
    }
    if(n++>0x1FFE) return 0;
  }
  fputc(0,urlfile);
  fflush(urlfile);
  return strdup(urlbuf);
}

int scogem_parse_url(Scogem_URL*out,const char*url,uint32_t flag) {
  // [scheme:[//[username[:password]@]host[:port]]path[?query][#fragment]]
  Scheme key;
  Scheme*sch;
  const char*p;
  const char*q;
  const char*r;
  int n,c;
  memset(out,0,sizeof(Scogem_URL));
  if(!urlfile) {
    urlfile=fmemopen(urlbuf,0x1FFF,"wb");
    if(!urlfile) return -2;
  }
  out->url=url;
  for(n=0;;n++) {
    c=url[n];
    if(c==':') break;
    if(n==15) return -1;
    if(c>='A' && c<='Z') c+='a'-'A';
    if((c>='0' && c<='9') || (c>='a' && c<='z') || c=='.' || c=='-' || c=='+') out->scheme[n]=c; else return -1;
  }
  p=url+n+1; // skip ':'
  key.name=out->scheme;
  sch=bsearch(&key,schemes,sizeof(schemes)/sizeof(Scheme),sizeof(Scheme),scheme_comp);
  if(!sch) return -1;
  if(sch->flag&SCHF_NOHOST) {
    if(*p=='/' && p[1]=='/') return -1;
  } else {
    if(*p!='/' || p[1]!='/') return -1;
    p+=2;
    n=0;
    q=p;
    r=0;
    while(c=*p) {
      if(c=='@') {
        if(out->userinfo_start || !(sch->flag&SCHF_PASSWORD)) return -1;
        out->userinfo_start=q-url;
        out->userinfo_end=p-url;
        if(r) {
          out->password_start=r-url;
          out->password_end=out->userinfo_end;
        }
        q=p+1;
        r=0;
      } else if(c==':' && !r) {
        r=p;
      } else if(c=='/' || c=='#' || c=='?') {
        break;
      }
      p++;
      if(n++>0x1FF0) return -1;
    }
    out->host=urlpart(q,'/',0);
    if(!out->host) return -1;
    if(urlcolon) {
      out->host[urlcolon]=0;
      strncpy(out->port,out->host+urlcolon+1,7);
      out->portnumber=strtol(out->port,0,10);
    } else {
      out->portnumber=sch->port;
    }
    if(out->userinfo_start) {
      out->username=urlpart(url+out->userinfo_start,'@',1);
      if(!out->username) return -1;
      if(urlcolon) {
        out->username[urlcolon]=0;
        out->password=out->username+urlcolon+1;
      }
    }
  }
  out->resource_start=p-url;
  if(q=strchr(p,'#')) {
    out->resource_end=q-url;
    out->fragment=urlpart(q+1,0,1);
    if(!out->fragment) return -1;
  } else {
    out->resource_end=strlen(url);
  }
  switch(out->code=sch->id) {
    case SCH_FINGER:
      if(out->password) return -1;
      if(out->username && url[out->resource_start] && url[out->resource_start+1]) return -1;
      break;
    case SCH_HASHED:
      if(p=strchr(p,',')) {
        out->inner_start=p+1-url;
        out->inner_end=strlen(url);
      }
      break;
    case SCH_JAR:
      out->inner_start=p-url;
      if(p=strchr(p,'!')) {
        if(p[1]!='/') return -1;
        out->inner_end=p-1-url;
        out->resource_start=p+1-url;
      } else {
        return -1;
      }
      break;
    case SCH_VIEW_SOURCE:
      out->inner_start=p-url;
      out->inner_end=strlen(url);
      break;
  }
  return 0;
}

void scogem_free_url(Scogem_URL*obj) {
  if(obj) {
    free(obj->host);
    free(obj->username);
    free(obj->fragment);
    obj->host=obj->username=obj->password=obj->fragment=0;
    obj->url=0;
    obj->port[0]=obj->scheme[0]=0;
  }
}

static inline const char*send_scheme(const char*p,FILE*f) {
  while(*p && *p!=':') if(*p>='A' && *p<='Z') fputc((*p++)+'a'-'A',f); else fputc(*p++,f);
  if(*p) fputc(*p++,f);
  return p;
}

int scogem_relative(FILE*out,const char*base,const char*url) {
  static char jar=0;
  static uint16_t path[256];
  char scheme[16];
  Scheme key;
  const Scheme*sch;
  const char*p;
  const char*end;
  char*q;
  int n,cs,t;
  restart:
  if(*url=='#' || !*url) {
    // It is a reference to the same file, but possibly a different part of the file.
    base=send_scheme(base,out);
    if(base[0]=='/' && base[1]=='/') {
      fputs("//",out);
      p=base+2;
      while(*p && *p!='/' && *p!='?' && *p!='#') fputc(*p++,out);
      if(*p!='/') fputc('/',out);
    } else {
      p=base;
    }
    while(*p && *p!='#') fputc(*p++,out);
    fputs(url,out);
    return 0;
  }
  // Is the target URL absolute?
  for(n=0;;) {
    if((url[n]>='A' && url[n]<='Z') || (url[n]>='a' && url[n]<='z') || (url[n]>='0' && url[n]<='9') || url[n]=='-' || url[n]=='+' || url[n]=='.') {
      if(n==15) break;
      if(url[n]>='A' && url[n]<='Z') scheme[n]=url[n]+'a'-'A'; else scheme[n]=url[n];
      n++;
    } else if(url[n]==':') {
      key.name=scheme;
      scheme[n++]=0;
      sch=bsearch(&key,schemes,sizeof(schemes)/sizeof(Scheme),sizeof(Scheme),scheme_comp);
      if(!sch) return -1;
      if(sch->id==SCH_HASHED) {
        fputs("hashed:",out);
        p=base+7;
        while(*p && *p!=',' && *p!='?' && *p!='#') fputc(*p++,out);
        if(*p!=',') return -1;
        base=p+1;
      } else if(sch->id==SCH_VIEW_SOURCE) {
        if(jar) return -1;
        if(strncasecmp(base,url,12)) fputs("view-source:",out); else base+=12;
        url+=12;
      } else if(sch->id==SCH_JAR) {
        if(jar || url[4]=='#' || !strncasecmp(url+4,"jar:",4)) return -1;
        q=strdup(url+4);
        if(!q) return -2;
        *strchrnul(q,'!')=0;
        jar=1;
        fputs("jar:",out);
        n=scogem_relative(out,base,p);
        jar=0;
        free(q);
        if(n) return n;
        p=strchr(url+4,'!');
        if(!p || p[1]!='/' | p[2]=='/') return -1;
        fputc('!',out);
        url=p+1;
      } else {
        base=url;
        url=strchrnul(url,'#');
      }
      goto restart;
    } else {
      break;
    }
  }
  if(jar && strchr(base,'!')) return -1;
  // Find scheme of base URL
  key.name=scheme;
  rescheme:
  for(n=0;;) {
    if(base[n]==':') break;
    if(n==15 || !base[n]) return -1;
    if(base[n]>='A' && base[n]<='Z') scheme[n]=base[n]+'a'-'A'; else scheme[n]=base[n];
    n++;
  }
  scheme[n++]=0;
  sch=bsearch(&key,schemes,sizeof(schemes)/sizeof(Scheme),sizeof(Scheme),scheme_comp);
  if(!sch) return -1;
  if(sch->flag&SCHF_NORELATIVE) return -1;
  switch(sch->id) {
    case SCH_1FILE:
      fputs("file:",out);
      base+=n;
      if(!strncmp(base,"////",4)) base++;
      break;
    case SCH_HASHED:
      base=strchr(base,',');
      if(!base) return -1;
      base++;
      goto rescheme;
    case SCH_JAR:
      p=strchr(base,'!');
      if(!p) return -1;
      fwrite("jar",1,3,out);
      fwrite(base+3,1,p-2-base,out);
      base=p+1;
      n=0;
      break;
    case SCH_VIEW_SOURCE:
      base+=12;
      fputs("view-source:",out);
      goto rescheme;
    default:
      fputs(scheme,out);
      fputc(':',out);
      base+=n;
  }
  // Process relative path
  if(*url=='?') {
    p=base;
    while(*p && *p!='?' && *p!='#') fputc(*p++,out);
    fputs(url,out);
    return 0;
  } else if(sch->flag&SCHF_NOHOST) {
    if(url[0]=='/' && url[1]=='/') return -1;
    fputs(url,out);
    return 0;
  } else if(url[0]=='/' && url[1]=='/') {
    fputs("//",out);
    url+=2;
    while(*url && *url!='/' && *url!='?' && *url!='#') fputc(*url++,out);
    if(*url!='/') {
      fputc('/',out);
      fputs(url,out);
      return 0;
    } else if(base[0]=='/' && base[1]=='/') {
      base+=2;
      while(*base && *base!='/' && *base!='?' && *base!='#') base++;
    }
  } else if(base[0]=='/' && base[1]=='/') {
    fputs("//",out);
    base+=2;
    while(*base && *base!='/' && *base!='?' && *base!='#') fputc(*base++,out);
  }
  fputc('/',out);
  if(*base=='/') base++;
  end=base;
  if(*url=='/') {
    url++;
    if(sch->flag&SCHF_ABNORMAL) {
      fputs(url,out);
      return 0;
    }
  } else if(sch->id==SCH_1FILE) {
    end+=strlen(base);
  } else {
    p=base;
    while(*p && *p!='?' && *p!='#') if(*p++=='/') end=p;
  }
  // Pieces of path
  cs=0;
  for(n=0;url[n];) {
    if(n>0x2000) return -1;
    while(url[n]=='/') n++;
    if(!url[n] || url[n]=='#' || url[n]=='?') break;
    if(url[n]=='.') {
      if(url[n+1]=='.') t=1; else t=0;
      if(url[n+t+1]=='/' || !url[n+t+1] || url[n+t+1]=='#' || url[n+t+1]=='?') {
        if(t) {
          if(cs) {
            --cs;
          } else if(end>base) {
            if(end[-1]=='/') --end;
            while(end>base && end[-1]!='/') --end;
          }
        }
        n+=t+1;
        continue;
      }
    }
    if(cs>=255) return -1;
    path[cs++]=n;
    while(url[n] && url[n]!='#' && url[n]!='?' && url[n]!='/') n++;
  }
  // Write path out
  if(sch->id!=SCH_1FILE) {
    fwrite(base,1,end-base,out);
  } else {
    for(p=base;p<end;p++) {
      if((*p>='A' && *p<='Z') || (*p>='a' && *p<='z') || (*p>='0' && *p<='9') || *p=='.' || *p=='-' || *p=='_' || *p=='/' || *p=='~') {
        fputc(*p,out);
      } else {
        fprintf(out,"%%%02X",*p&0xFF);
      }
    }
  }
  end=url+n;
  for(t=0;t<cs;t++) {
    p=url+path[t];
    while(*p && *p!='/' && *p!='#' && *p!='?') fputc(*p++,out);
    if(*p=='/') fputc('/',out);
  }
  fputs(end,out);
  return 0;
}

int scogem_relative_cwd(FILE*out,const char*url) {
  const char*p=url;
  char*q;
  if(*p=='/') return scogem_relative(out,"file:///",url);
  while(*p) {
    if((*p>='A' && *p<='Z') || (*p>='a' && *p<='z') || (*p>='0' && *p<='9') || *p=='-' || *p=='+' || *p=='.') {
      p++;
    } else if(*p==':') {
      if(p==url+4 && (url[0]|0x20)=='f' && (url[1]|0x20)=='i' && (url[2]|0x20)=='l' && (url[3]|0x20)=='e' && p[1] && (p[1]!='/' || p[2]!='/')) {
        url=p+1;
      } else {
        return scogem_relative(out,url,strchrnul(url,'#'));
      }
    } else {
      break;
    }
  }
  strcpy(urlbuf,"\x01""file:///");
  if(!getcwd(urlbuf+9,0x2000-11)) return -1;
  q=urlbuf+strlen(urlbuf);
  if(q>urlbuf && q[-1]!='/') *q='/',q[1]=0;
  if(!*url || *url=='#') {
    if(scogem_relative(out,urlbuf,".")) return -1;
    fputs(url,out);
    return 0;
  } else {
    return scogem_relative(out,urlbuf,url);
  }
}

void scogem_encode_c(uint8_t flag,FILE*out,uint8_t in) {
  if(in || (flag&SCOGEM_ALLOW_NULL)) {
    if((in>='A' && in<='Z') || (in>='a' && in<='z') || (in>='0' && in<='9') || in=='.' || in=='-' || in=='_' || in=='~' || ((flag&SCOGEM_NOENCODE_SLASH) && in=='/')) {
      fputc(in,out);
    } else if(in==' ' && (flag&SCOGEM_SPACE_AS_PLUS)) {
      fputc('+',out);
    } else {
      fprintf(out,"%%%02X",in);
    }
  }
}

void scogem_encode_f(uint8_t flag,FILE*out,FILE*in) {
  int c;
  while((c=fgetc(in))!=EOF) {
    if(!(flag&SCOGEM_ALLOW_NULL) && !c) return;
    if((flag&SCOGEM_CONTROL_STOP) && !(c&~0x1F)) return;
    if((c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9') || c=='.' || c=='-' || c=='_' || c=='~' || ((flag&SCOGEM_NOENCODE_SLASH) && c=='/')) {
      fputc(c,out);
    } else if(c==' ' && (flag&SCOGEM_SPACE_AS_PLUS)) {
      fputc('+',out);
    } else {
      fprintf(out,"%%%02X",c&0xFF);
    }
  }
}

void scogem_encode_m(uint8_t flag,FILE*out,const char*in,size_t len) {
  while(len--) {
    if(!(flag&SCOGEM_ALLOW_NULL) && !*in) return;
    if((flag&SCOGEM_CONTROL_STOP) && !(*in&~0x1F)) return;
    if((*in>='A' && *in<='Z') || (*in>='a' && *in<='z') || (*in>='0' && *in<='9') || *in=='.' || *in=='-' || *in=='_' || *in=='~' || ((flag&SCOGEM_NOENCODE_SLASH) && *in=='/')) {
      fputc(*in,out);
    } else if(*in==' ' && (flag&SCOGEM_SPACE_AS_PLUS)) {
      fputc('+',out);
    } else {
      fprintf(out,"%%%02X",*in&0xFF);
    }
    in++;
  }
}

void scogem_encode_s(uint8_t flag,FILE*out,const char*in) {
  while(*in) {
    if((flag&SCOGEM_CONTROL_STOP) && !(*in&~0x1F)) return;
    if((*in>='A' && *in<='Z') || (*in>='a' && *in<='z') || (*in>='0' && *in<='9') || *in=='.' || *in=='-' || *in=='_' || *in=='~' || ((flag&SCOGEM_NOENCODE_SLASH) && *in=='/')) {
      fputc(*in,out);
    } else if(*in==' ' && (flag&SCOGEM_SPACE_AS_PLUS)) {
      fputc('+',out);
    } else {
      fprintf(out,"%%%02X",*in&0xFF);
    }
    in++;
  }
}

int scogem_decode_f(uint8_t flag,FILE*out,FILE*in) {
  int c,d;
  while((c=fgetc(in))>0) {
    if(c=='%') {
      d=fgetc(in);
      if(d>='0' && d<='9') c=d-'0';
      else if(d>='A' && d<='F') c=d-'A'+10;
      else if(d>='a' && d<='f') c=d-'a'+10;
      else return -1;
      c<<=4;
      d=fgetc(in);
      if(d>='0' && d<='9') c+=d-'0';
      else if(d>='A' && d<='F') c+=d-'A'+10;
      else if(d>='a' && d<='f') c+=d-'a'+10;
      else return -1;
      if(!c && !(flag&SCOGEM_ALLOW_NULL)) return -1;
      if(c=='/' && (flag&SCOGEM_NOENCODE_SLASH)) return -1;
      fputc(c,out);
    } else if((flag&SCOGEM_CONTROL_STOP) && !(c&~0x1F)) {
      ungetc(c,in);
      return 0;
    } else {
      if((flag&SCOGEM_SPACE_AS_PLUS) && c=='+') c=' ';
      fputc(c,out);
    }
  }
  return 0;
}

int scogem_decode_m(uint8_t flag,FILE*out,const char*in,size_t len) {
  int c,d;
  while(len--) {
    c=*in++;
    if(!c) return 0;
    if(c=='%') {
      if(len<2) return -1;
      len-=2;
      d=*in++;
      if(d>='0' && d<='9') c=d-'0';
      else if(d>='A' && d<='F') c=d-'A'+10;
      else if(d>='a' && d<='f') c=d-'a'+10;
      else return -1;
      c<<=4;
      d=*in++;
      if(d>='0' && d<='9') c+=d-'0';
      else if(d>='A' && d<='F') c+=d-'A'+10;
      else if(d>='a' && d<='f') c+=d-'a'+10;
      else return -1;
      if(!c && !(flag&SCOGEM_ALLOW_NULL)) return -1;
      if(c=='/' && (flag&SCOGEM_NOENCODE_SLASH)) return -1;
      fputc(c,out);
    } else if((flag&SCOGEM_CONTROL_STOP) && !(c&~0x1F)) {
      return 0;
    } else {
      if((flag&SCOGEM_SPACE_AS_PLUS) && c=='+') c=' ';
      fputc(c,out);
    }
  }
  return 0;
}

int scogem_decode_s(uint8_t flag,FILE*out,const char*in) {
  return scogem_decode_m(flag,out,in,-1);
}

// Protocol implementations were going to be added here, but I should add them into a separate file instead, perhaps.

