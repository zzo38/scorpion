#if 0
gcc -s -O2 -c smallxrm.c
exit
#endif

/*
  Small XRM (X Resource Manager) in C.
  Public domain.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "smallxrm.h"

typedef struct xrm_pair {
  xrm_quark k;
  xrm_db*x;
} xrm_pair;

typedef struct xrm_map {
  int n;
  xrm_pair*p;
} xrm_map;

typedef struct xrm_db {
  xrm_map l;
  xrm_map t;
  char*v;
} xrm_db;

#define BUFINC 1024

static char anyq_name[2]="?";
static void*(*my_realloc)(void*,size_t);
static int nquarks;
static xrm_quark*quarklook;
static char**quarknames;
static xrm_quark keyquark=0;
static const char*keyname;
static char*inbuf;
static int inbufsize;
static int staticquarks;

static void*cb_get_resource(xrm_db*db,void*usr) {
  return db->v;
}

static int db_compar(const void*a,const void*b) {
  const xrm_pair*x=a;
  const xrm_pair*y=b;
  return x->k<y->k?-1:x->k==y->k?0:1;
}

static char*my_strdup(const char*p) {
  char*s=my_realloc(0,strlen(p)+1);
  if(!s) return 0;
  strcpy(s,p);
  return s;
}

static int quarklook_compar(const void*a,const void*b) {
  xrm_quark x=*(const xrm_quark*)a;
  xrm_quark y=*(const xrm_quark*)b;
  return strcmp(x?quarknames[x-1]?:"":keyname,y?quarknames[y-1]?:"":keyname);
}

void xrm_annihilate(void) {
  int i;
  if(!my_realloc) return;
  for(i=staticquarks;i<nquarks;i++) my_realloc(quarknames[i],0);
  my_realloc(quarknames,0);
  nquarks=0;
  quarklook=0;
  quarknames=0;
  my_realloc(inbuf,0);
  inbuf=0;
  inbufsize=0;
  my_realloc=0;
}

xrm_db*xrm_create(void) {
  xrm_db*db=my_realloc(0,sizeof(xrm_db));
  if(!db) return 0;
  db->l.n=0;
  db->l.p=0;
  db->t.n=0;
  db->t.p=0;
  db->v=0;
  return db;
}

void xrm_destroy(xrm_db*db) {
  int i;
  if(!db) return;
  my_realloc(db->v,0);
  for(i=0;i<db->l.n;i++) xrm_destroy(db->l.p[i].x);
  my_realloc(db->l.p,0);
  for(i=0;i<db->t.n;i++) xrm_destroy(db->t.p[i].x);
  my_realloc(db->t.p,0);
  my_realloc(db,0);
}

void*xrm_enumerate(xrm_db*db,void*(*cb)(xrm_db*,void*,int,xrm_quark),void*usr) {
  int i;
  void*r;
  if(!db) return 0;
  for(i=0;i<db->t.n;i++) if(r=cb(db,usr,0,db->t.p[i].k)) return r;
  for(i=0;i<db->l.n;i++) if(r=cb(db,usr,1,db->l.p[i].k)) return r;
  return 0;
}

const char*xrm_get(xrm_db*db) {
  return db?db->v:0;
}

const char*xrm_get_resource(xrm_db*db,const xrm_quark*ns,const xrm_quark*cs,int len) {
  if(!db) return 0;
  return xrm_search(db,ns,cs,len,cb_get_resource,0);
}

int xrm_init(void*(*f)(void*,size_t)) {
  if(my_realloc || !f) return -1;
  my_realloc=f;
  nquarks=1;
  quarknames=my_realloc(0,sizeof(char*));
  if(!quarknames) goto bad;
  quarklook=my_realloc(0,sizeof(xrm_quark));
  if(!quarklook) {
    my_realloc(quarknames,0);
    quarknames=0;
    goto bad;
  }
  *quarklook=xrm_anyq;
  *quarknames=anyq_name;
  inbuf=0;
  inbufsize=0;
  staticquarks=1;
  return 0;
bad:
  my_realloc=0;
  return -1;
}

int xrm_init_quarks(const char*const*list) {
  void*mem;
  int i=0;
  if(!my_realloc || !list || nquarks!=1 || staticquarks!=1) return -1;
  while(list[i]) i++;
  mem=my_realloc(quarknames,(i+1)*sizeof(char*));
  if(!mem) return -1;
  quarknames=mem;
  mem=my_realloc(quarklook,(i+1)*sizeof(xrm_quark));
  if(!mem) return -1;
  quarklook=mem;
  nquarks=staticquarks=i+1;
  for(i=0;list[i];i++) {
    quarknames[i+1]=(char*)(list[i]);
    quarklook[i+1]=i+2;
  }
  qsort(quarklook,nquarks,sizeof(xrm_quark),quarklook_compar);
  return 0;
}

int xrm_link(xrm_db*db,int loose,xrm_quark q,xrm_db*ins) {
  xrm_map*m;
  xrm_pair*p;
  xrm_pair k={q,ins};
  if(!db || !q) return 0;
  m=loose?&db->l:&db->t;
  if(m->n) {
    p=bsearch(&k,m->p,m->n,sizeof(xrm_pair),db_compar);
    if(p) {
      *p=k;
      return 0;
    }
  }
  p=my_realloc(m->p,(m->n+1)*sizeof(xrm_pair));
  if(!p) return -1;
  p[m->n]=k;
  qsort(p,++m->n,sizeof(xrm_pair),db_compar);
  m->p=p;
  return 0;
}

int xrm_load(xrm_db*db,FILE*fp,int o) {
  int bs,c,n,x;
  if(!inbuf) {
    inbuf=my_realloc(0,BUFINC+2);
    if(!inbuf) return -1;
    inbufsize=BUFINC;
  }
  if(!db || !fp) return -1;
  for(c=0;c!=EOF;) {
    for(x=bs=0;(c=fgetc(fp))!=EOF;) {
      if(c=='\r') continue;
      if(c=='\\') {
        bs^=1;
      } else if(c=='\n') {
        if(bs--) x--; else break;
      } else {
        bs=0;
      }
      inbuf[x++]=c;
      if(x>=inbufsize) {
        char*buf=my_realloc(inbuf,inbufsize+BUFINC+2);
        if(!buf) return -1;
        inbuf=buf;
        inbufsize+=BUFINC;
      }
    }
    inbuf[x]=0;
    xrm_load_line(db,inbuf,o);
  }
  return 0;
}

int xrm_load_line(xrm_db*db,const char*s,int o) {
  int c;
  int loose=0;
  char*p;
  char*q=0;
  char*r;
  if(!s) return -1;
  if(!*s || *s=='!') return 0;
  if(*s=='#') return -1;
  if(s!=inbuf) {
    int i=strlen(s)+1;
    if(i>=inbufsize) {
      char*buf=my_realloc(inbuf,i+2);
      if(!buf) return -1;
      inbuf=buf;
      inbufsize=i;
    }
    strcpy(inbuf,s);
  }
  p=inbuf;
  while(*p==' ' || *p=='\t') s++;
  if(!*p) return 0;
  while(c=*p++) {
    if(c=='.' || c=='*' || c==':') {
      if(q) {
        r=p-1;
        *r--=0;
        while(r>q && (*r==' ' || *r=='\t')) *r--=0;
        db=xrm_sub(db,loose,xrm_make_quark(q,1));
        if(!db) return -1;
        loose=0;
        q=0;
      }
      if(c=='*') loose=1;
      if(c==':') break;
    } else if(c!=' ' && c!='\t' && !q) {
      q=p-1;
    }
  }
  if(!c) return -1;
  if(db->v && !o) return 0;
  while(*p==' ' || *p=='\t') p++;
  q=p;
  while(c=*p++) {
    if(c=='\\') {
      if(p[0]>='0' && p[0]<'8' && p[1]>='0' && p[1]<'8' && p[2]>='0' && p[2]<'8') {
        r=p+2;
        *r=((p[0]-'0')<<6)|((p[1]-'0')<<3)|(p[2]-'0');
        while(*r) r[-3]=*r,++r;
        r[-3]=0;
      } else {
        if(*p=='n') *p='\n';
        r=p;
        while(*r) r[-1]=*r,++r;
        r[-1]=0;
      }
    } else if(c=='\r' || c=='\n') {
      break;
    }
  }
  *p=0;
  return xrm_put(db,q,1);
}

xrm_quark xrm_make_quark(const char*name,int addnew) {
  xrm_quark*q;
  if(name && !*name) return 0;
  keyname=name;
  if(!name) {
    if(!addnew) return 0;
    q=0;
  } else {
    q=bsearch(&keyquark,quarklook,nquarks,sizeof(xrm_quark),quarklook_compar);
  }
  if(addnew && !q) {
    xrm_quark*ql=my_realloc(quarklook,(nquarks+1)*sizeof(xrm_quark));
    char**qn=my_realloc(quarknames,(nquarks+1)*sizeof(char*));
    if(ql) quarklook=ql;
    if(qn) quarknames=qn;
    if(!ql || !qn) return 0;
    if(name) {
      qn[nquarks]=my_strdup(name);
      if(!qn[nquarks]) return 0;
    } else {
      qn[nquarks]=0;
    }
    ql[nquarks]=++nquarks;
    qsort(quarklook,nquarks,sizeof(xrm_quark),quarklook_compar);
    return nquarks;
  } else {
    return q?*q:0;
  }
}

int xrm_merge(xrm_db*to,xrm_db*from,int o) {
  int i;
  if(!from) return 0;
  if(!to) return -1;
  if(xrm_put(to,from->v,o)) return -1;
  for(i=0;i<from->t.n;i++) if(xrm_merge(xrm_sub(to,0,from->t.p[i].k),from->t.p[i].x,o)) return -1;
  for(i=0;i<from->l.n;i++) if(xrm_merge(xrm_sub(to,1,from->l.p[i].k),from->l.p[i].x,o)) return -1;
  return 0;
}

const char*xrm_name(xrm_quark n) {
  if(!n || n>nquarks) return 0;
  return quarknames[n-1];
}

int xrm_put(xrm_db*db,const char*v,int o) {
  char*s;
  if(!db) return -1;
  if(db->v && !o) return 0;
  if(v) {
    s=my_strdup(v);
    if(!s) return -1;
    my_realloc(db->v,0);
    db->v=s;
  } else {
    my_realloc(db->v,0);
    db->v=0;
  }
  return 0;
}

int xrm_put_resource(xrm_db*db,const xrm_quark*q,const char*b,const char*v,int o) {
  while(*b) {
    if(*b!='.' && *b!='*') return -1;
    db=xrm_sub(db,*b=='*',*q);
    q++; b++;
  }
  return xrm_put(db,v,o);
}

void*xrm_search(xrm_db*db,const xrm_quark*ns,const xrm_quark*cs,int len,void*(*cb)(xrm_db*,void*),void*usr) {
  xrm_db*p;
  void*r;
  if(!len) return cb(db,usr);
  if((p=xrm_sub(db,0,*ns)) && (r=xrm_search(p,ns+1,cs+1,len-1,cb,usr))) return r;
  if(ns!=cs && (p=xrm_sub(db,0,*cs)) && (r=xrm_search(p,ns+1,cs+1,len-1,cb,usr))) return r;
  if((p=xrm_sub(db,0,xrm_anyq)) && (r=xrm_search(p,ns+1,cs+1,len-1,cb,usr))) return r;
again:
  if((p=xrm_sub(db,1,*ns)) && (r=xrm_search(p,ns+1,cs+1,len-1,cb,usr))) return r;
  if(ns!=cs && (p=xrm_sub(db,1,*cs)) && (r=xrm_search(p,ns+1,cs+1,len-1,cb,usr))) return r;
  if((p=xrm_sub(db,1,xrm_anyq)) && (r=xrm_search(p,ns+1,cs+1,len-1,cb,usr))) return r;
  ns++; cs++;
  if(--len) goto again;
  return 0;
}

xrm_db*xrm_sub(xrm_db*db,int loose,xrm_quark q) {
  xrm_map*m;
  xrm_pair*p;
  xrm_pair k={q,0};
  if(!db || !q) return 0;
  m=loose?&db->l:&db->t;
  if(m->n) {
    p=bsearch(&k,m->p,m->n,sizeof(xrm_pair),db_compar);
    if(p) return p->x;
  }
  k.x=xrm_create();
  if(!k.x) return 0;
  p=my_realloc(m->p,(m->n+1)*sizeof(xrm_pair));
  if(!p) {
    my_realloc(k.x,0);
    return 0;
  }
  p[m->n]=k;
  qsort(p,++m->n,sizeof(xrm_pair),db_compar);
  m->p=p;
  return k.x;
}

