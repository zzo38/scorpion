#if 0
gcc -s -O2 -c fontconfig.c `sdl-config --cflags`
exit
#endif

#include "common.h"
#include <errno.h>
#include <glob.h>

FontConfig fontc;

static CharsetInfo csalias={.kind=CS_ALIAS};

typedef struct {
  union {
    void*unknown;
    FontGroup*group;
    CharsetInfo*charset;
  };
  char*name;
  Uint16 id;
} Node;

static int compare_key(const void*a,const void*b) {
  const Node*x=a;
  const Node*y=b;
  return strcmp(x->name,y->name);
}

static int compare_csname(const void*a,const void*b) {
  const CharsetName*x=a;
  const CharsetName*y=b;
  return strcmp(x->name,y->name);
}

static int add_node(Node**y,char*name,void**tree) {
  Node**x;
  Node key;
  key.name=name;
  x=tsearch(&key,tree,compare_key);
  if(!x) err(1,"Allocation failed");
  if(*x==&key) {
    key.name=strdup(name);
    if(!key.name) err(1,"Allocation failed");
    key.unknown=0;
    *y=*x=malloc(sizeof(Node));
    if(!*x) err(1,"Allocation failed");
    **x=key;
    return 1;
  } else {
    *y=*x;
    return 0;
  }
}

static const char*const blocknames[]={
  [B_NORMAL]="NORM",
  [B_H1]="H1",
  [B_H2]="H2",
  [B_H3]="H3",
  [B_H4]="H4",
  [B_H5]="H5",
  [B_H6]="H6",
  [B_LINK]="LINK",
  [B_LINK_INPUT]="LINK_ASK",
  [B_LINK_INTERACT]="LINK_INTER",
  [B_LINK_ALTERNATE]="LINK_ALT",
  [B_QUOTE]="QUOTE",
  [B_PRE]="PRE",
  [B_METADATA]="META",
  [B_EOF]="EOF",
  [B_ERROR]="ERR",
  [B_INFO]="INFO",
  [B_SYSTEM]="SYS",
};

static void grouptree_des(void*nodep) {
  Node*x=(Node*)nodep;
  if(!x->group) errx(1,"Font group '%s' mentioned but not defined",x->name);
  fontc.group[x->id]=x->group[0];
  free(x->group);
  if(x->name[0]=='*') {
    if(x->name[1]=='*' && !x->name[2]) fontc.ui2=x->id;
    if(!x->name[1]) fontc.ui1=x->id;
  }
  free(x->name);
  free(x);
}

static void cstree_des(void*nodep) {
  Node*x=(Node*)nodep;
  if(!x->charset) errx(1,"Character set '%s' mentioned but not defined",x->name);
  if(x->charset!=&csalias) {
    if(x->charset->kind==CS_UNDEF) errx(1,"Character set '%s' does not have a valid kind",x->name);
    fontc.charset[x->id]=x->charset[0];
    free(x->charset);
  }
  fontc.csnames[fontc.ncsnames].name=x->name;
  fontc.csnames[fontc.ncsnames++].id=x->id;
  free(x);
}

static int globerrcb(const char*epath,int eerrno) {
  errno=eerrno;
  warn("Glob error with '%s'",epath);
  return 0;
}

static void set_tron_fonts(FontGroup*g,int sty,const char*name) {
  glob_t gl={};
  FontSet y={};
  const char*e;
  FILE*f;
  int i;
  if(glob(name,GLOB_NOSORT|GLOB_MARK|GLOB_TILDE|GLOB_BRACE,globerrcb,&gl)) errx(1,"Glob error with pattern '%s'",name);
  for(i=0;i<gl.gl_pathc;i++) {
    if(gl.gl_pathv[i][strlen(gl.gl_pathv[i])-1]=='/') continue;
    f=fopen(gl.gl_pathv[i],"r");
    if(!f) err(1,"Cannot open font file '%s'",gl.gl_pathv[i]);
    if(e=load_font_into_set(f,&y,0,0)) errx(1,"Font error with '%s': %s",gl.gl_pathv[i],e);
    fclose(f);
  }
  globfree(&gl);
  for(i=0;i<NUM_TEXT_FORMATS;i++) if(sty&(1<<i)) g->tron[i]=y;
}

static void set_normal_fonts(FontGroup*g,int sty,int id,const char*name) {
  Font y={};
  const char*e;
  int i;
  FILE*f=fopen(name,"r");
  if(!f) err(1,"Cannot open font file '%s'",name);
  if(e=load_font(f,&y,0)) errx(1,"Font error with '%s': %s",name,e);
  fclose(f);
  if(g->numcs<=id) {
    g->others=realloc(g->others,(id+1)*NUM_TEXT_FORMATS*sizeof(Font));
    if(!g->others) err(1,"Memory error");
    for(i=g->numcs*NUM_TEXT_FORMATS;i<(id+1)*NUM_TEXT_FORMATS;i++) memset(g->others+i,0,sizeof(Font));
    g->numcs=id+1;
  }
  for(i=0;i<NUM_TEXT_FORMATS;i++) if(sty&(1<<i)) g->others[i+id*NUM_TEXT_FORMATS]=y;
}

static void load_charset_map(Uint32*map,const char*name) {
  int c;
  Uint32 n=0;
  Uint32 s=0;
  Uint32 u;
  FILE*f=fopen(name,"r");
  if(!f) err(1,"Cannot open file '%s'",name);
  plane:
  c=fgetc(f);
  if(c==EOF) errx(1,"Unexpected end of file");
  if(c==0xFE) {
    s+=0x100;
    goto plane;
  } else if(c==0x7F || c==0xFF || c<0x21) {
    errx(1,"Improper command in character map file");
  } else {
    s+=c;
  }
  normal:
  if(n>0xFF) goto end;
  c=fgetc(f);
  if(c==EOF) goto end;
  if(c==0xFE) {
    s=0;
    goto plane;
  } else if(c<0x21) {
    u=n?map[n-1]:0;
    for(c++;c;c--) {
      if(n>0xFF) errx(1,"Improper command in character map file");
      map[n++]=u?++u:0;
    }
  } else if(c==0x7F || c==0xFF) {
    map[n++]=0;
  } else {
    map[n]=s<<16;
    map[n]|=c<<8;
    map[n]|=fgetc(f)&255;
    n++;
  }
  goto normal;
  end:
  fclose(f);
}

void load_fontconfig(void) {
  BlockStyle*bs;
  Node*node;
  Node*node2;
  int state=0;
  void*grouptree=0;
  void*cstree=0;
  int maxgroup=0;
  int maxcs=2;
  int maxalias=0;
  char*line=0;
  char*p;
  char*q;
  size_t line_size=0;
  int linenum=0;
  int i,j;
  FILE*fp=fopenat(config_dir,"fontconfig","r");
  // It is necessary for TRON and PC to be the first two character sets.
  add_node(&node,"TRON",&cstree);
  node->id=0;
  node->charset=calloc(sizeof(CharsetInfo),1);
  if(!node->charset) err(1,"Allocation failed");
  node->charset->kind=CS_TRON;
  add_node(&node,"PC",&cstree);
  node->id=1;
  node->charset=calloc(sizeof(CharsetInfo),1);
  if(!node->charset) err(1,"Allocation failed");
  node->charset->kind=CS_NORMAL;
  while(getline(&line,&line_size,fp)>0) {
    ++linenum;
    if(!*line || *line=='\n' || *line=='#') continue;
    p=line+strlen(line);
    while(p>line && (p[-1]=='\n' || p[-1]=='\r' || p[-1]=='\t' || p[-1]==' ')) *--p=0;
    if(*line=='(') {
      p=strchr(line,')');
      if(!p || p[1]) goto syntax;
      *p=0;
      if(add_node(&node,line+1,&grouptree)) {
        node->group=calloc(sizeof(FontGroup),1);
        if(!node->group) err(1,"Allocation failed");
        node->group->other=node->id=maxgroup++;
      } else if(!node->group) {
        node->group=calloc(sizeof(FontGroup),1);
        if(!node->group) err(1,"Allocation failed");
      }
      state='G';
    } else if(*line=='<') {
      p=strchr(line,'>');
      if(!p || p[1]) goto syntax;
      *p=0;
      if(add_node(&node,line+1,&cstree)) {
        node->charset=calloc(sizeof(CharsetInfo),1);
        if(!node->charset) err(1,"Allocation failed");
        node->charset->link=node->id=maxcs++;
      } else if(!node->charset) {
        node->charset=calloc(sizeof(CharsetInfo),1);
        if(!node->charset) err(1,"Allocation failed");
        node->charset->link=node->id;
      } else if(node->charset==&csalias) {
        errx(1,"Character set '%s' is an alias and cannot be redefined",line+1);
      }
      if(node->charset->kind==CS_UNDEF) node->charset->kind=CS_NORMAL;
      state='C';
    } else if(*line=='[') {
      p=strchr(line,']');
      if(!p || p[1]) goto syntax;
      *p=0;
      state='B';
      for(i=0;i<sizeof(blocknames)/sizeof(const char*);i++) {
        if(blocknames[i] && !strcasecmp(line+1,blocknames[i])) {
          bs=fontc.bstyle+i;
          goto found;
        }
      }
      errx(1,"Improper block type on line %d of fontconfig",linenum);
      found: ;
    } else if(state=='B') {
      p=strchr(line,'=');
      if(!p) goto syntax;
      *p++=0;
      switch(*line) {
        case 'C':
          if(!strcasecmp(line,"Color")) {
            bs->color=parse_color(p);
          } else if(!strcasecmp(line,"Copy")) {
            for(i=0;i<sizeof(blocknames)/sizeof(const char*);i++) {
              if(blocknames[i] && !strcasecmp(p,blocknames[i])) goto copyfound;
            }
            errx(1,"Improper block type on line %d of fontconfig",linenum);
            copyfound:
            *bs=fontc.bstyle[i];
          } else {
            goto syntax;
          }
          break;
        case 'D':
          if(strcasecmp(line,"Depth")) goto syntax;
          bs->depth=strtol(p,0,10);
          break;
        case 'F':
          if(strcasecmp(line,"Fonts")) goto syntax;
          if(add_node(&node,p,&grouptree)) node->id=maxgroup++;
          bs->group=node->id;
          break;
        case 'H':
          if(strcasecmp(line,"Height")) goto syntax;
          bs->height=strtol(p,0,10);
          break;
        case 'I':
          if(strcasecmp(line,"Indent")) goto syntax;
          bs->indent=strtol(p,0,10);
          break;
        case 'L':
          if(!strcasecmp(line,"Leading")) {
            bs->leading=strtol(p,0,10);
          } else if(!strcasecmp(line,"LeftMargin")) {
            bs->lmargin=strtol(p,0,10);
          } else {
            goto syntax;
          }
          break;
        case 'R':
          if(strcasecmp(line,"RightMargin")) goto syntax;
          bs->rmargin=strtol(p,0,10);
          break;
        default: goto syntax;
      }
    } else if(state=='G' && *line>='1' && *line<='9') {
      i=strtol(line,&p,10);
      if(*p++!='x') goto syntax;
      j=strtol(p,&p,10);
      if(*p==':') {
        node->group->oxsc=i?:1;
        node->group->oysc=j?:1;
        if(add_node(&node2,p+1,&grouptree)) node2->id=maxgroup++;
        node->group->other=node2->id;
      } else if(!*p) {
        node->group->xsc=i;
        node->group->ysc=j;
      } else {
        goto syntax;
      }
    } else if(state=='G' && ((*line>='A' && *line<='Z') || *line=='*')) {
      p=strchr(line,':');
      if(!p) goto syntax;
      q=strchr(++p,':');
      if(!q) goto syntax;
      *q++=0;
      if(add_node(&node2,p,&cstree)) node2->id=maxcs++;
      j=0;
      p=line;
      while(*p!=':') switch(*p++) {
        case '*': j|=0x0F; break;
        case 'N': j|=0x01; break;
        case 'S': j|=0x02; break;
        case 'E': j|=0x04; break;
        case 'F': j|=0x08; break;
        case 'U': j|=0x10; break;
        default: goto syntax;
      }
      if(node2->id) set_normal_fonts(node->group,j,node2->id,q); else set_tron_fonts(node->group,j,q);
    } else if(state=='C') {
      p=strchr(line,'=');
      if(!p) goto syntax;
      *p++=0;
      switch(*line) {
        case 'A':
          if(!strcasecmp(line,"Alias")) {
            if(!add_node(&node2,p,&cstree)) errx(1,"Character set already defined on line %d of fontconfig",linenum);
            maxalias++;
            node2->charset=&csalias;
            node2->id=node->id;
          } else if(!strcasecmp(line,"Alternate")) {
            if(add_node(&node2,p,&cstree)) node2->id=maxcs++;
            node->charset->link=node2->id;
          } else {
            goto syntax;
          }
          break;
        case 'M':
          if(strcasecmp(line,"Map")) goto syntax;
          if(node->charset->map) errx(1,"Error on line %d of fontconfig: map is already specified",linenum);
          node->charset->map=calloc(0x100,sizeof(Uint32));
          if(!node->charset->map) err(1,"Allocation failed");
          load_charset_map(node->charset->map,p);
          node->charset->kind=CS_MAPPED_TRON;
          break;
        default: goto syntax;
      }
    } else {
      syntax: errx(1,"Syntax error on line %d of fontconfig",linenum);
    }
  }
  if(maxgroup>254 || maxcs>254) errx(1,"Too many font groups and character set definitions");
  free(line);
  fclose(fp);
  fontc.group=calloc(fontc.ngroup=maxgroup,sizeof(FontGroup));
  if(!fontc.group) err(1,"Allocation failed");
  tdestroy(grouptree,grouptree_des);
  fontc.charset=calloc(fontc.ncharset=maxcs,sizeof(CharsetInfo));
  if(!fontc.charset) err(1,"Allocation failed");
  fontc.csnames=calloc(maxcs+maxalias,sizeof(CharsetName));
  if(!fontc.csnames) err(1,"Allocation failed");
  fontc.ncsnames=0;
  tdestroy(cstree,cstree_des);
  qsort(fontc.csnames,fontc.ncsnames,sizeof(CharsetName),compare_csname);
  if(config.dumpfontconfig) {
    printf("[FONTCONFIG]\n");
    printf(" ngroup=%d ncharset=%d maxalias=%d ncsnames=%d\n",fontc.ngroup,fontc.ncharset,maxalias,fontc.ncsnames);
    printf(" ui1=%d ui2=%d\n",fontc.ui1,fontc.ui2);
    for(i=0;i<fontc.ngroup;i++) {
      printf("group[%d]:\n",i);
      printf(" sc=%dx%d osc=%dx%d other=%d",fontc.group[i].xsc,fontc.group[i].ysc,fontc.group[i].oxsc,fontc.group[i].oysc,fontc.group[i].other);
      printf(" numcs=%d\n",fontc.group[i].numcs);
      for(j=0;j<fontc.group[i].numcs*NUM_TEXT_FORMATS;j++) if(fontc.group[i].others[j].data) printf(" font(%d)\n",j);
      for(j=0;j<NUM_TEXT_FORMATS;j++) if(fontc.group[i].tron[j].len) printf(" tron(%d)=%d\n",j,fontc.group[i].tron[j].len);
    }
    for(i=0;i<fontc.ncharset;i++) {
      printf("charset[%d]:\n",i);
      printf(" kind=%d map=%p link=%d\n",fontc.charset[i].kind,fontc.charset[i].map,fontc.charset[i].link);
    }
    for(i=0;i<NUM_BLOCK_TYPES;i++) {
      printf("block[%d]:\n",i);
      printf(" lmargin=%d rmargin=%d indent=%d leading=%d height=%d depth=%d\n",fontc.bstyle[i].lmargin,fontc.bstyle[i].rmargin,fontc.bstyle[i].indent
       ,fontc.bstyle[i].leading,fontc.bstyle[i].height,fontc.bstyle[i].depth);
      printf(" group=%d color=%08lX\n",fontc.bstyle[i].group,(unsigned long)fontc.bstyle[i].color);
    }
    printf("csnames:\n");
    for(i=0;i<fontc.ncsnames;i++) printf(" name=\"%s\" id=%d\n",fontc.csnames[i].name,fontc.csnames[i].id);
  }
}

int find_charset_by_name(const char*name) {
  CharsetName key={(char*)name,0};
  CharsetName*x=bsearch(&key,fontc.csnames,fontc.ncsnames,sizeof(CharsetName),compare_csname);
  return x?x->id:-1;
}

