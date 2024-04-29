#if 0
gcc -s -O2 -c fontconfig.c `sdl-config --cflags`
exit
#endif

#include "common.h"
#include <errno.h>
#include <glob.h>

FontConfig fontc;

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
  free(x->name);
  free(x);
}

static void cstree_des(void*nodep) {
  Node*x=(Node*)nodep;
  if(!x->charset) errx(1,"Character set '%s' mentioned but not defined",x->name);
  fontc.charset[x->id]=x->charset[0];
  free(x->charset);
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

void load_fontconfig(void) {
  BlockStyle*bs;
  Node*node;
  Node*node2;
  int state=0;
  void*grouptree=0;
  void*cstree=0;
  int maxgroup=0;
  int maxcs=2;
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
        node->id=maxcs++;
      } else if(!node->charset) {
        node->charset=calloc(sizeof(CharsetInfo),1);
        if(!node->charset) err(1,"Allocation failed");
      }
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
  tdestroy(cstree,cstree_des);
}

