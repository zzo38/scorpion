#if 0
gcc -g -O0 -c window.c
exit
#endif

#include "window.h"

Display*display;
Window rootwindow;
Window mainwindow;
ColorConfig colors;
Colormap colormap;

#define X(x) Atom XA_##x;
#include "atom.inc"
#undef X

static Cursor cursors[80];
static char privatecolor;
static XContext window_data_context;
static int server_fd;
static int poll_fd;
static FdStatus closed_root;
static FdStatus*closed_item=&closed_root;
static FdStatus*server_fd_status;

static int server_fd_in_event(FdStatus*s) {
  XEvent e;
  WindowStatus*p;
  int i;
  while(XPending(display)) {
    XNextEvent(display,&e);
    if(e.type==MappingNotify) {
      XRefreshKeyboardMapping(&e.xmapping);
      continue;
    }
    if(!e.xany.window || XFindContext(display,e.xany.window,window_data_context,(XPointer*)&p) || !p) continue;
    if(e.type==DestroyNotify && e.xdestroywindow.event==e.xdestroywindow.window) {
      p->flag|=WF_DESTROYED;
      if(p->class->event) i=p->class->event(p,&e); else i=0;
      if(p->class->destroy) p->class->destroy(p);
      XDeleteContext(display,p->id,window_data_context);
      if(p->flag&WF_OWN_GC) XFreeGC(display,p->gc);
      free(p);
      if(i) goto yield;
      continue;
    }
    if(p->class->event) {
      if(i=p->class->event(p,&e)) {
        yield:
        XFlush(display);
        return i;
      }
    }
  }
  return 0;
}

static const FdClass server_fd_class={
  .in=server_fd_in_event,
  .pri=server_fd_in_event,
};

void set_window_cursor(Window w,int shape) {
  if(!cursors[shape>>1]) cursors[shape>>1]=XCreateFontCursor(display,shape);
  XDefineCursor(display,w,cursors[shape>>1]);
}

static Visual*visual_from_id(VisualID id) {
  XVisualInfo t={.visualid=id};
  int n=0;
  XVisualInfo*vi=XGetVisualInfo(display,VisualIDMask,&t,&n);
  Visual*v;
  if(!n || !vi) errx(1,"No matching visual");
  v=vi->visual;
  XFree(vi);
  return v;
}

Pixel color_from_name(const char*name) {
  XColor c;
  if(privatecolor) {
    return XAllocNamedColor(display,colormap,name,&c,&c)?c.pixel:0;
  } else {
    return XLookupColor(display,colormap,name,&c,&c)?c.pixel:0;
  }
}

void init_window_system(WindowConfig*conf) {
  int x,y,g,sc;
  unsigned int w,h;
  XSizeHints*sh;
  XClassHint clh={(char*)conf->class,(char*)conf->class};
  XWindowAttributes wa;
  display=XOpenDisplay(0);
  if(!display) errx(1,"Cannot open display");
#define X(x) XA_##x=XInternAtom(display,#x,False);
#include "atom.inc"
#undef X
  rootwindow=DefaultRootWindow(display);
  sc=DefaultScreen(display);
  g=x=y=w=h=0;
  if(conf->geom) g=XParseGeometry(conf->geom,&x,&y,&w,&h);
  sh=XAllocSizeHints();
  if(g&(XValue|YValue)) sh->flags|=USPosition|PWinGravity;
  if(g&(WidthValue|HeightValue)) sh->flags|=USSize;
  switch(g&(XNegative|YNegative)) {
    case 0: sh->win_gravity=NorthWestGravity; break;
    case XNegative: sh->win_gravity=NorthEastGravity; break;
    case YNegative: sh->win_gravity=SouthWestGravity; break;
    default: sh->win_gravity=SouthEastGravity; break;
  }
  if(g&XNegative) x+=DisplayWidth(display,sc)-w;
  if(g&YNegative) y+=DisplayHeight(display,sc)-h;
  sh->x=x;
  sh->y=y;
  sh->width=w;
  sh->height=h;
  if(conf->visualid) {
    mainwindow=XCreateWindow(display,rootwindow,x,y,w,h,0,conf->depth,InputOutput,visual_from_id(conf->visualid),0,0);
  } else {
    mainwindow=XCreateSimpleWindow(display,rootwindow,x,y,w,h,0,BlackPixel(display,sc),WhitePixel(display,sc));
  }
  XmbSetWMProperties(display,mainwindow,conf->name,0,conf->argv,conf->argc,sh,0,&clh);
  XGetWindowAttributes(display,mainwindow,&wa);
  if(privatecolor=conf->private_colors) {
    colormap=XCreateColormap(display,mainwindow,wa.visual,AllocNone);
    XSetWindowColormap(display,mainwindow,colormap);
  } else {
    colormap=wa.colormap;
  }
  XFree(sh);
  window_data_context=XUniqueContext();
  server_fd=ConnectionNumber(display);
  poll_fd=epoll_create1(EPOLL_CLOEXEC);
  if(poll_fd==-1) err(1,"Cannot create epoll instance");
  server_fd_status=fd_register(server_fd,&server_fd_class,0);
  fd_configure(server_fd_status,EPOLLIN|EPOLLPRI);
  XMapWindow(display,mainwindow);
  XFlush(display);
}

FdStatus*fd_register(int fd,const FdClass*cl,void*data) {
  struct epoll_event e={.events=0};
  FdStatus*x=calloc(1,sizeof(FdStatus)+cl->data_size);
  if(!x) err(1,"Allocation failed");
  x->class=cl;
  x->id=fd;
  if(cl->data_size) x->data=x->unused; else x->data=data;
  e.data.ptr=x;
  if(epoll_ctl(poll_fd,EPOLL_CTL_ADD,fd,&e)) warn("epoll_ctl (ADD,%d)",fd);
  if(cl->start) cl->start(x);
  return x;
}

void fd_unregister(FdStatus*x) {
  struct epoll_event e;
  if(!x->closed) {
    if(epoll_ctl(poll_fd,EPOLL_CTL_DEL,x->id,&e)) warn("epoll_ctl (DEL,%d)",x->id);
    x->closed=closed_item;
    closed_item=x;
  }
}

void fd_configure(FdStatus*x,uint32_t v) {
  struct epoll_event e={.events=v};
  e.data.ptr=x;
  if(!x->closed && epoll_ctl(poll_fd,EPOLL_CTL_MOD,x->id,&e)) warn("epoll_ctl (MOD,%d)",x->id);
}

void fd_clean(void) {
  FdStatus*x;
  while(closed_item!=&closed_root) {
    x=closed_item;
    closed_item=x->closed;
    free(x);
  }
}

int do_event_loop(int timeout) {
  struct epoll_event e;
  FdStatus*p;
  int i;
  if(display) XFlush(display);
  loop:
  fd_clean();
  i=epoll_wait(poll_fd,&e,1,timeout);
  if(i==-1 && errno==EINTR) goto loop;
  if(i<=0) return i;
  p=e.data.ptr;
  p->events=e.events;
  i=0;
  if((p->events&EPOLLIN) && !p->closed && p->class->in) i|=p->class->in(p);
  if((p->events&EPOLLOUT) && !p->closed && p->class->out) i|=p->class->out(p);
  if((p->events&EPOLLRDHUP) && !p->closed && p->class->rdhup) i|=p->class->rdhup(p);
  if((p->events&EPOLLPRI) && !p->closed && p->class->pri) i|=p->class->pri(p);
  if((p->events&EPOLLERR) && !p->closed && p->class->err) i|=p->class->err(p);
  if((p->events&EPOLLHUP) && !p->closed && p->class->hup) i|=p->class->hup(p);
  if(i) {
    fd_clean();
    return i;
  }
  goto loop;
}

