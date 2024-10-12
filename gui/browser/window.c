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
  XMapWindow(display,mainwindow);
  XFlush(display);
}
