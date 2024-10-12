
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/cursorfont.h>

typedef unsigned long Pixel;

#define X(x) extern Atom XA_##x;
#include "atom.inc"
#undef X

typedef struct {
  const char*geom;
  const char*name;
  const char*class;
  int argc;
  char**argv;
  VisualID visualid;
  unsigned int depth;
  char private_colors;
} WindowConfig;

typedef struct {
#define B(n,t,d)
#define C(n,t,d) Pixel n;
#define I(n,t,d)
#define S(n,t,d)
#include "config.inc"
#undef B
#undef C
#undef I
#undef S
} ColorConfig;

extern Display*display;
extern Window rootwindow;
extern Window mainwindow;
extern ColorConfig colors;

void init_window_system(WindowConfig*conf);
void set_window_cursor(Window w,int shape);

