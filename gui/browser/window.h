
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
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

typedef struct FdClass FdClass;
typedef struct FdStatus FdStatus;
typedef struct WindowClass WindowClass;
typedef struct WindowStatus WindowStatus;

struct FdClass {
  void*misc;
  size_t data_size;
  void(*start)(FdStatus*);
  int(*in)(FdStatus*);
  int(*out)(FdStatus*);
  int(*rdhup)(FdStatus*);
  int(*pri)(FdStatus*);
  int(*err)(FdStatus*);
  int(*hup)(FdStatus*);
};

struct FdStatus {
  const FdClass*class;
  int id;
  void*data;
  uint32_t events;
  FdStatus*closed;
  char unused[0] __attribute__((aligned(__BIGGEST_ALIGNMENT__)));
};

struct WindowClass {
  void*misc;
  size_t data_size;
  long mask;
  void(*create)(WindowStatus*);
  void(*destroy)(WindowStatus*);
  int(*event)(WindowStatus*,XEvent*);
  int(*configure)(WindowStatus*,XRectangle*);
  uint32_t flag;
};

struct WindowStatus {
  const WindowClass*class;
  Window id;
  void*data;
  GC gc;
  uint32_t flag;
  char unused[0] __attribute__((aligned(__BIGGEST_ALIGNMENT__)));
};

#define WF_VALUE         0x00000001
#define WF_OWN_GC        0x00000002
#define WF_DESTROYED     0x00000004

extern Display*display;
extern Window rootwindow;
extern Window mainwindow;
extern ColorConfig colors;

void init_window_system(WindowConfig*conf);
void set_window_cursor(Window w,int shape);
Pixel color_from_name(const char*name);

FdStatus*fd_register(int fd,const FdClass*cl,void*data);
void fd_unregister(FdStatus*x);
void fd_configure(FdStatus*x,uint32_t v);
void fd_clean(void);
int do_event_loop(int timeout);

