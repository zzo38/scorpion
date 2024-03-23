#ifndef QUARKS_H_INCLUDED
#define QUARKS_H_INCLUDED

#ifdef MAIN_PROGRAM
#define Q(z) #z,
static const char*const quarkslist[]={
#include "quarks.h"
#undef Q
0};
#endif

enum {
  Q__nullq__=0,
  Q__anyq__=1,
#define Q(z) Q_##z,
#include "quarks.h"
#undef Q
};

#define Q(z)
#endif

// Display settings
  Q(screen)
  Q(width)
  Q(height)

#undef Q
