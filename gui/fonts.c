#if 0
gcc -s -O2 -c -fwrapv -Wno-unused-result fonts.c `sdl-config --cflags`
exit
#endif

#include "SDL.h"
#include "fonts.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char*load_font(FILE*f,Font*d,const char*(*ext)(Font*,Uint8,Uint8*)) {
  FILE*o;
  size_t siz=0;
  Uint8 b[64];
  Uint8 h[8];
  Uint32 nchars;
  Uint32*q;
  const char*e;
  int c,n;
  if(fread(b,1,32,f)!=32) return "Unrecognized file format";
  if(memcmp(b,"\xFF\x01\x73\x63\x6F\x62\x66\x00",8)) return "Unrecognized file format";
  d->xsize=b[8]; d->ysize=b[9];
  d->xadj=b[10]-128; d->yadj=b[11]-128;
  d->ascent=b[14]; d->descent=b[15];
  d->min_code=0xFFFF; d->max_code=0x0000;
  d->def_code=b[12]+(b[13]<<8);
  d->plane=b[18]+(b[19]<<8);
  nchars=b[16]+(b[17]<<8)+1;
  d->ref=calloc(sizeof(Uint32),0x10000);
  d->data=0;
  if(!d->ref) return "Memory allocation error";
  o=open_memstream((char**)(&d->data),&siz);
  if(!o) {
    free(d->ref);
    d->ref=0;
    return "Error with open_memstream";
  }
  h[1]=d->xsize^0x80;
  memcpy(h+4,b+8,4);
  fputc(0,o);
  for(;;) {
    c=fgetc(f);
    if(c==EOF) {
      fclose(o);
      free(d->data);
      free(d->ref);
      d->data=0;
      d->ref=0;
      return ferror(f)?"Error reading file":"Unexpected end of file";
    } else if(c==0x00) {
      fread(h+1,1,7,f);
      goto glyph;
    } else if(c==0x01) {
      fread(h+2,1,2,f);
      glyph:
      d->ref[c=h[2]+(h[3]<<8)]=ftell(o);
      if(d->min_code>c) d->min_code=c;
      if(d->max_code<c) d->max_code=c;
      fputc(h[1],o);
      fwrite(h+4,1,4,o);
      n=((h[4]+7)>>3)*h[5];
      while(n) {
        c=(n>64?64:n);
        fread(b,1,c,f);
        fwrite(b,1,c,o);
        n-=c;
      }
    } else if(c==0xF0) {
      break;
    } else if(c&0x80) {
      fread(b,1,c&15,f);
      if(ext && (e=ext(d,c,b))) {
        fclose(o);
        free(d->data);
        free(d->ref);
        d->data=0;
        d->ref=0;
        return e;
      }
    } else {
      fclose(o);
      free(d->data);
      free(d->ref);
      d->data=0;
      d->ref=0;
      return "Invalid command";
    }
  }
  fclose(o);
  if(!d->data) {
    free(d->ref);
    d->ref=0;
    return "Memory allocation error";
  }
  if(d->max_code!=0xFFFF || d->min_code) {
    q=malloc(sizeof(Uint32)*(d->max_code-d->min_code+1));
    if(!q) {
      free(d->ref);
      free(d->data);
      d->data=0;
      d->ref=0;
      return "Memory allocation error";
    }
    memcpy(q,d->ref+d->min_code,sizeof(Uint32)*(d->max_code-d->min_code+1));
    free(d->ref);
    d->ref=q;
  }
  return 0;
}

void unload_font(Font*d) {
  free(d->data);
  free(d->ref);
  d->data=0;
  d->ref=0;
}

Font*font_in_set(const FontSet*s,Uint16 p) {
  if((p&0xFF)<0x21 || (p&0xFF)>0xFD || (p&0xFF)==0x7F) return 0;
  if(p&0x80) p--;
  p=((p&0xFF)-0x21)+(p>>8)*220;
  if(p>=s->len) return 0;
  return s->fonts[p];
}

Font*font_in_set_add(FontSet*s,Uint16 p) {
  if((p&0xFF)<0x21 || (p&0xFF)>0xFD || (p&0xFF)==0x7F) return 0;
  if(p&0x80) p--;
  p=((p&0xFF)-0x21)+(p>>8)*220;
  if(p>=s->len) {
    Font**q=realloc(s->fonts,sizeof(Font*)*(p+1));
    if(!q) return 0;
    s->fonts=q;
    while(s->len<=p) q[s->len++]=0;
  }
  if(!s->fonts[p]) {
    Font*f=malloc(sizeof(Font));
    if(!f) return 0;
    memset(f,0,sizeof(Font));
    s->fonts[p]=f;
  }
  return s->fonts[p];
}

const char*load_font_into_set(FILE*f,FontSet*s,const char*(*ext)(Font*,Uint8,Uint8*),int ov) {
  Font d;
  Font*p;
  const char*e;
  d.data=0;
  d.ref=0;
  if(e=load_font(f,&d,ext)) return e;
  p=font_in_set_add(s,d.plane);
  if(!p) {
    unload_font(&d);
    return "Cannot get font from set";
  }
  if(p->data) {
    if(!ov) {
      unload_font(&d);
      return "Font already loaded";
    }
    unload_font(p);
  }
  *p=d;
  return 0;
}

Sint32 font_measure_glyph(const Font*d,Uint16 c) {
  if(c<d->min_code || c>d->max_code || !d->ref[c-d->min_code]) c=d->def_code;
  if(c<d->min_code || c>d->max_code) return 0;
  return d->data[d->ref[c-d->min_code]]-128;
}

void font_measure_ascii(const Font*d,const Uint8*t,Sint32*r) {
  while(*t) *r+=font_measure_glyph(d,*t++);
}

void font_measure_tron32(const FontSet*s,Uint32**t,Sint32*r) {
  Font*f=0;
  Uint16 p=0;
  while(**t) {
    Uint32 c=**t;
    if(c<0x212121 || c>0xFFFDFDFD || (c&0xFF)==0x7F || (c&0xFF)<0x21) return;
    if(p!=(c>>16)) f=font_in_set(s,p=c>>16);
    if(f) *r+=font_measure_glyph(f,c&0xFFFF);
    ++*t;
  }
}

void font_measure_tron8(const FontSet*s,Uint8**t,Uint16*p,Sint32*r) {
  Font*f=font_in_set(s,*p);
  while(**t) {
    Uint16 c=**t;
    if(c<0x21 || c==0x7F || c==0xFF) return;
    if(c==0xFE) {
      *p=0;
      do c=*++*t; while(c==0xFE && (*p+=0x100));
      if(c>0xFD || c==0x7F || c<0x21) return;
      f=font_in_set(s,*p+=c);
      ++*t;
    } else {
      c=(c<<8)|(*++*t);
      if((c&0xFF)<0x21 || (c&0xFF)==0x7F || (c&0xFF)>0xFD) return;
      if(f) *r+=font_measure_glyph(f,c);
      ++*t;
    }
  }
}

void font_gc_set_surface(FontGC*gc,SDL_Surface*s) {
  gc->pitch=s->pitch;
  gc->pixels=s->pixels;
  gc->bytes=s->format->BytesPerPixel;
  gc->box=s->clip_rect;
}

void font_gc_set_address(FontGC*gc,void*addr,Uint32 pitch,Uint8 bytes) {
  gc->pixels=addr;
  gc->pitch=pitch;
  gc->bytes=bytes;
}

void font_gc_set_color(FontGC*gc,Uint32 color) {
  switch(gc->bytes) {
    case 1: *gc->color=color; break;
    case 2: *(Uint16*)gc->color=color; break;
    case 4: *(Uint32*)gc->color=color; break;
  }
}

void font_gc_set_box(FontGC*gc,SDL_Rect box) {
  gc->box=box;
}

void font_draw_glyph(const Font*d,Uint16 c,Sint32*x,Sint32 y,FontGC*gc) {
  Uint8*pp;
  Uint8*p;
  const Uint8*dd;
  int xx,yy;
  int x0=gc->box.x;
  int y0=gc->box.y;
  int x1=gc->box.x+gc->box.w-1;
  int y1=gc->box.y+gc->box.h-1;
  int u,v,w,z;
  if(c<d->min_code || c>d->max_code || !d->ref[c-d->min_code]) c=d->def_code;
  if(c<d->min_code || c>d->max_code) return;
  dd=d->data+d->ref[c-d->min_code];
  xx=*x+dd[3]-128; yy=y+dd[4]-dd[2]-128;
  *x+=*dd-128;
  u=(dd[1]+7)>>3; v=dd[2]; w=dd[1];
  dd+=5;
  if(yy<y0) {
    dd+=u*(y0-yy);
    v-=(y0-yy);
    yy=y0;
  }
  pp=gc->pixels+gc->pitch*yy+gc->bytes*xx;
  while(v-- && yy<=y1) {
    p=pp;
    for(z=0;z<w;z++) if(xx+z>=x0 && xx+z<=x1 && (dd[z>>3]&(0x80>>(z&7)))) memcpy(pp+z*gc->bytes,gc->color,gc->bytes);
    pp+=gc->pitch;
    dd+=u;
  }
}

void font_draw_ascii(const Font*d,const Uint8*t,Sint32*x,Sint32 y,FontGC*gc) {
  while(*t) font_draw_glyph(d,*t++,x,y,gc);
}

void font_draw_tron32(const FontSet*s,Uint32**t,Sint32*x,Sint32 y,FontGC*gc) {
  Font*f=0;
  Uint16 p=0;
  while(**t) {
    Uint32 c=**t;
    if(c<0x212121 || c>0xFFFDFDFD || (c&0xFF)==0x7F || (c&0xFF)<0x21) return;
    if(p!=(c>>16)) f=font_in_set(s,p=c>>16);
    if(f) font_draw_glyph(f,c&0xFFFF,x,y,gc);
    ++*t;
  }
}

void font_draw_tron8(const FontSet*s,Uint8**t,Uint16*p,Sint32*x,Sint32 y,FontGC*gc) {
  Font*f=font_in_set(s,*p);
  while(**t) {
    Uint16 c=**t;
    if(c<0x21 || c==0x7F || c==0xFF) return;
    if(c==0xFE) {
      *p=0;
      do c=*++*t; while(c==0xFE && (*p+=0x100));
      if(c>0xFD || c==0x7F || c<0x21) return;
      f=font_in_set(s,*p+=c);
      ++*t;
    } else {
      c=(c<<8)|(*++*t);
      if((c&0xFF)<0x21 || (c&0xFF)==0x7F || (c&0xFF)>0xFD) return;
      if(f) font_draw_glyph(f,c,x,y,gc);
      ++*t;
    }
  }
}

