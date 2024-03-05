
typedef struct {
  Uint16 min_code,max_code,def_code,plane;
  Sint8 xadj,yadj;
  Uint8 xsize,ysize,ascent,descent;
  Uint8*data;
  Uint32*ref;
} Font;

typedef struct {
  Uint16 len;
  Font**fonts;
} FontSet;

typedef struct {
  Uint8 color[4];
  Uint8*pixels;
  Uint32 pitch;
  SDL_Rect box;
  Uint8 bytes;
  Uint8 xscale,yscale;
} FontGC;

const char*load_font(FILE*f,Font*d,const char*(*ext)(Font*,Uint8,Uint8*));
void unload_font(Font*d);
Font*font_in_set(const FontSet*s,Uint16 p);
Font*font_in_set_add(FontSet*s,Uint16 p);
const char*load_font_into_set(FILE*f,FontSet*s,const char*(*ext)(Font*,Uint8,Uint8*),int ov);
Sint32 font_measure_glyph(const Font*d,Uint16 c);
void font_measure_ascii(const Font*d,const Uint8*t,Sint32*r);
void font_measure_tron32(const FontSet*s,Uint32**t,Sint32*r);
void font_measure_tron8(const FontSet*s,Uint8**t,Uint16*p,Sint32*r);
void font_gc_set_surface(FontGC*gc,SDL_Surface*s);
void font_gc_set_address(FontGC*gc,void*addr,Uint32 pitch,Uint8 bytes);
void font_gc_set_color(FontGC*gc,Uint32 color);
void font_gc_set_box(FontGC*gc,SDL_Rect box);
void font_gc_set_scale(FontGC*gc,Uint8 xs,Uint8 ys);
void font_draw_glyph(const Font*d,Uint16 c,Sint32*x,Sint32 y,FontGC*gc);
void font_draw_ascii(const Font*d,const Uint8*t,Sint32*x,Sint32 y,FontGC*gc);
void font_draw_tron32(const FontSet*s,Uint32**t,Sint32*x,Sint32 y,FontGC*gc);
void font_draw_tron8(const FontSet*s,Uint8**t,Uint16*p,Sint32*x,Sint32 y,FontGC*gc);

