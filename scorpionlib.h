
#define SCORPIONLIB_CHARSET_TRON8 0x00
#define SCORPIONLIB_CHARSET_TRON8_LTR 0x00
#define SCORPIONLIB_CHARSET_PC 0x10
#define SCORPIONLIB_CHARSET_TRON8_RTL 0x80

#define SCORPIONLIB_BLOCK_NORMAL 0x00
#define SCORPIONLIB_BLOCK_HEAD1 0x01
#define SCORPIONLIB_BLOCK_HEAD2 0x02
#define SCORPIONLIB_BLOCK_HEAD3 0x03
#define SCORPIONLIB_BLOCK_HEAD4 0x04
#define SCORPIONLIB_BLOCK_HEAD5 0x05
#define SCORPIONLIB_BLOCK_HEAD6 0x06
#define SCORPIONLIB_BLOCK_HYPERLINK 0x08
#define SCORPIONLIB_BLOCK_HYPERLINK_INPUT 0x09
#define SCORPIONLIB_BLOCK_HYPERLINK_INTERACTIVE 0x0A
#define SCORPIONLIB_BLOCK_BLOCKQUOTE 0x0C
#define SCORPIONLIB_BLOCK_PREFORMATTED 0x0D

void scorpionlib_ask(const char*in,char*out,int len,const char*prompt);
void scorpionlib_bad_request(void);
void scorpionlib_begin(const char*type,const char*version);
void scorpionlib_begin_size(char kind,unsigned long size,const char*type,const char*version);
void scorpionlib_error(const char*text);
void scorpionlib_forbid(void);
int scorpionlib_fputc_pc(int code,FILE*file);
int scorpionlib_fputc_tron8(unsigned int*state,unsigned long code,FILE*file);
void scorpionlib_fputs_pc(const char*text,FILE*file);
int scorpionlib_fputs_tron8(unsigned int*state,const char*text,FILE*file);
void scorpionlib_not_found(void);
void scorpionlib_print_block(int type,const char*adata,int alen,const char*bdata,int blen);
int scorpionlib_query(const char*in,char*out,int len);
int scorpionlib_receiver(const char*req,unsigned long*start,unsigned long*end,char*kind);
void scorpionlib_redirect(char perm,const char*target);
int scorpionlib_user_info(const char*req,char*user,int userlen,char*pass,int passlen);
void scorpionlib_write_block(FILE*fp,int type,const char*adata,int alen,const char*bdata,int blen);

// cat scorpionlib.c | sed -rn '/^[^ ]/s/ \{$/;/p'
