FILE*open_base64_dec(FILE*f,char autoclose);
FILE*open_base64_enc(FILE*f,uint8_t maxwidth,FILE*echo,char autoclose);
FILE*open_base64_pem_dec(FILE*f,const char*text,int(*filter)(FILE*,const char*,const char*),char autoclose);
#define BASE64_FILTER_MATCH 1
#define BASE64_FILTER_LAST 2
