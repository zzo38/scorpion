
#include <stdint.h>
#include <time.h>

// Universal types
#define ASN1_EOC 0
#define ASN1_END_OF_CONTENT 0
#define ASN1_BOOLEAN 1
#define ASN1_INTEGER 2
#define ASN1_BIT_STRING 3
#define ASN1_OCTET_STRING 4
#define ASN1_NULL 5
#define ASN1_OBJECT_IDENTIFIER 6
#define ASN1_OID 6
#define ASN1_OBJECT_DESCRIPTOR 7
#define ASN1_EXTERNAL 8
#define ASN1_REAL 9
#define ASN1_FLOAT 9
#define ASN1_ENUMERATED 10
#define ASN1_EMBEDDED_PDV 11
#define ASN1_UTF8STRING 12
#define ASN1_UTF8_STRING 12
#define ASN1_RELATIVE_OID 13
#define ASN1_TIME 14
#define ASN1_SEQUENCE 16
#define ASN1_SEQUENCE_OF 16
#define ASN1_SET 17
#define ASN1_SET_OF 17
#define ASN1_NUMERICSTRING 18
#define ASN1_NUMERIC_STRING 18
#define ASN1_PRINTABLESTRING 19
#define ASN1_PRINTABLE_STRING 19
#define ASN1_T61STRING 20
#define ASN1_T61_STRING 20
#define ASN1_TELETEXSTRING 20
#define ASN1_TELETEX_STRING 20
#define ASN1_VIDEOTEXSTRING 21
#define ASN1_VIDEOTEX_STRING 21
#define ASN1_IA5STRING 22
#define ASN1_IA5_STRING 22
#define ASN1_ASCII_STRING 22
#define ASN1_UTCTIME 23
#define ASN1_UTC_TIME 23
#define ASN1_GENERALIZEDTIME 24
#define ASN1_GENERALIZED_TIME 24
#define ASN1_GRAPHICSTRING 25
#define ASN1_GRAPHIC_STRING 25
#define ASN1_VISIBLESTRING 26
#define ASN1_VISIBLE_STRING 26
#define ASN1_GENERALSTRING 27
#define ASN1_GENERAL_STRING 27
#define ASN1_UNIVERSALSTRING 28
#define ASN1_UNIVERSAL_STRING 28
#define ASN1_UTF32_STRING 28
#define ASN1_UCS4_STRING 28
#define ASN1_ISO10646_STRING 28
#define ASN1_CHARACTER_STRING 29
#define ASN1_BMPSTRING 30
#define ASN1_BMP_STRING 30
#define ASN1_UTF16_STRING 30
#define ASN1_UCS2_STRING 30
#define ASN1_DATE 31
#define ASN1_TIME_OF_DAY 32
#define ASN1_DATE_TIME 33
#define ASN1_DURATION 34
#define ASN1_OID_IRI 35
#define ASN1_RELATIVE_OID_IRI 36

// Classes
#define ASN1_UNIVERSAL 0
#define ASN1_APPLICATION 1
#define ASN1_CONTEXT_SPECIFIC 2
#define ASN1_PRIVATE 3

// Results
#define ASN1_OK 0
#define ASN1_ERROR 1
#define ASN1_IMPROPER_TYPE 2
#define ASN1_IMPROPER_VALUE 3
#define ASN1_TOO_SHORT 4
#define ASN1_TOO_SMALL 4
#define ASN1_IMPROPER_ENCODING 5
#define ASN1_TOO_BIG 6
#define ASN1_OVERFLOW 6
#define ASN1_IMPROPER_MODE 7
#define ASN1_IMPROPER_ARGUMENT 8

// Flags
#define ASN1_SORT 0x01
#define ASN1_UNIQ 0x02
#define ASN1_INDEFINITE 0x04
#define ASN1_ONCE 0x08

// Others
#define ASN1_AUTO 0 // means use the existing universal or explicit type instead of an implicit type

typedef struct {
  const uint8_t*data;
  size_t length;
  uint32_t type;
  uint8_t class,constructed,own;
} ASN1;

typedef struct {
  int16_t zone; // measured in minutes
  int16_t year;
  uint8_t month,day,hours,minutes,seconds;
  uint32_t nano;
} ASN1_DateTime;

typedef struct ASN1_Encoder ASN1_Encoder;

int asn1_construct(ASN1_Encoder*enc,uint8_t class,uint32_t type,uint8_t mode);
ASN1_Encoder*asn1_create_encoder(FILE*file);
FILE*asn1_current_file(ASN1_Encoder*enc);
int asn1_date_to_time(const ASN1_DateTime*in,time_t*out,uint32_t*nano);
int asn1_decode_date(const ASN1*asn,uint32_t type,ASN1_DateTime*out);
int asn1_decode_int8(const ASN1*asn,uint32_t type,int8_t*out);
int asn1_decode_int16(const ASN1*asn,uint32_t type,int16_t*out);
int asn1_decode_int32(const ASN1*asn,uint32_t type,int32_t*out);
int asn1_decode_int64(const ASN1*asn,uint32_t type,int64_t*out);
int asn1_decode_time(const ASN1*asn,uint32_t type,int16_t zone,time_t*out,uint32_t*nano);
int asn1_decode_uint8(const ASN1*asn,uint32_t type,uint8_t*out);
int asn1_decode_uint16(const ASN1*asn,uint32_t type,uint16_t*out);
int asn1_decode_uint32(const ASN1*asn,uint32_t type,uint32_t*out);
int asn1_decode_uint64(const ASN1*asn,uint32_t type,uint64_t*out);
int asn1_distinguished_parse(const uint8_t*data,size_t length,ASN1*out,size_t*next);
int asn1_encode(ASN1_Encoder*enc,const ASN1*value);
int asn1_encode_boolean(ASN1_Encoder*enc,int value);
int asn1_encode_c_string(ASN1_Encoder*enc,uint32_t type,const char*text);
int asn1_encode_date(ASN1_Encoder*enc,uint32_t type,const ASN1_DateTime*x);
int asn1_encode_int8(ASN1_Encoder*enc,int8_t value);
int asn1_encode_int16(ASN1_Encoder*enc,int16_t value);
int asn1_encode_int32(ASN1_Encoder*enc,int32_t value);
int asn1_encode_int64(ASN1_Encoder*enc,int64_t value);
int asn1_encode_oid(ASN1_Encoder*enc,const char*t);
int asn1_encode_time(ASN1_Encoder*enc,uint32_t type,time_t value,uint32_t nano,int16_t zone);
int asn1_encode_uint16(ASN1_Encoder*enc,uint16_t value);
int asn1_encode_uint32(ASN1_Encoder*enc,uint32_t value);
int asn1_encode_uint64(ASN1_Encoder*enc,uint64_t value);
int asn1_end(ASN1_Encoder*enc);
int asn1_explicit(ASN1_Encoder*enc,uint8_t class,uint32_t type);
int asn1_finish_encoder(ASN1_Encoder*enc);
int asn1_flush(ASN1_Encoder*enc);
int asn1_from_c_string(uint8_t class,uint32_t type,const char*data,ASN1*out);
int asn1_get_bit(const ASN1*asn,uint32_t type,uint64_t which,int*out);
int asn1_implicit(ASN1_Encoder*enc,uint8_t class,uint32_t type);
int asn1_make_oid(const char*text,ASN1*out);
int asn1_make_static_oid(const char*text,uint8_t*buf,size_t maxlen,ASN1*out);
int asn1_parse(const uint8_t*data,size_t length,ASN1*out,size_t*next);
int asn1_primitive(ASN1_Encoder*enc,uint8_t class,uint32_t type,const uint8_t*data,size_t length);
int asn1_print_decimal_oid(const ASN1*data,uint32_t type,FILE*stream);
int asn1_time_to_date(time_t in,uint32_t nano,ASN1_DateTime*out);
int asn1_wrap(ASN1_Encoder*enc);
void asn1_write_length(uint64_t length,FILE*stream);
void asn1_write_type(uint8_t constructed,uint8_t class,uint32_t type,FILE*stream);

#define asn1__decode_number__(D,E,F) __builtin_choose_expr(__builtin_types_compatible_p(typeof(D),E*),asn1_decode_##F,
#define asn1_decode_number(A,B,C) (( \
  asn1__decode_number__(C,int8_t,int8) \
  asn1__decode_number__(C,int16_t,int16) \
  asn1__decode_number__(C,int32_t,int32) \
  asn1__decode_number__(C,int64_t,int64) \
  asn1__decode_number__(C,uint8_t,uint8) \
  asn1__decode_number__(C,uint16_t,uint16) \
  asn1__decode_number__(C,uint32_t,uint32) \
  asn1__decode_number__(C,uint64_t,uint64) \
  (void)0 )))))))))(A,B,C) )

#define asn1__encode_number__(D,E,F) __builtin_choose_expr(__builtin_types_compatible_p(typeof(D),E),asn1_encode_##F,
#define asn1_encode_integer(A,C) (( \
  asn1__encode_number__(C,int8_t,int8) \
  asn1__encode_number__(C,int16_t,int16) \
  asn1__encode_number__(C,int32_t,int32) \
  asn1__encode_number__(C,int64_t,int64) \
  asn1__encode_number__(C,uint8_t,uint16) \
  asn1__encode_number__(C,uint16_t,uint16) \
  asn1__encode_number__(C,uint32_t,uint32) \
  asn1__encode_number__(C,uint64_t,uint64) \
  (void)0 )))))))))(A,C) )

