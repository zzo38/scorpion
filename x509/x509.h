#include <stdio.h>
#include "asn1.h"

// Option flags
#define X509_IGNORE_NOT_VALID_BEFORE 0x0001
#define X509_IGNORE_NOT_VALID_AFTER 0x0002
#define X509_IGNORE_SIGNATURE 0x0004
#define X509_NO_STANDARD_EXTENSIONS 0x0008
#define X509_ASSUME_NOT_CA 0x0010
#define X509_IGNORE_EXTENSIONS 0x0020
#define X509_ROOT_LAST 0x0040
#define X509_REVERSE_AUTHORITY 0x0080
#define X509_NO_SIGNATURE 0x0100
#define X509_USER1_OPTION 0x4000
#define X509_USER2_OPTION 0x8000

// Extension flags
#define X509_IGNORE_UNLESS_CRITICAL 0x01
#define X509_REQUIRE_EXTENSION_END 0x02
#define X509_REQUIRE_EXTENSION_CA 0x04
#define X509_SECOND_PHASE 0x08
#define X509_REJECT_IF_CRITICAL 0x10

// Errors
#define X509_OK 0
#define X509_IMPROPER_TYPE ASN1_IMPROPER_TYPE
#define X509_IMPROPER_VALUE ASN1_IMPROPER_VALUE
#define X509_NOT_ENOUGH_FIELDS ASN1_DONE
#define X509_ERROR 33
#define X509_EXPIRED 34
#define X509_NOT_VALID_YET 35
#define X509_NAME_MISMATCH 36
#define X509_IMPROPER_FORMAT 37
#define X509_EXT_ERROR 38
#define X509_WRONG_SIGNATURE 39
#define X509_UNKNOWN_SIGNATURE 40
#define X509_UNKNOWN_AUTHORITY 41
#define X509_UNKNOWN_EXTENSION 42
#define X509_REPEATED_EXTENSION 43
#define X509_REVOKED 44
#define X509_REJECTED_EXTENSION 45
#define X509_DEFER_EXTENSION 46
#define X509_MISSING_EXTENSION 47
#define X509_ACCESS_DENIED 48
#define X509_NOT_IMPLEMENTED 49
#define X509_IMPROPER_STEP 50
#define X509_IMPROPER_KEY 51

// Key usage
#define X509_KEYUSAGE_DIGITAL_SIGNATURE 0x8000
#define X509_KEYUSAGE_NON_REPUDIATION 0x4000
#define X509_KEYUSAGE_KEY_ENCIPHERMENT 0x2000
#define X509_KEYUSAGE_DATA_ENCIPHERMENT 0x1000
#define X509_KEYUSAGE_KEY_AGREEMENT 0x0800
#define X509_KEYUSAGE_KEY_CERT_SIGN 0x0400
#define X509_KEYUSAGE_CRL_SIGN 0x0200
#define X509_KEYUSAGE_ENCIPHER_ONLY 0x0100
#define X509_KEYUSAGE_DECIPHER_ONLY 0x0080
#define X509_KEYUSAGE_UNRESTRICTED 0x0001

// Extended key usage
#define X509_EKU_TLS_SERVER_AUTH 0x00000002
#define X509_EKU_TLS_CLIENT_AUTH 0x00000004
#define X509_EKU_SIGN_EXEC 0x00000008
#define X509_EKU_EMAIL 0x00000010
#define X509_EKU_TIMESTAMP 0x00000100
#define X509_EKU_OCSP 0x00000200
#define X509_EKU_SSH_CLIENT_AUTH 0x00200000
#define X509_EKU_SSH_SERVER_AUTH 0x00400000

// Extended key usage flags
#define X509_EKUF_ONE_OF 0x0001
#define X509_EKUF_ALL_OF 0x0002
#define X509_EKUF_EXPLICIT 0x0004

// Revocation reason
#define X509_REASON_UNSPECIFIED 0
#define X509_REASON_KEY_COMPROMISE 1
#define X509_REASON_CA_COMPROMISE 2
#define X509_REASON_AFFILIATION_CHANGED 3
#define X509_REASON_SUPERSEDED 4
#define X509_REASON_CESSATION_OF_OPERATION 5
#define X509_REASON_CERTIFICATE_HOLD 6
#define X509_REASON_REMOVE_FROM_CRL 8
#define X509_REASON_NOT_REVOKED 8
#define X509_REASON_PRIVILEGE_WITHDRAWN 9
#define X509_REASON_AA_COMPROMISE 10
#define X509_REASON_WEAK_KEY 11

typedef struct X509_Algorithm X509_Algorithm;
typedef struct X509_Chain X509_Chain;
typedef struct X509_Encoder X509_Encoder;
typedef struct X509_Extension X509_Extension;
typedef struct X509_ExtraData X509_ExtraData;
typedef struct X509_Info X509_Info;
typedef struct X509_Options X509_Options;

struct X509_Algorithm {
  void*userdata;
  const uint8_t*s_oid;
  size_t s_oidlen;
  const uint8_t*k_oid;
  size_t k_oidlen;
  int(*check_signature)(const X509_Algorithm*al,const X509_Info*info,const uint8_t*data,size_t len,const ASN1_Value*publickey,const ASN1_Value*algorithm,const ASN1_Value*signature);
  int(*make_public_key)(const X509_Algorithm*al,const X509_Info*info,void*privatekey,const ASN1_Value*keyalgorithm,ASN1_Encoder*encoder);
  int(*make_signature)(const X509_Algorithm*al,const X509_Info*info,const uint8_t*data,size_t len,void*privatekey,const ASN1_Value*algorithm,ASN1_Value*signature);
};

struct X509_Chain {
  ASN1_Value*item;
  uint16_t count;
};

struct X509_Extension {
  int(*call)(const X509_Extension*ext,X509_Info*info,const X509_Options*option,const ASN1_Value*data,uint8_t crit);
  void*userdata;
  const uint8_t*oid;
  size_t oidlen;
  uint8_t flag;
};

struct X509_Info {
  ASN1_Value subject,subject_id,issuer,issuer_id,publickey;
  time_t starts,expires;
  uint16_t count;
  X509_ExtraData*in;
  X509_ExtraData*out;
  int8_t phase;
};

struct X509_Options {
  void*userdata;
  int(*begin_chain)(const X509_Chain*chain,const X509_Options*option,X509_ExtraData*extra);
  int(*check_info)(const X509_Info*info,void*userdata);
  int(*check_revoked)(const X509_Info*info,const X509_Options*option,const ASN1_Value*certificate,const ASN1_Value*serial);
  int(*check_signature)(const X509_Info*info,const uint8_t*data,size_t len,const ASN1_Value*publickey,const ASN1_Value*algorithm,const ASN1_Value*signature);
  int(*end_chain)(const X509_Chain*chain,const X509_Options*option,X509_ExtraData*extra,X509_Info*info,int status);
  int(*find_authority)(const X509_Info*info,const ASN1_Value*certificate);
  int(*find_issuer)(const X509_Info*info,const ASN1_Value*certificate,ASN1_Value*out);
  int(*find_root)(const X509_Info*info,const ASN1_Value*certificate);
  int(*make_signature)(const X509_Info*info,const uint8_t*data,size_t len,void*privatekey,const ASN1_Value*algorithm,ASN1_Value*signature);
  int(*mid_chain)(const X509_Chain*chain,const X509_Options*option,X509_ExtraData*extra,X509_Info*info);
  int(*set_serial)(const X509_Info*info,void*userdata);
  const X509_Extension*extlist;
  uint32_t extcount;
  time_t now;
  uint16_t flag;
};

int x509_accept_any_self_signed(const X509_Info*info,const ASN1_Value*certificate);
int x509_check_signature(const X509_Info*info,const uint8_t*data,size_t len,const ASN1_Value*publickey,const ASN1_Value*algorithm,const ASN1_Value*signature);
void x509_extra_delete(X509_ExtraData*extra,const void*key);
void x509_extra_destroy(X509_ExtraData*extra);
void*x509_extra_destructor(X509_ExtraData*extra,const void*key);
void*x509_extra_find(X509_ExtraData*extra,const void*key,void(*destructor)(void*),const void*data,size_t size);
X509_ExtraData*x509_extra_mirror(const X509_ExtraData*orig);
X509_ExtraData*x509_extra_new(void);
int x509_find_algorithm(const X509_Info*info,const ASN1_Value*publickey,const ASN1_Value*algorithm,const X509_Algorithm**result);
uint16_t x509_get_key_usage(const X509_Info*info);
int x509_make_signature(const X509_Info*info,const uint8_t*data,size_t len,void*privatekey,const ASN1_Value*algorithm,ASN1_Value*signature);
X509_Encoder*x509_new_certificate(const X509_Info*info,const X509_Options*option,ASN1_Encoder*out);
int x509_read_certificate(const ASN1_Value*cert,const X509_Options*option,X509_ExtraData*extra,X509_Info*info);
int x509_read_chain(const X509_Chain*chain,const X509_Options*option,X509_ExtraData*extra,X509_Info*info);
void x509_reset_info(X509_Info*info);
int x509_set_alglist(X509_ExtraData*info,X509_Options*option,X509_Algorithm*alglist,uint32_t algcount);
int x509_set_needed_extended_key_usage(X509_ExtraData*ex,uint32_t usage,uint32_t flag);
int x509_set_needed_key_usage(X509_ExtraData*ex,uint16_t usage);
int x509_set_time(X509_ExtraData*ex,time_t now);
int x509_sign_certificate(const X509_Info*info,const X509_Options*option,const ASN1_Value*tbs,void*privatekey,ASN1_Encoder*enc);
void x509_sort_alglist(X509_Algorithm*alglist,uint32_t algcount);
void x509_sort_extlist(X509_Extension*extlist,uint32_t extcount);
