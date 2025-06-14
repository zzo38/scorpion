/*
 There is no implemented; this is just ideas of a possible API, and is incomplete.
 It also might be changed in future, for various reasons. (Anyone who can comment
 about this should do so, in order to improve this, and then hopefully it will be
 possible to make a implementation.)

 Many functions are currently missing, such as:
  - Set the public and private keys
  - When accepting a connection, to handle SNI and send a certificate
  - When making a connection, to set the certificate
  - The list of what the valid options are
 (There may be others as well, that are missed.)
*/

typedef struct TLS_CertificateList TLS_CertificateList;
typedef struct TLS_Connection TLS_Connection;
typedef struct TLS_Options TLS_Options;

typedef struct TLS_Data {
  uint8_t*data;
  size_t len;
} TLS_Data;

typedef union TLS_Union {
  TLS_Data data;
  int64_t integer;
  void*pointer;
} TLS_Union;

// **** Setting up options ****

void TLS_set_allocation(void*(*f)(void*,size_t));
// Set the function to use for allocating memory.

TLS_Options*TLS_alloc_options(const TLS_Options*prototype);
// Allocate a TLS_Options object. If you specify a prototype, the values are copied; if the
// prototype is null, then the default values will be used (which may change in later versions
// of the software).

void TLS_free_options(TLS_Options*option);
// Deallocate a TLS_Options object.

int TLS_load_options(TLS_Options*option,FILE*in,FILE*err_out);
// Load options from a file. If err_out is null then error messages are not sent.
// Any options that are already set will be overridden by the options in the file.
// Returns zero if OK or nonzero if error (whether or not err_out is null).

int TLS_set_option(TLS_Options*option,int key,const TLS_Union*value);
// Set a specific option.

// **** Creating connections ****

// For these functions that accept a file descriptor, you may safely pass -1 in which case it
// will do nothing and will return null; errno is unchanged in this case.

TLS_Connection*TLS_direct(int fd,const TLS_Options*option);
// Creates a TLS_Connection object which directly communicates with the fd, without encryption.
// The options may be null to use the default options, but most options are not used anyways.

TLS_Connection*TLS_server(int fd,const TLS_Options*option,int mandatory);
// Creates a TLS_Connection object for a server. The "mandatory" flag is nonzero if encryption
// is mandatory, or if the server sends first; it can be zero if the client sends first and can
// connect with or without encryption and the server will use the client's preference.

TLS_Connection*TLS_client(int fd,const TLS_Options*option,const char*name);
// Creates a TLS_Connection object for a client. Optionally specify the name for use with SNI.
// This will immediately send a client hello message to the server.

// **** Using connections to send/receive data ****

ssize_t TLS_recv(TLS_Connection*cd,void*buf,size_t len,int flags);
// Like recv but uses TLS_Connection instead of a file descriptor.

ssize_t TLS_send(TLS_Connection*cd,const void*buf,size_t len,int flags);
// Like send but uses TLS_Connection instead of a file descriptor.

ssize_t TLS_uncork(TLS_Connection*cd);
// Forces data to be sent even if MSG_MORE or TCP_CORK is used.

// **** Other functions with connections ****

uint32_t TLS_ready(TLS_Connection*cd);
// Tells you whether or not the connection is ready, and other status flags such as whether
// or not the connection is encrypted.

FILE*TLS_open(TLS_Connection*cd,const char*mode);
// Creates a FILE object from a TLS_Connection. Reading will receive data and writing will send.
// Calling fclose on the FILE object will also call TLS_close on it.

int TLS_getfd(TLS_Connection*cd);
// Tells you the underlying file descriptor for a connection, or -1 if there isn't any.

int TLS_close(TLS_Connection*cd);
// Closes a connection including the socket.

void TLS_free(TLS_Connection*cd);
// Deallocates a TLS_Connection object without writing any data or affecting the socket in any way.

int TLS_getsockopt(TLS_Connection*cd,int level,int optname,void*optval,socklen_t optlen);
// Get options from the underlying socket.

int TLS_setsockopt(TLS_Connection*cd,int level,int optname,const void*optval,socklen_t optlen);
// Set options in the underlying socket.

// **** Certificate verification ****

uint32_t TLS_certlist_count(const TLS_CertificateList*list);
// Tell you how many certificates are in a certificate list.

TLS_Data*TLS_certlist_get(const TLS_CertificateList*list,uint32_t item);
// Retrieves the contents of a certificate in DER encoding.

uint16_t TLS_certlist_type(const TLS_CertificateList*list,uint32_t item);
// Tell you the certificate type (X.509 certificate or public key only).

void TLS_set_cert_verify_callback(TLS_Options*option,int(*cb)(TLS_Connection*,const TLS_CertificateList*,void*),void*userdata);
// Set the callback function for verifying certificates from the other side. If the callback
// returns a negative number, or if the callback function does not extract the public key and
// tell the TLS library about it, then the connection will be an error condition.
// The TLS_CertificateList object and the data it contains is only valid during the callback
// function; if you want to keep it, you must make your own copy. Use the other functions listed
// above in order to read the data from the TLS_CertificateList object.

