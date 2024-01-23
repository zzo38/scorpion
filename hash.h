// Free public domain cryptographic hash library

#define HASH_SHA1 0x11
#define HASH_SHA3_512 0x14
#define HASH_SHA3_384 0x15
#define HASH_SHA3_256 0x16
#define HASH_SHA3_224 0x17
#define HASH_MD5 0xD5

long hash_length(long long alg);
// Tell the length (in bytes) of the hash of the specified algorithm. If
// it is not implemented, then the result is zero.

FILE*hash_stream(long long alg,FILE*echo,unsigned char*out);
// Returns a writable stream. If the echo stream is not null, then any
// data written to the stream is also written to the echo stream. When
// the stream is closed, the hash (as binary) is written to the out.

unsigned char*hash_buffer(long long alg,const unsigned char*data,int len);
// Returns a hash (as binary) of the specified data. The returned buffer
// is allocated by malloc and must be freed by free. (This function is a
// convenience function implemented in terms of the other two functions.)

