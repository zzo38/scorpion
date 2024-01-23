#if 0
gcc ${CFLAGS:--s -O2} -c -fwrapv hash.c
exit
#endif

/*
  Some of the code in this file is based on some code from SQLite.
  The original code and this code also is public domain.
*/

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"

// ######## SHA-1 hash

/* Context for the SHA1 hash */
typedef struct SHA1Context SHA1Context;
struct SHA1Context {
  unsigned int state[5];
  unsigned int count[2];
  unsigned char buffer[64];
};

#define SHA_ROT(x,l,r) ((x) << (l) | (x) >> (r))
#define rol(x,k) SHA_ROT(x,k,32-(k))
#define ror(x,k) SHA_ROT(x,32-(k),k)

#define blk0le(i) (block[i] = (ror(block[i],8)&0xFF00FF00) \
    |(rol(block[i],8)&0x00FF00FF))
#define blk0be(i) block[i]
#define blk(i) (block[i&15] = rol(block[(i+13)&15]^block[(i+8)&15] \
    ^block[(i+2)&15]^block[i&15],1))

/*
 * (R0+R1), R2, R3, R4 are the different operations (rounds) used in SHA1
 *
 * Rl0() for little-endian and Rb0() for big-endian.  Endianness is
 * determined at run-time.
 */
#define Rl0(v,w,x,y,z,i) \
    z+=((w&(x^y))^y)+blk0le(i)+0x5A827999+rol(v,5);w=ror(w,2);
#define Rb0(v,w,x,y,z,i) \
    z+=((w&(x^y))^y)+blk0be(i)+0x5A827999+rol(v,5);w=ror(w,2);
#define R1(v,w,x,y,z,i) \
    z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=ror(w,2);
#define R2(v,w,x,y,z,i) \
    z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=ror(w,2);
#define R3(v,w,x,y,z,i) \
    z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=ror(w,2);
#define R4(v,w,x,y,z,i) \
    z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=ror(w,2);

/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */
static void SHA1Transform(unsigned int state[5], const unsigned char buffer[64]){
  unsigned int qq[5]; /* a, b, c, d, e; */
  static int one = 1;
  unsigned int block[16];
  memcpy(block, buffer, 64);
  memcpy(qq,state,5*sizeof(unsigned int));

#define a qq[0]
#define b qq[1]
#define c qq[2]
#define d qq[3]
#define e qq[4]

  /* Copy p->state[] to working vars */
  /*
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  */

  /* 4 rounds of 20 operations each. Loop unrolled. */
  if( 1 == *(unsigned char*)&one ){
    Rl0(a,b,c,d,e, 0); Rl0(e,a,b,c,d, 1); Rl0(d,e,a,b,c, 2); Rl0(c,d,e,a,b, 3);
    Rl0(b,c,d,e,a, 4); Rl0(a,b,c,d,e, 5); Rl0(e,a,b,c,d, 6); Rl0(d,e,a,b,c, 7);
    Rl0(c,d,e,a,b, 8); Rl0(b,c,d,e,a, 9); Rl0(a,b,c,d,e,10); Rl0(e,a,b,c,d,11);
    Rl0(d,e,a,b,c,12); Rl0(c,d,e,a,b,13); Rl0(b,c,d,e,a,14); Rl0(a,b,c,d,e,15);
  }else{
    Rb0(a,b,c,d,e, 0); Rb0(e,a,b,c,d, 1); Rb0(d,e,a,b,c, 2); Rb0(c,d,e,a,b, 3);
    Rb0(b,c,d,e,a, 4); Rb0(a,b,c,d,e, 5); Rb0(e,a,b,c,d, 6); Rb0(d,e,a,b,c, 7);
    Rb0(c,d,e,a,b, 8); Rb0(b,c,d,e,a, 9); Rb0(a,b,c,d,e,10); Rb0(e,a,b,c,d,11);
    Rb0(d,e,a,b,c,12); Rb0(c,d,e,a,b,13); Rb0(b,c,d,e,a,14); Rb0(a,b,c,d,e,15);
  }
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

  /* Add the working vars back into context.state[] */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;

#undef a
#undef b
#undef c
#undef d
#undef e
}


/* Initialize a SHA1 context */
static void sha1_hash_init(SHA1Context *p){
  /* SHA1 initialization constants */
  p->state[0] = 0x67452301;
  p->state[1] = 0xEFCDAB89;
  p->state[2] = 0x98BADCFE;
  p->state[3] = 0x10325476;
  p->state[4] = 0xC3D2E1F0;
  p->count[0] = p->count[1] = 0;
}

/* Add new content to the SHA1 hash */
static void sha1_hash_step(
  SHA1Context *p,                 /* Add content to this context */
  const unsigned char *data,      /* Data to be added */
  unsigned int len                /* Number of bytes in data */
){
  unsigned int i, j;

  j = p->count[0];
  if( (p->count[0] += len << 3) < j ){
    p->count[1] += (len>>29)+1;
  }
  j = (j >> 3) & 63;
  if( (j + len) > 63 ){
    (void)memcpy(&p->buffer[j], data, (i = 64-j));
    SHA1Transform(p->state, p->buffer);
    for(; i + 63 < len; i += 64){
      SHA1Transform(p->state, &data[i]);
    }
    j = 0;
  }else{
    i = 0;
  }
  (void)memcpy(&p->buffer[j], &data[i], len - i);
}


/* Add padding and compute the message digest.  Render the
** message digest as binary and put it into digest[].
** digest[] must be at least 20 bytes long. */
static void sha1_hash_finish(
  SHA1Context *p,           /* The SHA1 context to finish and render */
  unsigned char *digest     /* Store hash here */
){
  unsigned int i;
  unsigned char finalcount[8];

  for (i = 0; i < 8; i++){
    finalcount[i] = (unsigned char)((p->count[(i >= 4 ? 0 : 1)]
       >> ((3-(i & 3)) * 8) ) & 255); /* Endian independent */
  }
  sha1_hash_step(p, (const unsigned char *)"\200", 1);
  while ((p->count[0] & 504) != 448){
    sha1_hash_step(p, (const unsigned char *)"\0", 1);
  }
  sha1_hash_step(p, finalcount, 8);  /* Should cause a SHA1Transform() */
  for (i = 0; i < 20; i++){
    digest[i] = (unsigned char)((p->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
  }
}

// ######## SHA-3 hash

/*
** Macros to determine whether the machine is big or little endian,
** and whether or not that determination is run-time or compile-time.
**
** For best performance, an attempt is made to guess at the byte-order
** using C-preprocessor macros.  If that is unsuccessful, or if
** -DSHA3_BYTEORDER=0 is set, then byte-order is determined
** at run-time.
*/
#ifndef SHA3_BYTEORDER
# if defined(i386)     || defined(__i386__)   || defined(_M_IX86) ||    \
     defined(__x86_64) || defined(__x86_64__) || defined(_M_X64)  ||    \
     defined(_M_AMD64) || defined(_M_ARM)     || defined(__x86)   ||    \
     defined(__arm__)
#   define SHA3_BYTEORDER    1234
# elif defined(sparc)    || defined(__ppc__)
#   define SHA3_BYTEORDER    4321
# else
#   define SHA3_BYTEORDER 0
# endif
#endif

typedef unsigned long long u64;

/*
** State structure for a SHA3 hash in progress
*/
typedef struct SHA3Context SHA3Context;
struct SHA3Context {
  union {
    u64 s[25];                /* Keccak state. 5x5 lines of 64 bits each */
    unsigned char x[1600];    /* ... or 1600 bytes */
  } u;
  unsigned nRate;        /* Bytes of input accepted per Keccak iteration */
  unsigned nLoaded;      /* Input bytes loaded into u.x[] so far this cycle */
  unsigned ixMask;       /* Insert next input into u.x[nLoaded^ixMask]. */
};

/*
** A single step of the Keccak mixing function for a 1600-bit state
*/
static void KeccakF1600Step(SHA3Context *p){
  int i;
  u64 b0, b1, b2, b3, b4;
  u64 c0, c1, c2, c3, c4;
  u64 d0, d1, d2, d3, d4;
  static const u64 RC[] = {
    0x0000000000000001ULL,  0x0000000000008082ULL,
    0x800000000000808aULL,  0x8000000080008000ULL,
    0x000000000000808bULL,  0x0000000080000001ULL,
    0x8000000080008081ULL,  0x8000000000008009ULL,
    0x000000000000008aULL,  0x0000000000000088ULL,
    0x0000000080008009ULL,  0x000000008000000aULL,
    0x000000008000808bULL,  0x800000000000008bULL,
    0x8000000000008089ULL,  0x8000000000008003ULL,
    0x8000000000008002ULL,  0x8000000000000080ULL,
    0x000000000000800aULL,  0x800000008000000aULL,
    0x8000000080008081ULL,  0x8000000000008080ULL,
    0x0000000080000001ULL,  0x8000000080008008ULL
  };
# define a00 (p->u.s[0])
# define a01 (p->u.s[1])
# define a02 (p->u.s[2])
# define a03 (p->u.s[3])
# define a04 (p->u.s[4])
# define a10 (p->u.s[5])
# define a11 (p->u.s[6])
# define a12 (p->u.s[7])
# define a13 (p->u.s[8])
# define a14 (p->u.s[9])
# define a20 (p->u.s[10])
# define a21 (p->u.s[11])
# define a22 (p->u.s[12])
# define a23 (p->u.s[13])
# define a24 (p->u.s[14])
# define a30 (p->u.s[15])
# define a31 (p->u.s[16])
# define a32 (p->u.s[17])
# define a33 (p->u.s[18])
# define a34 (p->u.s[19])
# define a40 (p->u.s[20])
# define a41 (p->u.s[21])
# define a42 (p->u.s[22])
# define a43 (p->u.s[23])
# define a44 (p->u.s[24])
# define ROL64(a,x) ((a<<x)|(a>>(64-x)))

  for(i=0; i<24; i+=4){
    c0 = a00^a10^a20^a30^a40;
    c1 = a01^a11^a21^a31^a41;
    c2 = a02^a12^a22^a32^a42;
    c3 = a03^a13^a23^a33^a43;
    c4 = a04^a14^a24^a34^a44;
    d0 = c4^ROL64(c1, 1);
    d1 = c0^ROL64(c2, 1);
    d2 = c1^ROL64(c3, 1);
    d3 = c2^ROL64(c4, 1);
    d4 = c3^ROL64(c0, 1);

    b0 = (a00^d0);
    b1 = ROL64((a11^d1), 44);
    b2 = ROL64((a22^d2), 43);
    b3 = ROL64((a33^d3), 21);
    b4 = ROL64((a44^d4), 14);
    a00 =   b0 ^((~b1)&  b2 );
    a00 ^= RC[i];
    a11 =   b1 ^((~b2)&  b3 );
    a22 =   b2 ^((~b3)&  b4 );
    a33 =   b3 ^((~b4)&  b0 );
    a44 =   b4 ^((~b0)&  b1 );

    b2 = ROL64((a20^d0), 3);
    b3 = ROL64((a31^d1), 45);
    b4 = ROL64((a42^d2), 61);
    b0 = ROL64((a03^d3), 28);
    b1 = ROL64((a14^d4), 20);
    a20 =   b0 ^((~b1)&  b2 );
    a31 =   b1 ^((~b2)&  b3 );
    a42 =   b2 ^((~b3)&  b4 );
    a03 =   b3 ^((~b4)&  b0 );
    a14 =   b4 ^((~b0)&  b1 );

    b4 = ROL64((a40^d0), 18);
    b0 = ROL64((a01^d1), 1);
    b1 = ROL64((a12^d2), 6);
    b2 = ROL64((a23^d3), 25);
    b3 = ROL64((a34^d4), 8);
    a40 =   b0 ^((~b1)&  b2 );
    a01 =   b1 ^((~b2)&  b3 );
    a12 =   b2 ^((~b3)&  b4 );
    a23 =   b3 ^((~b4)&  b0 );
    a34 =   b4 ^((~b0)&  b1 );

    b1 = ROL64((a10^d0), 36);
    b2 = ROL64((a21^d1), 10);
    b3 = ROL64((a32^d2), 15);
    b4 = ROL64((a43^d3), 56);
    b0 = ROL64((a04^d4), 27);
    a10 =   b0 ^((~b1)&  b2 );
    a21 =   b1 ^((~b2)&  b3 );
    a32 =   b2 ^((~b3)&  b4 );
    a43 =   b3 ^((~b4)&  b0 );
    a04 =   b4 ^((~b0)&  b1 );

    b3 = ROL64((a30^d0), 41);
    b4 = ROL64((a41^d1), 2);
    b0 = ROL64((a02^d2), 62);
    b1 = ROL64((a13^d3), 55);
    b2 = ROL64((a24^d4), 39);
    a30 =   b0 ^((~b1)&  b2 );
    a41 =   b1 ^((~b2)&  b3 );
    a02 =   b2 ^((~b3)&  b4 );
    a13 =   b3 ^((~b4)&  b0 );
    a24 =   b4 ^((~b0)&  b1 );

    c0 = a00^a20^a40^a10^a30;
    c1 = a11^a31^a01^a21^a41;
    c2 = a22^a42^a12^a32^a02;
    c3 = a33^a03^a23^a43^a13;
    c4 = a44^a14^a34^a04^a24;
    d0 = c4^ROL64(c1, 1);
    d1 = c0^ROL64(c2, 1);
    d2 = c1^ROL64(c3, 1);
    d3 = c2^ROL64(c4, 1);
    d4 = c3^ROL64(c0, 1);

    b0 = (a00^d0);
    b1 = ROL64((a31^d1), 44);
    b2 = ROL64((a12^d2), 43);
    b3 = ROL64((a43^d3), 21);
    b4 = ROL64((a24^d4), 14);
    a00 =   b0 ^((~b1)&  b2 );
    a00 ^= RC[i+1];
    a31 =   b1 ^((~b2)&  b3 );
    a12 =   b2 ^((~b3)&  b4 );
    a43 =   b3 ^((~b4)&  b0 );
    a24 =   b4 ^((~b0)&  b1 );

    b2 = ROL64((a40^d0), 3);
    b3 = ROL64((a21^d1), 45);
    b4 = ROL64((a02^d2), 61);
    b0 = ROL64((a33^d3), 28);
    b1 = ROL64((a14^d4), 20);
    a40 =   b0 ^((~b1)&  b2 );
    a21 =   b1 ^((~b2)&  b3 );
    a02 =   b2 ^((~b3)&  b4 );
    a33 =   b3 ^((~b4)&  b0 );
    a14 =   b4 ^((~b0)&  b1 );

    b4 = ROL64((a30^d0), 18);
    b0 = ROL64((a11^d1), 1);
    b1 = ROL64((a42^d2), 6);
    b2 = ROL64((a23^d3), 25);
    b3 = ROL64((a04^d4), 8);
    a30 =   b0 ^((~b1)&  b2 );
    a11 =   b1 ^((~b2)&  b3 );
    a42 =   b2 ^((~b3)&  b4 );
    a23 =   b3 ^((~b4)&  b0 );
    a04 =   b4 ^((~b0)&  b1 );

    b1 = ROL64((a20^d0), 36);
    b2 = ROL64((a01^d1), 10);
    b3 = ROL64((a32^d2), 15);
    b4 = ROL64((a13^d3), 56);
    b0 = ROL64((a44^d4), 27);
    a20 =   b0 ^((~b1)&  b2 );
    a01 =   b1 ^((~b2)&  b3 );
    a32 =   b2 ^((~b3)&  b4 );
    a13 =   b3 ^((~b4)&  b0 );
    a44 =   b4 ^((~b0)&  b1 );

    b3 = ROL64((a10^d0), 41);
    b4 = ROL64((a41^d1), 2);
    b0 = ROL64((a22^d2), 62);
    b1 = ROL64((a03^d3), 55);
    b2 = ROL64((a34^d4), 39);
    a10 =   b0 ^((~b1)&  b2 );
    a41 =   b1 ^((~b2)&  b3 );
    a22 =   b2 ^((~b3)&  b4 );
    a03 =   b3 ^((~b4)&  b0 );
    a34 =   b4 ^((~b0)&  b1 );

    c0 = a00^a40^a30^a20^a10;
    c1 = a31^a21^a11^a01^a41;
    c2 = a12^a02^a42^a32^a22;
    c3 = a43^a33^a23^a13^a03;
    c4 = a24^a14^a04^a44^a34;
    d0 = c4^ROL64(c1, 1);
    d1 = c0^ROL64(c2, 1);
    d2 = c1^ROL64(c3, 1);
    d3 = c2^ROL64(c4, 1);
    d4 = c3^ROL64(c0, 1);

    b0 = (a00^d0);
    b1 = ROL64((a21^d1), 44);
    b2 = ROL64((a42^d2), 43);
    b3 = ROL64((a13^d3), 21);
    b4 = ROL64((a34^d4), 14);
    a00 =   b0 ^((~b1)&  b2 );
    a00 ^= RC[i+2];
    a21 =   b1 ^((~b2)&  b3 );
    a42 =   b2 ^((~b3)&  b4 );
    a13 =   b3 ^((~b4)&  b0 );
    a34 =   b4 ^((~b0)&  b1 );

    b2 = ROL64((a30^d0), 3);
    b3 = ROL64((a01^d1), 45);
    b4 = ROL64((a22^d2), 61);
    b0 = ROL64((a43^d3), 28);
    b1 = ROL64((a14^d4), 20);
    a30 =   b0 ^((~b1)&  b2 );
    a01 =   b1 ^((~b2)&  b3 );
    a22 =   b2 ^((~b3)&  b4 );
    a43 =   b3 ^((~b4)&  b0 );
    a14 =   b4 ^((~b0)&  b1 );

    b4 = ROL64((a10^d0), 18);
    b0 = ROL64((a31^d1), 1);
    b1 = ROL64((a02^d2), 6);
    b2 = ROL64((a23^d3), 25);
    b3 = ROL64((a44^d4), 8);
    a10 =   b0 ^((~b1)&  b2 );
    a31 =   b1 ^((~b2)&  b3 );
    a02 =   b2 ^((~b3)&  b4 );
    a23 =   b3 ^((~b4)&  b0 );
    a44 =   b4 ^((~b0)&  b1 );

    b1 = ROL64((a40^d0), 36);
    b2 = ROL64((a11^d1), 10);
    b3 = ROL64((a32^d2), 15);
    b4 = ROL64((a03^d3), 56);
    b0 = ROL64((a24^d4), 27);
    a40 =   b0 ^((~b1)&  b2 );
    a11 =   b1 ^((~b2)&  b3 );
    a32 =   b2 ^((~b3)&  b4 );
    a03 =   b3 ^((~b4)&  b0 );
    a24 =   b4 ^((~b0)&  b1 );

    b3 = ROL64((a20^d0), 41);
    b4 = ROL64((a41^d1), 2);
    b0 = ROL64((a12^d2), 62);
    b1 = ROL64((a33^d3), 55);
    b2 = ROL64((a04^d4), 39);
    a20 =   b0 ^((~b1)&  b2 );
    a41 =   b1 ^((~b2)&  b3 );
    a12 =   b2 ^((~b3)&  b4 );
    a33 =   b3 ^((~b4)&  b0 );
    a04 =   b4 ^((~b0)&  b1 );

    c0 = a00^a30^a10^a40^a20;
    c1 = a21^a01^a31^a11^a41;
    c2 = a42^a22^a02^a32^a12;
    c3 = a13^a43^a23^a03^a33;
    c4 = a34^a14^a44^a24^a04;
    d0 = c4^ROL64(c1, 1);
    d1 = c0^ROL64(c2, 1);
    d2 = c1^ROL64(c3, 1);
    d3 = c2^ROL64(c4, 1);
    d4 = c3^ROL64(c0, 1);

    b0 = (a00^d0);
    b1 = ROL64((a01^d1), 44);
    b2 = ROL64((a02^d2), 43);
    b3 = ROL64((a03^d3), 21);
    b4 = ROL64((a04^d4), 14);
    a00 =   b0 ^((~b1)&  b2 );
    a00 ^= RC[i+3];
    a01 =   b1 ^((~b2)&  b3 );
    a02 =   b2 ^((~b3)&  b4 );
    a03 =   b3 ^((~b4)&  b0 );
    a04 =   b4 ^((~b0)&  b1 );

    b2 = ROL64((a10^d0), 3);
    b3 = ROL64((a11^d1), 45);
    b4 = ROL64((a12^d2), 61);
    b0 = ROL64((a13^d3), 28);
    b1 = ROL64((a14^d4), 20);
    a10 =   b0 ^((~b1)&  b2 );
    a11 =   b1 ^((~b2)&  b3 );
    a12 =   b2 ^((~b3)&  b4 );
    a13 =   b3 ^((~b4)&  b0 );
    a14 =   b4 ^((~b0)&  b1 );

    b4 = ROL64((a20^d0), 18);
    b0 = ROL64((a21^d1), 1);
    b1 = ROL64((a22^d2), 6);
    b2 = ROL64((a23^d3), 25);
    b3 = ROL64((a24^d4), 8);
    a20 =   b0 ^((~b1)&  b2 );
    a21 =   b1 ^((~b2)&  b3 );
    a22 =   b2 ^((~b3)&  b4 );
    a23 =   b3 ^((~b4)&  b0 );
    a24 =   b4 ^((~b0)&  b1 );

    b1 = ROL64((a30^d0), 36);
    b2 = ROL64((a31^d1), 10);
    b3 = ROL64((a32^d2), 15);
    b4 = ROL64((a33^d3), 56);
    b0 = ROL64((a34^d4), 27);
    a30 =   b0 ^((~b1)&  b2 );
    a31 =   b1 ^((~b2)&  b3 );
    a32 =   b2 ^((~b3)&  b4 );
    a33 =   b3 ^((~b4)&  b0 );
    a34 =   b4 ^((~b0)&  b1 );

    b3 = ROL64((a40^d0), 41);
    b4 = ROL64((a41^d1), 2);
    b0 = ROL64((a42^d2), 62);
    b1 = ROL64((a43^d3), 55);
    b2 = ROL64((a44^d4), 39);
    a40 =   b0 ^((~b1)&  b2 );
    a41 =   b1 ^((~b2)&  b3 );
    a42 =   b2 ^((~b3)&  b4 );
    a43 =   b3 ^((~b4)&  b0 );
    a44 =   b4 ^((~b0)&  b1 );
  }
}

/*
** Initialize a new hash.  iSize determines the size of the hash
** in bits and should be one of 224, 256, 384, or 512.  Or iSize
** can be zero to use the default hash size of 256 bits.
*/
static void SHA3Init(SHA3Context *p, int iSize){
  memset(p, 0, sizeof(*p));
  if( iSize>=128 && iSize<=512 ){
    p->nRate = (1600 - ((iSize + 31)&~31)*2)/8;
  }else{
    p->nRate = (1600 - 2*256)/8;
  }
#if SHA3_BYTEORDER==1234
  /* Known to be little-endian at compile-time. No-op */
#elif SHA3_BYTEORDER==4321
  p->ixMask = 7;  /* Big-endian */
#else
  {
    static unsigned int one = 1;
    if( 1==*(unsigned char*)&one ){
      /* Little endian.  No byte swapping. */
      p->ixMask = 0;
    }else{
      /* Big endian.  Byte swap. */
      p->ixMask = 7;
    }
  }
#endif
}

/*
** Make consecutive calls to the SHA3Update function to add new content
** to the hash
*/
static void SHA3Update(
  SHA3Context *p,
  const unsigned char *aData,
  unsigned int nData
){
  unsigned int i = 0;
  if( aData==0 ) return;
#if SHA3_BYTEORDER==1234
  if( (p->nLoaded % 8)==0 && ((aData - (const unsigned char*)0)&7)==0 ){
    for(; i+7<nData; i+=8){
      p->u.s[p->nLoaded/8] ^= *(u64*)&aData[i];
      p->nLoaded += 8;
      if( p->nLoaded>=p->nRate ){
        KeccakF1600Step(p);
        p->nLoaded = 0;
      }
    }
  }
#endif
  for(; i<nData; i++){
#if SHA3_BYTEORDER==1234
    p->u.x[p->nLoaded] ^= aData[i];
#elif SHA3_BYTEORDER==4321
    p->u.x[p->nLoaded^0x07] ^= aData[i];
#else
    p->u.x[p->nLoaded^p->ixMask] ^= aData[i];
#endif
    p->nLoaded++;
    if( p->nLoaded==p->nRate ){
      KeccakF1600Step(p);
      p->nLoaded = 0;
    }
  }
}

/*
** After all content has been added, invoke SHA3Final() to compute
** the final hash.  The function returns a pointer to the binary
** hash value.
*/
static unsigned char *SHA3Final(SHA3Context *p){
  unsigned int i;
  if( p->nLoaded==p->nRate-1 ){
    const unsigned char c1 = 0x86;
    SHA3Update(p, &c1, 1);
  }else{
    const unsigned char c2 = 0x06;
    const unsigned char c3 = 0x80;
    SHA3Update(p, &c2, 1);
    p->nLoaded = p->nRate - 1;
    SHA3Update(p, &c3, 1);
  }
  for(i=0; i<p->nRate; i++){
    p->u.x[i+p->nRate] = p->u.x[i^p->ixMask];
  }
  return &p->u.x[p->nRate];
}

// ######## MD5

typedef struct {
  uint8_t chunk[64];
  uint64_t len;
  uint32_t a,b,c,d;
} MD5Context;

static void md5_init(MD5Context*v) {
  v->len=0;
  v->a=0x67452301;
  v->b=0xEFCDAB89;
  v->c=0x98BADCFE;
  v->d=0x10325476;
}

static void md5_step(MD5Context*v) {
  static const uint8_t s[64]={
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
  };
  static const uint32_t k[64]={
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
  };
  static const uint8_t g[64]={
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    4, 24, 44, 0, 20, 40, 60, 16, 36, 56, 12, 32, 52, 8, 28, 48,
    20, 32, 44, 56, 4, 16, 28, 40, 52, 0, 12, 24, 36, 48, 60, 8,
    0, 28, 56, 20, 48, 12, 40, 4, 32, 60, 24, 52, 16, 44, 8, 36,
  };
  uint32_t a,b,c,d,f,i;
  a=v->a; b=v->b; c=v->c; d=v->d;
  for(i=0;i<64;i++) {
    switch(i&0x30) {
      case 0x00: f=(b&c)|(d&~b); break;
      case 0x10: f=(b&d)|(c&~d); break;
      case 0x20: f=b^c^d; break;
      case 0x30: f=c^(b|~d); break;
    }
    f+=a+k[i]+v->chunk[g[i]]+(v->chunk[g[i]+1]<<8)+(v->chunk[g[i]+2]<<16)+(v->chunk[g[i]+3]<<24);
    a=d; d=c; c=b;
    b+=(f<<s[i])|(f>>(32-s[i]));
  }
  v->a+=a; v->b+=b; v->c+=c; v->d+=d;
}

static void md5_write(MD5Context*v,const char*buf,size_t len) {
  size_t n=len;
  size_t i;
  while(n) {
    i=n; if(i>64-(v->len&63)) i=64-(v->len&63);
    memcpy(v->chunk+(v->len&63),buf,i);
    buf+=i; v->len+=i; n-=i;
    if(!(v->len&63)) md5_step(v);
  }
}

static void md5_finish(MD5Context*v,unsigned char*o) {
  uint64_t n=v->len*8;
  uint8_t buf[8];
  buf[0]=n>>000; buf[1]=n>>010; buf[2]=n>>020; buf[3]=n>>030;
  buf[4]=n>>040; buf[5]=n>>050; buf[6]=n>>060; buf[7]=n>>070;
  md5_write(v,"\x80",1);
  memset(v->chunk+(v->len&63),0,64-(v->len&63));
  if((v->len&63)>56) {
    md5_step(v);
    memset(v->chunk,0,56);
  }
  memcpy(v->chunk+56,buf,8);
  md5_step(v);
  o[0]=v->a; o[1]=v->a>>8; o[2]=v->a>>16; o[3]=v->a>>24;
  o[4]=v->b; o[5]=v->b>>8; o[6]=v->b>>16; o[7]=v->b>>24;
  o[8]=v->c; o[9]=v->c>>8; o[10]=v->c>>16; o[11]=v->c>>24;
  o[12]=v->d; o[13]=v->d>>8; o[14]=v->d>>16; o[15]=v->d>>24;
}

// ########

typedef struct {
  union {
    SHA1Context sha1;
    SHA3Context sha3;
    MD5Context md5;
  };
  long long alg;
  FILE*echo;
  unsigned char*out;
} HashState;

static ssize_t hash_write(void *cookie, const char *buf, size_t size) {
  HashState*hs=cookie;
  if(!size) return 0;
  if(hs->echo) fwrite(buf,1,size,hs->echo);
  switch(hs->alg) {
    case HASH_SHA1:
      sha1_hash_step(&hs->sha1,buf,size); break;
    case HASH_SHA3_224:
    case HASH_SHA3_256:
    case HASH_SHA3_384:
    case HASH_SHA3_512:
      SHA3Update(&hs->sha3,buf,size); break;
    case HASH_MD5:
      md5_write(&hs->md5,buf,size); break;
  }
  return size;
}

static int hash_close(void *cookie) {
  HashState*hs=cookie;
  switch(hs->alg) {
    case HASH_SHA1:
      sha1_hash_finish(&hs->sha1,hs->out); break;
    case HASH_SHA3_224:
    case HASH_SHA3_256:
    case HASH_SHA3_384:
    case HASH_SHA3_512:
      memcpy(hs->out,SHA3Final(&hs->sha3),hash_length(hs->alg)); break;
    case HASH_MD5:
      md5_finish(&hs->md5,hs->out); break;
  }
  free(cookie);
  return 0;
}

long hash_length(long long alg) {
  switch(alg) {
    case HASH_SHA1: return 20;
    case HASH_SHA3_224: return 224/8;
    case HASH_SHA3_256: return 256/8;
    case HASH_SHA3_384: return 384/8;
    case HASH_SHA3_512: return 512/8;
    case HASH_MD5: return 16;
    default: return 0;
  }
}

FILE*hash_stream(long long alg,FILE*echo,unsigned char*out) {
  HashState*hs=malloc(sizeof(HashState));
  FILE*fp;
  if(!hs) return 0;
  switch(alg) {
    case HASH_SHA1: sha1_hash_init(&hs->sha1); break;
    case HASH_SHA3_224: SHA3Init(&hs->sha3,224); break;
    case HASH_SHA3_256: SHA3Init(&hs->sha3,256); break;
    case HASH_SHA3_384: SHA3Init(&hs->sha3,384); break;
    case HASH_SHA3_512: SHA3Init(&hs->sha3,512); break;
    case HASH_MD5: md5_init(&hs->md5); break;
    default: free(hs); return 0;
  }
  fp=fopencookie(hs,"w",(cookie_io_functions_t){.write=hash_write,.close=hash_close});
  if(!fp) {
    free(hs);
    return 0;
  }
  hs->alg=alg;
  hs->echo=echo;
  hs->out=out;
  return fp;
}

unsigned char*hash_buffer(long long alg,const unsigned char*data,int len) {
  int n=hash_length(alg);
  unsigned char*b;
  FILE*fp;
  if(!n || (len && !data)) return 0;
  b=malloc(n);
  if(!b) return 0;
  fp=hash_stream(alg,0,b);
  if(!fp) {
    free(b);
    return 0;
  }
  fwrite(data,1,len,fp);
  fclose(fp);
  return b;
}
