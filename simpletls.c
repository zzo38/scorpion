#if 0
gcc -s -O2 -c simpletls.c
exit
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "simpletls.h"

#define BufferSize 0x4000
int secure_socket(struct sockaddr*addr,const char*hostname,const char*options,const Certificate*cert) {
  char xx[BufferSize];
  SSL_CTX*ctx=0;
  SSL*ssl=0;
  fd_set rs,ws;
  int r,e,n,m,net,hi;
  pid_t pid;
  int sv[2];
  uint64_t o;
  uint16_t oo=0;
  int bloc=0;
  if(socketpair(AF_UNIX,SOCK_STREAM,0,sv)) return -1;
  pid=fork();
  if(pid==-1) {
    e=errno;
    close(sv[0]);
    close(sv[1]);
    errno=e;
    return -1;
  } else if(pid) {
    close(sv[1]);
    if(recv(sv[0],xx,1,MSG_WAITALL)!=1 || *xx!=1) {
      close(sv[0]);
      return -1;
    }
    return sv[0];
  } else {
    close(sv[0]);
    SSL_library_init();
    OPENSSL_config(NULL);
    if(!options) options="";
    ctx=SSL_CTX_new(SSLv23_client_method());
    if(!ctx) _exit(1);
    if(options) {
      e=0;
      while(*options && *options!=',' && *options!=':' && *options!=';') {
        switch(*options++) {
          case '-': e='-'; break;
          case '+': e='+'; break;
          case '=': e='+'; SSL_CTX_clear_options(ctx,SSL_CTX_get_options(ctx)); break;
#define Z(aa,bb) case aa: if(e=='+') SSL_CTX_set_options(ctx,bb); else if(e=='-') SSL_CTX_clear_options(ctx,bb); break;
          Z('A',SSL_OP_ALL)
          Z('r',SSL_OP_TLS_ROLLBACK_BUG)
          Z('s',SSL_OP_SINGLE_DH_USE)
          Z('C',SSL_OP_CIPHER_SERVER_PREFERENCE)
          Z('2',SSL_OP_NO_SSLv2)
          Z('3',SSL_OP_NO_SSLv3)
          Z('1',SSL_OP_NO_TLSv1)
          Z('S',SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION)
          Z('T',SSL_OP_NO_TICKET)
          Z('U',SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
          Z('L',SSL_OP_LEGACY_SERVER_CONNECT)
          Z('c',SSL_OP_NO_COMPRESSION)
#undef Z
#define Z(aa,bb) case aa: if(e=='+') oo|=bb; else if(e=='-') oo&=~(bb); break;
          Z('0',0x0001)
          Z('E',0x0002)
#undef Z
          case 'x': o=strtol(options,(char**)&options,16); if(e=='+') SSL_CTX_set_options(ctx,o); else if(e=='-') SSL_CTX_clear_options(ctx,o); break;
        }
      }
    }
    if(oo&0x0002) SSL_load_error_strings();
    if(options && *options==',') SSL_CTX_set_cipher_list(ctx,options+1);
    SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
    ssl=SSL_new(ctx);
    if(!ssl) _exit(1);
    if(cert && cert->type>0 && cert->type<3) {
      if(cert->cert_file) SSL_use_certificate_file(ssl,cert->cert_file,cert->type==1?SSL_FILETYPE_ASN1:SSL_FILETYPE_PEM);
      if(cert->key_file) SSL_use_PrivateKey_file(ssl,cert->key_file,cert->type==1?SSL_FILETYPE_ASN1:SSL_FILETYPE_PEM);
      if(oo&0x0002) ERR_print_errors_fp(stderr),fflush(stderr);
    }
    net=socket(AF_INET,SOCK_STREAM,0);
    if(net==-1) _exit(1);
    if(connect(net,addr,sizeof(struct sockaddr_in))<0) _exit(1);
    hi=(net>sv[1]?net:sv[1])+1;
    if(hostname && !(oo&0x0001)) SSL_set_tlsext_host_name(ssl,hostname);
    SSL_set_fd(ssl,net);
    SSL_set_connect_state(ssl);
    *xx=1;
    send(sv[1],xx,1,0);
    e=SSL_connect(ssl);
    if(oo&0x0002) ERR_print_errors_fp(stderr),fflush(stderr);
    for(;;) {
      FD_ZERO(&rs);
      FD_SET(sv[1],&rs);
      FD_SET(net,&rs);
      r=select(hi,&rs,0,0,0);
      if(r==-1) _exit(1);
      if(!r) continue;
      if(FD_ISSET(sv[1],&rs)) {
        r=recv(sv[1],xx,BufferSize,0);
        if((r==-1 && errno==EPIPE) || !r) _exit(0);
        if(r==-1 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) continue;
        if(r==-1) _exit(1);
        e=SSL_write(ssl,xx,r);
        if(e<=0) switch(SSL_get_error(ssl,e)) {
          case SSL_ERROR_ZERO_RETURN: _exit(0);
          case SSL_ERROR_WANT_READ: case SSL_ERROR_WANT_WRITE: break;
          //TODO: other conditions
          default: _exit(1);
        }
      }
      if(FD_ISSET(net,&rs)) {
        r=SSL_read(ssl,xx,BufferSize);
        if(r<=0) switch(SSL_get_error(ssl,r)) {
          case SSL_ERROR_ZERO_RETURN: _exit(0);
          case SSL_ERROR_WANT_READ: case SSL_ERROR_WANT_WRITE: break;
          //TODO: other conditions
          default: _exit(1);
        }
        m=0;
        resend:
        e=send(sv[1],xx+m,r,MSG_NOSIGNAL);
        if((e==-1 && (errno==EPIPE || errno==ECONNRESET)) || !e) _exit(0);
        if(e==-1 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) goto resend;
        if(e==-1) _exit(1);
        if(e<r) {
          m+=e;
          r-=e;
          goto resend;
        }
      }
    }
  }
}

/*
  TODO:
  - Ensure all options work properly
  - If anything else is wrong, fix that too
*/

