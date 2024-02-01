typedef struct {
  char type; // 0=none, 1=ASN.1, 2=PEM
  const char*cert_file;
  const char*key_file;
} Certificate;
int secure_socket(struct sockaddr*addr,const char*hostname,const char*options,const Certificate*cert);
