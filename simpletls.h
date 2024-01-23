typedef struct {
  
} Certificate;
int secure_socket(struct sockaddr*addr,const char*hostname,const char*options,const Certificate*cert);
