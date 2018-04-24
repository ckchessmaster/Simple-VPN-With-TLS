#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#define DEFAULT_PORT_NUMBER 55555
#define DEFAULT_BUFF_SIZE 65535
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }

struct Config {
  char* programName;
  char* hostname;
  int port;
  int shouldDebug;
  int useEncryption;
} config;

struct sockaddr_in server;
int sockfd, tunfd; // The file descriptors
SSL* ssl;

void debug(char* message) {
  if (config.shouldDebug == 1) {
    printf("%s", message);
  }
}

int verify_callback(int preverify_ok, X509_STORE_CTX* x509_ctx) {
  char buf[300];

  X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);

  if(config.shouldDebug == 1) {
    printf("subject= %s\n", buf);
  }

  if(preverify_ok == 1) {
    debug("Verification passed.\n");
  } else if(config.shouldDebug == 1){
    int err = X509_STORE_CTX_get_error(x509_ctx);
    printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
  }
}

void initTLS() {
  printf("Initializing TLS...\n");

  int err;

  // Step 0: OpenSSL library initialization
  // This step is no longer needed as of version 1.1.0.
  // As of 4/22/18 Ubuntu 17.10 uses OpenSSL 1.0.21)
  SSL_library_init();
  SSL_load_error_strings();

  // Step 1: SSL context initialization
  SSL_METHOD* method = (SSL_METHOD*)DTLS_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback); // We want to verify the server's cert

  err = SSL_CTX_use_certificate_file(ctx, "./cert/client_cert.pem", SSL_FILETYPE_PEM); // The server's cert
  if(err != 1) on_error("Could not load client certificate!\n");

  err = SSL_CTX_use_PrivateKey_file(ctx, "./cert/client_key.pem", SSL_FILETYPE_PEM); // The server's key
  if(err != 1) on_error("Could not load client key!\n");

  err = SSL_CTX_load_verify_locations(ctx, NULL, "./cert");
  if(err != 1) on_error("Could not load certs!\n");

  // Step 2: Create a new SSL structure for a connection
  ssl = SSL_new (ctx);
  if(ssl == NULL) on_error("SSL initialization failure!\n");

  // Step 3: Enable the hostname check
  X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
  err = X509_VERIFY_PARAM_set1_host(vpm, config.hostname, 0);
  if(err != 1) on_error("Could not setup host verification!\n");

  printf("TLS setup complete!\n");
}

void sslErr() {
  ERR_print_errors_fp (stderr);
  on_error("\n");
}

void initTunnel() {
  printf("Initializing tunnel...\n");
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN;

  tunfd = open("/dev/net/tun", O_RDWR);
  ioctl(tunfd, TUNSETIFF, &ifr);

  printf("Tunnel setup complete! File descriptor: %d\n", tunfd);
}

void connectToTCPServer() {
  printf("Connecting to server...\n");

  // Setup the address and port
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  inet_pton(AF_INET, config.hostname, &server.sin_addr);
  server.sin_port = htons(config.port);

  sockfd = socket(PF_INET, SOCK_STREAM, 0); // Create the socket
  if(sockfd < 0) on_error("Could not create socket\n");

  // Connect to the server
  int err = connect(sockfd, (struct sockaddr*)&server, sizeof(server));
  if (err < 0) on_error("Could not connect to server\n");

  printf("Connection established!\n");

  // TLS Handshake
  if(config.useEncryption == 1) {
    printf("Starting TLS handshake...\n");
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl);
    if(err != 1) {
      printf("Handshake unsuccessful!\n");
      sslErr();
    }

    printf("SSL connection is successful\n");
    printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
  }
}

int socketReady() {
  int len, err;
  char buff[DEFAULT_BUFF_SIZE];

  // Read in packet from the server
  bzero(buff, DEFAULT_BUFF_SIZE);
  if(config.useEncryption == 1) {
    SSL_read(ssl, buff, DEFAULT_BUFF_SIZE);
  } else len = recv(sockfd, buff, DEFAULT_BUFF_SIZE, 0);

  printf("Message from the server!\n");

  // Output packet to the tunnel interface
  err = write(tunfd, buff, len);
  if(err > 0 && config.shouldDebug == 1) debug("Message sent to the tunnel interface!\n");

  return len;
}

void tunnelReady() {
  int len, err;
  char buff[DEFAULT_BUFF_SIZE];

  // Read in packet from the tunnel interface
  bzero(buff, DEFAULT_BUFF_SIZE);
  len = read(tunfd, buff, DEFAULT_BUFF_SIZE);

  // Output packet to the server
  if(config.useEncryption == 1) {
    err = SSL_write(ssl, buff, len);
  } else err = send(sockfd, buff, len, 0);

  if(err < 0 && config.useEncryption == 1) {
    sslErr();
  }else if(err > 0 && config.shouldDebug == 1) debug("Message sent to the server!\n");
}

void handleConnection() {
  while(1) {
    fd_set readFDSet; // The set of file descriptors (fd)

    FD_ZERO(&readFDSet); // zero out the set
    FD_SET(sockfd, &readFDSet); // add the tcp fd to the set
    FD_SET(tunfd, &readFDSet); // add the tunnel fd to the set

    // Wait until something arrives on either the tunnel or the tcp socket
    select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

    debug("Something is ready!\n");

    if(FD_ISSET(sockfd, &readFDSet)) {
      int code = socketReady();
      if(code < 1) return;
    }

    if(FD_ISSET(tunfd, &readFDSet)) tunnelReady();
  }

  close(sockfd);
}

void usage() {
  printf("Usage:\n");
  printf("%s -h <hostname> [-p <port>] [-d] [-e]\n", config.programName);
  printf("\n");
  printf("-i <hostname>: specify the server address (mandatory)\n");
  printf("-p <port>: port to connect to, default 55555\n");
  printf("-d: outputs debug information while running\n");
  printf("-e: use TLS encryption\n");
  printf("-h: prints this help text\n");

  on_error("\n");
}

void initConfig(int argc, char* argv[]) {
  if(argc < 2) {
    usage();
  }

  config.programName = argv[0];
  config.port = 55555;
  config.shouldDebug = 0;
  config.useEncryption = 0;

  int option;
  while((option = getopt(argc, argv, "i:p:deh")) > 0) {
    switch(option) {
      case 'i':
        config.hostname = optarg;
        break;
      case 'p':
        config.port = atoi(optarg);
        break;
      case 'd':
        config.shouldDebug = 1;
        break;
      case 'e':
        config.useEncryption = 1;
        break;
      case 'h':
        usage();
        break;
      default:
        printf("Unknown option %c\n", option);
        usage();
    }
  }
}

int main (int argc, char * argv[]) {
  printf("Hello World!\n");

  initConfig(argc, argv);
  if(config.useEncryption == 1) initTLS();
  initTunnel();
  connectToTCPServer();
  handleConnection();

  close(sockfd);
  close(tunfd);
  SSL_shutdown(ssl);
  SSL_free(ssl);

  return 0;
}
