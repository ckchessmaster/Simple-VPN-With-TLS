#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

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
  int port;
  int shouldDebug;
  int useEncryption;
} config;

struct sockaddr_in server, client; // the sockets
int server_fd, client_fd, tun_fd; // file descriptors
SSL* ssl;

void debug(char* message) {
  if(config.shouldDebug == 1) printf("%s", message);
}

void initTLS() {
  printf("Initializing TLS...\n");

  // Step 0: OpenSSL library initialization
  // This step is no longer needed as of version 1.1.0.
  // As of 4/22/18 Ubuntu 17.10 uses OpenSSL 1.0.21)
  SSL_library_init();
  SSL_load_error_strings();

  SSL_METHOD* method;
  SSL_CTX* ctx; // ssl context
  int err;

  // Step 1: SSL context initialization
  method = (SSL_METHOD*)DTLS_method();
  ctx = SSL_CTX_new(method);
  if(ctx == NULL) on_error("Unable to create new SSL context!\n");

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // Don't verify the client's cert

  // Step 2: Set up the server certificate and private bank_key
  err = SSL_CTX_use_certificate_file(ctx, "./cert/server_cert.pem", SSL_FILETYPE_PEM); // The server's cert
  if(err != 1) on_error("Could not load server certificate!\n");

  err = SSL_CTX_use_PrivateKey_file(ctx, "./cert/server_key.pem", SSL_FILETYPE_PEM); // The server's key
  if(err != 1) on_error("Could not load server key!\n");

  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new(ctx);
  if(ssl == NULL) on_error("SSL initialization failure!\n");

  printf("TLS Setup complete!\n");
}

void sslErr() {
  ERR_print_errors_fp(stderr);
  on_error("\n");
}

void initTunnel() {
  printf("Initializing tunnel...\n");

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN;

  tun_fd = open("/dev/net/tun", O_RDWR);
  ioctl(tun_fd, TUNSETIFF, &ifr);

  printf("Tunnel setup complete! File descriptor: %d\n", tun_fd);
}

void initTCPServer() {
  int err;
  printf("Initializing UDP server...\n");

  // AF_INET = ipv4, SOCK_STREAM = TCP, 0 = default
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) on_error("Could not create socket\n");

  // Setup server socket
  memset(&server, 0, sizeof(server)); // zero out the struct
  server.sin_family = AF_INET;
  server.sin_port = htons(config.port); // convert int to proper form and assign
  server.sin_addr.s_addr = htonl(INADDR_ANY); // We will accept from any address

  int opt_val = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val); // set socket options

  // Bind to socket
  err = bind(server_fd, (struct sockaddr*) &server, sizeof(server));
  if (err < 0) on_error("Could not bind socket\n");

  err = listen(server_fd, 128); // 128 = max clients in queue
  if (err < 0) on_error("Could not listen on socket\n");

  printf("Server is now listening on %d\n", config.port);
}

int clientReady() {
  // Read in client packet
  char inbuf[DEFAULT_BUFF_SIZE];
  int len;
  if(config.useEncryption == 1) {
    len = SSL_read(ssl, inbuf, sizeof(inbuf));
  } else {
    len = recv(client_fd, inbuf, DEFAULT_BUFF_SIZE, 0);
  }

  debug("Message from client!\n");

  // Output packet to our network

  if(len > 0) {
    int result = write(tun_fd, inbuf, len);
    debug("Message sent to the tunnel interface!\n");
    if (result < 0){
      printf("Tunnel write error on: %s\n", strerror(errno));
      printf("len: %d, msg: %s", len, inbuf);
    }
  } else {
    debug("Recieved message of 0 len!\n");
  }

  return len;
}

int tunnelReady() {
  int len, result;
  char buff[DEFAULT_BUFF_SIZE];

  debug("Message from tunnel interface.\n");

  // Read in packet from tunnel interface
  bzero(buff, DEFAULT_BUFF_SIZE);
  len = read(tun_fd, buff, DEFAULT_BUFF_SIZE);

  // Output packet to the client
  if(config.useEncryption == 1) {
    result = SSL_write(ssl, buff, len);
  } else {
    result = sendto(client_fd, buff, len, 0, (struct sockaddr*)&client, sizeof(client));
  }
  if(result < 0) {
    printf("Client disconnected!\n");
    return result;
  } else if(result > 0 && config.shouldDebug == 1) debug("Message sent to the Client\n");

  return 0;
}

void start() {
  int err, result;
  char inbuf[DEFAULT_BUFF_SIZE];

  while(1) {
    printf("Listening for client...\n");
    socklen_t client_len = sizeof(client);
    client_fd = accept(server_fd, (struct sockaddr*)&client, &client_len);
    if(client_fd < 0) on_error("Could not establish new connection\n");
    printf("New client connected!\n");

    if(fork() == 0) { // We are the child process
      close(server_fd); // Don't need this anymore

      if(config.useEncryption == 1) {
        SSL_set_fd(ssl, client_fd);
        int err = SSL_accept(ssl);
        if(err != 1) {
          printf("Unable to establish TLS connection!\n");
          sslErr();
        }

        printf ("SSL connection established!\n");
        printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
      }

      while(1) {
        fd_set readFDSet; // The set of file descriptors (fd)

        FD_ZERO(&readFDSet); // zero out the set
        FD_SET(client_fd, &readFDSet); // add the tcp fd to the set
        FD_SET(tun_fd, &readFDSet); // add the tunnel fd to the set

        // Wait until something arrives on either the tunnel or the tcp socket
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        debug("Something is here!\n");

        if(FD_ISSET(client_fd, &readFDSet)) {
          result = clientReady();
          if(result < 1) break;
        }
        if(FD_ISSET(tun_fd, &readFDSet)) {
          result = tunnelReady();
          if(result < 0) break; // Client disconnected
        }
      }

      close(client_fd);
      return;
    } else { // We are the parent process
      close(client_fd); // The child will deal with this
    }
  }
}

void usage() {
  printf("Usage:\n");
  printf("%s [-p <port>] [-d] [-e]\n", config.programName);
  printf("\n");
  printf("-p <port>: port to connect to, default 55555\n");
  printf("-d: outputs debug information while running\n");
  printf("-e: use TLS encryption\n");
  printf("-h: prints this help text\n");

  on_error("\n");
}

void initConfig(int argc, char* argv[]) {
  config.programName = argv[0];
  config.port = 55555;
  config.shouldDebug = 0;
  config.useEncryption = 0;

  int option;
  while((option = getopt(argc, argv, "p:deh")) > 0) {
    switch(option) {
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
  initTCPServer();
  start();

  close(server_fd);
  close(tun_fd);
  SSL_shutdown(ssl);
  SSL_free(ssl);

  return 0;
}
