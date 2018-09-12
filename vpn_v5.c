/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>

#include <openssl/rsa.h>       // SSLeay stuff
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 1500   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define CACERT HOME "ca.crt"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/**************************************************************************
 * gen_kv: randomly generate key and iv.                                  *
 **************************************************************************/
void gen_kv(char* key, char* iv) {
  unsigned char dic[] = " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  size_t diclen = strlen(dic);
  srand((unsigned) time(NULL));
    
  size_t i;
  for (i = 0; i < 16; i++){
  size_t rdnum = rand() % diclen;
  key[i] = dic[rdnum];
  }
  //printf("New Secret-key: %s\n", key);

  for (i = 0; i < 16; i++){
    size_t rdnum = rand() % diclen;
    iv[i] = dic[rdnum];
  }
  //printf("New IV: %s\n", iv);
}

/**************************************************************************
 * SSL_Setup_NOCERT: SSL Connection Setup without certificate.            *
 **************************************************************************/
void SSL_Setup_NOCERT(const SSL_METHOD* meth, SSL_CTX** ctx) {
  SSLeay_add_ssl_algorithms();
  SSL_load_error_strings();
  if (((*ctx) = SSL_CTX_new(meth)) == NULL){
    perror("SSL_CTX_new() client");
    exit(1);
  }

  // Server Authentication to client
  SSL_CTX_set_verify((*ctx),SSL_VERIFY_PEER,NULL);
  SSL_CTX_load_verify_locations((*ctx),CACERT,NULL);
}

/**************************************************************************
 * SSL_Setup: SSL Connection Setup with certificate.                      *
 **************************************************************************/
void SSL_Setup(const char* certf, const char* keyf, const SSL_METHOD* meth, SSL_CTX** ctx){
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  (*ctx) = SSL_CTX_new(meth);
  if (!(*ctx)) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  // No Client Authentication to server
  SSL_CTX_set_verify((*ctx),SSL_VERIFY_NONE,NULL); // whether verify the certificate 
  SSL_CTX_load_verify_locations((*ctx),CACERT,NULL);

  if (SSL_CTX_use_certificate_file((*ctx), certf, SSL_FILETYPE_PEM) <= 0) {
    perror("SSL_CTX_use_certificate_file()\n");
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file((*ctx), keyf, SSL_FILETYPE_PEM) <= 0) {
    perror("SSL_CTX_use_PrivateKey_file()\n");
    ERR_print_errors_fp(stderr);
    exit(4);
  }
  if (!SSL_CTX_check_private_key((*ctx))) {
    perror("SSL_CTX_check_private_key()\n");
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }
}

/**************************************************************************
 * cn_auth: authenticate CN for given certificate                         *
 **************************************************************************/
int cn_auth(SSL* ssl, char* commonName)
{
  X509* peer_cert;
  char* str;
  char peer_CN[256];

  /* Get client's certificate (note: beware of dynamic allocation) - opt */
  if (SSL_get_verify_result(ssl)!=X509_V_OK){
    perror("Certificate doesn't verify.\n");
    X509_free (peer_cert);
    return 0;
  }

  peer_cert = SSL_get_peer_certificate (ssl);
  if (peer_cert == NULL){
    perror ("Peer does not have certificate.\n");
    X509_free (peer_cert);
    return 0;
  }

  // check common name here
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),  NID_commonName, peer_CN, 256);
  if(strcmp(peer_CN, commonName) != 0) {
    printf("peer common name: %s, local request: %s\n", peer_CN, commonName);
    perror("SSL_CTX_use_PrivateKey_file()\n");("Common name doesn't match host name\n");
    X509_free (peer_cert);
    return 0;
  }

  printf("Common Names are the same: %s \n", commonName);
  X509_free (peer_cert);
}

/**************************************************************************
 * get_usrAndpwd: get user name and password from user input              *
 **************************************************************************/
void get_usrAndpwd(char* usr, char* pwd)
{
  printf("    User(most 60 characters): ");
  fgets(usr, 60, stdin);
  printf("Passward(most 80 characters): ");
  fgets(pwd, 80, stdin);

  if (usr[strlen(usr)-1] == '\n')
    usr[strlen(usr)-1] = '\0';
  if (pwd[strlen(pwd)-1] == '\n')
    pwd[strlen(pwd)-1] = '\0';
}

/**************************************************************************
 * chk_usrAndpwd: check user identity                                     *
 **************************************************************************/
int chk_usrAndpwd(char* usr, char* pwd)
{
  int chk = 0, bug;
  int usr_fd;
  char userdb[1000];
  char cusr[60];
  char cpwd[80];
  char* cur_index;
  char* last_index;

  // Client authentication to server, get users information from user database
  usr_fd = open("userdb.txt", O_RDONLY);
  bug = read(usr_fd, userdb, sizeof(userdb)-1);
  if (bug < 0){
    printf("Error from fetching users information from database\n");
    exit(1);
  }
  close(usr_fd);
  userdb[bug] = '\0';
  //do_debug("\nUser database:\n%s", userdb);

  last_index = userdb;
  cur_index = strchr(userdb, '\n');
  while (cur_index != NULL){
    int tem_len = cur_index - last_index;
    memcpy(cusr, last_index, tem_len);
    cusr[tem_len] = '\0';

    //do_debug("\n      received user: %s,    database user: %s\n", usr, cusr);
    if (strcmp(usr, cusr) == 0){
      last_index = cur_index + 1;
      cur_index = strchr(cur_index + 1, '\n');
      if (cur_index == NULL)
	break;
      tem_len = cur_index - last_index;
      memcpy(cpwd, last_index, tem_len);
      cpwd[tem_len] = '\0';

      //do_debug("received password: %s, database password:%s\n\n", pwd, cpwd);
      if (strcmp(pwd, cpwd) != 0)
	break;
      chk = 1;
      break;
    }else{
      cur_index = strchr(cur_index + 1, '\n');
      if (cur_index == NULL)
	break;
      last_index = cur_index + 1;
      cur_index = strchr(cur_index + 1, '\n');
    }
  }

  return chk;
}

/**************************************************************************
 * gen_cmd: generate command                                              *
 **************************************************************************/
void gen_cmd(char* context, char* tem_cmd, char mode)
{
  switch (mode){
  	case '1':
		memcpy(tem_cmd, "1:", 2);
      		memcpy(tem_cmd+2, context, 16);
		tem_cmd[18] = '\n';
		tem_cmd[19] = '\0';
		break;
	case '2':
		memcpy(tem_cmd, "2:", 2);
      		memcpy(tem_cmd+2, context, 16);
		tem_cmd[18] = '\n';
		tem_cmd[19] = '\0';
		break;
	case '3':
		memcpy(tem_cmd, "3", 1);
		tem_cmd[1] = '\n';
		tem_cmd[2] = '\0';
		break;
	case '4':
		memcpy(tem_cmd, "4", 1);
		tem_cmd[1] = '\n';
		tem_cmd[2] = '\0';
		break;
  }
}

/**************************************************************************
 * chg_KeyOrIv: accpet user input for new key or iv                       *
 **************************************************************************/
void chg_KeyOrIv(char* input, char mode)
{
  size_t in_len, i;

  switch (mode){
  	case '1':
		printf("New Key(most 16 char): ");
		break;
	case '2':
		printf("New IV(most 16 char): ");
		break;
  }
  fgets(input, 17, stdin);

  in_len = strlen(input);
  if (in_len < 16){
    for (i = in_len - 1; i < 16; i++)
      input[i] = ' ';
      input[16] = '\0';
    }
  if (input[15] == '\n')
  input[15] = ' ';
}

/**************************************************************************
 * handleErrors: prints errors in encryption or decryption.               *
 **************************************************************************/
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/**************************************************************************
 * encrypt: Encryption.                                                   *
 **************************************************************************/
int encrypt(unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

/**************************************************************************
 * decrypt: Decryption.                                                   *
 **************************************************************************/
int decrypt(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len, plaintext_len;
		
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
	 printf("decrypt new error\n");
	 handleErrors();
  }

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
    printf("decrypt init error\n");
    handleErrors();
  }
  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    printf("decrypt update error\n");
    handleErrors();
  }
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
      	 printf("decrypt final error %s,%d\n",plaintext,len);
 	 handleErrors();
  }
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

/**************************************************************************
 * HMACSHA256: make hash.                                                 *
 **************************************************************************/
void HMACSHA256(unsigned char *data, unsigned int data_len, unsigned char* result, unsigned int result_len, unsigned char *key)
{
	HMAC_CTX ctx;

 	HMAC_CTX_init(&ctx);
 	if(1 != HMAC_Init_ex(&ctx, key, 16, EVP_sha256(), NULL)) {
		printf("HMACSHA HMAC_Init_ex error\n");
		handleErrors();
	}

 	if(1 != HMAC_Update(&ctx, data, data_len)) {
		printf("HMACSHA HMAC_Update error\n");
		handleErrors();
	}
 	if(1 != HMAC_Final(&ctx, result, &result_len)) {
		printf("HMACSHA HMAC_Final error\n");
		handleErrors();
	}
}

/**************************************************************************
 * testHash: authentication of two hash.                                  *
 **************************************************************************/
unsigned int testHash(unsigned char *result, unsigned char *tem_result, unsigned int result_len)
{
	unsigned int i;
        for (i=0; i!=result_len; i++)
        {
                if (tem_result[i]!=result[i])
                {
                        printf("Got %02X instead of %02X at byte %d!\n", result[i], tem_result[i], i);
                        break;
                }
        }
	return i;
}

int main(int argc, char *argv[]) 
{
  int option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int cliserv = -1;    /* must be specified on cmd line */

  char* servcn = "CIS";
  /* A 128 bit default key */
  unsigned char key[] = "default         ";
  /* A 128 bit default IV */
  unsigned char iv[] = "0000000000000000";
  pid_t childpid;
  int pipefd[2];

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }
  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  // client: generate random key and iv
  if (cliserv == CLIENT)
    gen_kv(key, iv);
  printf("New Secret-key: %s\n        New IV: %s\n", key, iv);

  // build pipe and fork child process for UDP Tunnel
  pipe(pipefd);
  fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
  write(pipefd[1], "\n", 1);
  if((childpid = fork()) == -1){
    perror("fork()");
    exit(1);
  }

  if(childpid == 0){
    do_debug("Parent Process\n");
    close(pipefd[0]);
    
    if(cliserv == CLIENT){
      do_debug("Client Authentication\n");

      // -----------------------------------------------
      // Build Client TCP&SSL Connection
      int err;
      int sd;
      struct sockaddr_in sa;
      SSL_CTX* ctx;
      SSL*     ssl;
      X509*    server_cert;
      char*    str;
      char     buf [2000];
      const SSL_METHOD *meth;
      char usr[60];
      char pwd[80];
       
      // Client SSL Setup
      meth = SSLv23_client_method();
      SSL_Setup_NOCERT(meth, &ctx);

      // Create a socket and connect to server using normal socket calls.
      sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
 
      memset (&sa, '\0', sizeof(sa));
      sa.sin_family      = AF_INET;
      sa.sin_addr.s_addr = inet_addr (remote_ip);   // Server IP 
      sa.sin_port        = htons     (1111);          // Server Port number
  
      err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));        CHK_ERR(err, "TCP connect");

      // Now we have fTCP conncetion. Start SSL negotiation.
      if ((ssl = SSL_new (ctx)) == NULL){
        perror("SSL_new() in client");
        exit(1);
      }
      SSL_set_fd (ssl, sd);
      err = SSL_connect (ssl);                     CHK_SSL(err);
      
      // Server Authentication
      if (cn_auth(ssl, servcn) == 0){
	printf("Common Name of Server Authentication failed");
	exit(0);
      }

      // ---------------------------------------------------
      // Client authentication to server, accept user input of user name and passward
      /*while (1){
        get_usrAndpwd(usr, pwd);
        //printf("Input     User: %s\nInput Password: %s\n", usr, pwd);

        // Send user name and passward to server
        err = SSL_write (ssl, usr, strlen(usr));                    CHK_SSL(err);
        err = SSL_write (ssl, pwd, strlen(pwd));                    CHK_SSL(err);

        // wait for response of client authentication
        err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
        buf[err] = '\0';
        if (strcmp(buf, "Client Authentication passed") == 0)
	  break;
        printf("\nWrong user name or password\n\n");
      }*/

      // ---------------------------------------------------
      // Key EXCHANGE - Send secret-key and iv to server 
      err = SSL_write (ssl, key, strlen(key));                        CHK_SSL(err);
      err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
      buf[err] = '\0';
      //printf ("Got %d reponse:'%s'\n", err, buf);
      err = SSL_write (ssl, iv, strlen(iv));                          CHK_SSL(err);
      err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
      buf[err] = '\0';
      //printf ("Got %d reponse:'%s'\n", err, buf);

      // inform UDP Tunnel to change key and iv
      gen_cmd(key, buf, '1');
      write(pipefd[1], buf, strlen(buf));
      //printf("CMD: %s.\n", buf);
      gen_cmd(iv, buf, '2');
      write(pipefd[1], buf, strlen(buf));
      //printf("CMD: %s.\n", buf);
      gen_cmd("", buf, '4');
      write(pipefd[1], buf, strlen(buf));
      //printf("CMD: %s.\n", buf);

      // ---------------------------------------------------
      // Handle user requirement
      while(1){
	char cmd[100];

	printf("\nCOMMAND CHOICE: 1.Key changement 2.IV changement 3.Stop UDP Tunnel\n");
	printf("    USER INPUT: ");
	gets(cmd);
	switch (cmd[0]){
	  case '1':
		chg_KeyOrIv(cmd, '1');
		strcpy(key, cmd);
		gen_cmd(key, cmd, '1');
		printf("New command: %s", cmd);

		write(pipefd[1], cmd, strlen(cmd));
		err = SSL_write (ssl, cmd, strlen(cmd));              CHK_SSL(err);
		err = SSL_read (ssl, cmd, sizeof(cmd) - 1);           CHK_SSL(err);
		cmd[err] = '\0';
		printf("Got reponse:'%s'\n", cmd);
		break;
	  case '2':
		chg_KeyOrIv(cmd, '2');
		strcpy(iv, cmd);
		gen_cmd(iv, cmd, '2');
		printf("New command: %s", cmd);

		write(pipefd[1], cmd, strlen(cmd));
		err = SSL_write (ssl, cmd, strlen(cmd));              CHK_SSL(err);
		err = SSL_read (ssl, cmd, sizeof(cmd) - 1);           CHK_SSL(err);
		cmd[err] = '\0';
		printf("Got reponse:'%s'\n", cmd);
		break;
	  case '3':
		gen_cmd("", cmd, '3');
		printf("New command: %s", cmd);

		write(pipefd[1], cmd, strlen(cmd));
		err = SSL_write (ssl, cmd, strlen(cmd));              CHK_SSL(err);
		err = SSL_read (ssl, cmd, sizeof(cmd) - 1);           CHK_SSL(err);
		cmd[err] = '\0';
		printf("Got reponse:'%s'\n", cmd);
		break;
	  default:
		printf("WRONG INPUT!\n");
	}
      }

      // send SSL/TLS close_notify
      SSL_shutdown (ssl); 
      // Clean up.
      close (sd);
      SSL_free (ssl);
      SSL_CTX_free (ctx);
    }else{
      do_debug("Server Authentication\n");

      int err;
      int listen_sd, sd;
      struct sockaddr_in sa_serv;
      struct sockaddr_in sa_cli;
      size_t client_len;
      SSL_CTX* ctx;
      SSL*     ssl;
      char     buf [2000];
      const SSL_METHOD *meth;
  
      // ----------------------------------------------- 
      // Server SSL Setup
      meth = SSLv23_server_method();
      SSL_Setup(CERTF, KEYF, meth, &ctx);  

      // ----------------------------------------------- 
      // Prepare TCP socket for receiving connections 
      listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket listen_sd");
  
      memset (&sa_serv, '\0', sizeof(sa_serv));
      sa_serv.sin_family      = AF_INET;
      sa_serv.sin_addr.s_addr = INADDR_ANY;
      sa_serv.sin_port        = htons (1111);          // Server Port number
  
      err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof (sa_serv));   CHK_ERR(err, "TCP bind");
	     
      // Receive a TCP connection.      
      err = listen (listen_sd, 5);                    CHK_ERR(err, "TCP listen");
  
      client_len = sizeof(sa_cli);
      sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len); CHK_ERR(sd, "TCP accept");
      close (listen_sd);
      printf ("TCP Connection from %s, port %d\n", inet_ntoa(*((struct in_addr*)&sa_cli.sin_addr.s_addr)), ntohs(sa_cli.sin_port));
  
      // ----------------------------------------------- 
      // TCP connection is ready. Do server side SSL. 
      if ((ssl = SSL_new (ctx)) == NULL){
	perror("SSL_new() in server");
        exit(1);
      }
      SSL_set_fd (ssl, sd);
      err = SSL_accept (ssl);                        CHK_SSL(err);

      // ---------------------------------------------------
      // Client authentication to server
      /*while (1){
	int isAuth;
	char usr[60]; char pwd[80];
	// get user name and password from client
	err = SSL_read (ssl, usr, sizeof(usr) - 1);                     CHK_SSL(err);
	usr[err] = '\0';
	printf("Got username: %s\n", usr);
	err = SSL_read (ssl, pwd, sizeof(pwd) - 1);                     CHK_SSL(err);
	pwd[err] = '\0';
	printf("Got password: %s\n", pwd);
        
	isAuth = chk_usrAndpwd(usr, pwd);
	//printf("\nisAuth: %d\n\n", isAuth);
	if (isAuth == 1){
	  err = SSL_write (ssl, "Client Authentication passed", strlen("Client Authentication passed"));  CHK_SSL(err);
	  break;
	}
	err = SSL_write (ssl, "Client Authentication failed", strlen("Client Authentication failed"));  CHK_SSL(err);
      }*/

      // Key EXCHANGE - Receive message and send reply.
      err = SSL_read (ssl, key, sizeof(key) - 1);                       CHK_SSL(err);
      key[err] = '\0';
      do_debug("Got %d key:%s\n", err, key);
      err = SSL_write (ssl, "Key received", strlen("Key received"));    CHK_SSL(err);
      err = SSL_read (ssl, iv, sizeof(iv) - 1);                         CHK_SSL(err);
      iv[err] = '\0';
      do_debug("Got %d IV:%s\n", err, iv);
      err = SSL_write (ssl, "IV received", strlen("IV received"));      CHK_SSL(err);

      // inform UDP Tunnel to revise key and iv
      gen_cmd(key, buf, '1');
      write(pipefd[1], buf, strlen(buf));
      //printf("CMD: %s.\n", buf);
      gen_cmd(iv, buf, '2');
      write(pipefd[1], buf, strlen(buf));
      //printf("CMD: %s.\n", buf);
      gen_cmd("", buf, '4');
      write(pipefd[1], buf, strlen(buf));
      //printf("CMD: %s.\n", buf);

      // ---------------------------------------------------
      // Handle client requirement
      while (1){
	char cmd[100];
	err = SSL_read (ssl, cmd, sizeof(cmd) - 1);                     CHK_SSL(err);
        cmd[err] = '\0';
	write(pipefd[1], cmd, strlen(cmd));
	do_debug("Got %d bytes request:%s\n", err, cmd);
	switch (cmd[0]){
		case '1':
			memcpy(key, cmd+2, 16);
			//printf("New Key: %s, length: %d\n", key, strlen(key));
			err = SSL_write (ssl, "Key Received", strlen("Key Received"));    CHK_SSL(err);
			break;
		case '2':
			memcpy(iv, cmd+2, 16);
			//printf("New IV: %s, length: %d\n", iv, strlen(iv));
			err = SSL_write (ssl, "IV Received", strlen("IV Received"));    CHK_SSL(err);
			break;
		case '3':
			printf("Stop UDP Tunnel!\n");
			break;
	}
      }

      // Clean up.
      close (sd);
      SSL_free (ssl);
      SSL_CTX_free (ctx);
    }

    //write(pipefd[1], "1:1111111111111111\n", 19);
    //write(pipefd[1], "2:2222222222222222\n", 19);
    sleep(15);
    do_debug("Parent Process normally exit\n");
  }else{
    do_debug("Child Process\n");
    close(pipefd[1]);

    int tap_fd, maxfd;
    char ini_buffer[] = "initialization connection\n";//initialization connection
    uint16_t nread, nwrite;
    //  uint16_t total_len, ethertype;
    char buffer[BUFSIZE];
    struct sockaddr_in local, remote;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    unsigned long int tap2net = 0, net2tap = 0;

    // initialize tun/tap interface
    if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
      my_err("Error connecting to tun/tap interface %s!\n", if_name);
      exit(1);
    }
    do_debug("Successfully connected to interface %s\n", if_name);
  
    // create socket which uses datagram and protocol UDP
    if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket() for sock_fd");
      exit(1);
    }

    if(cliserv==CLIENT){
      // Client, try to connect to server

      // assign the destination address
      memset(&remote, 0, sizeof(remote));
      remote.sin_family = AF_INET;
      remote.sin_addr.s_addr = inet_addr(remote_ip);
      remote.sin_port = htons(port);

      //initialize the connection
      if(sendto(sock_fd, ini_buffer, strlen(ini_buffer), 0, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        perror("sendto() in initialization of client");
        exit(1);
      }

      if(recvfrom(sock_fd, buffer, BUFSIZE, 0, (struct sockaddr *)&remote, &remotelen) < 0) {
        perror("recvfrom() in initialization of server");
        exit(1);
      }

      do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr)); 
    } else {
      // Server, wait for connections

      // avoid EADDRINUSE error on bind()
      if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
        perror("setsockopt()");
        exit(1);
      }
    
      memset(&local, 0, sizeof(local));
      local.sin_family = AF_INET;
      local.sin_addr.s_addr = htonl(INADDR_ANY);
      local.sin_port = htons(port);

      // assign a local protocol address to a socket
      if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
         perror("bind()");
         exit(1);
      }
    
      // wait for connection request
      remotelen = sizeof(remote);
      memset(&remote, 0, remotelen);

      // wait for client's first call to initialize connection
      if(recvfrom(sock_fd, buffer, BUFSIZE, 0, (struct sockaddr *) &remote, &remotelen) < 0) {
          perror("recvfrom() in initialization of connection from server");
          exit(1);
      }

      // send reply data back to client 
      if(sendto(sock_fd, ini_buffer, strlen(ini_buffer), 0, (struct sockaddr *) &remote, sizeof(remote)) < 0) {
        perror("sendto() in initialization of connection from server");
        exit(1);
      }

      do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
    }
    net_fd = sock_fd;

    // use select() to handle two descriptors at once 
    maxfd = (tap_fd > sock_fd)?tap_fd:sock_fd;

    // read from pipe, net_fd, tap_fd
    int isBeg = 0;
    char last_rdbuf[100]; last_rdbuf[0] = '\n'; last_rdbuf[1] = '\0';
    while(1) {
      // check commands from TCP Connection
      int nbytes = 0;
      char readbuffer[100];
      nbytes = read(pipefd[0], readbuffer, sizeof(readbuffer)-1);
      readbuffer[nbytes] = '\0';
      //printf("last_rdbuf: %s, readbuffer: %s\n", last_rdbuf, readbuffer);

      if (strcmp(last_rdbuf, readbuffer) != 0){
	char cmd[100];
	char* last_index = readbuffer;
	char* cur_index = strchr(readbuffer, '\n');
	while (cur_index != NULL){
	  memcpy(cmd, last_index, cur_index-last_index);
	  cmd[cur_index-last_index] = '\0';
	  printf("cmd: %s, length: %d\n", cmd, strlen(cmd));
	  switch (cmd[0]){
		case '1':
			strcpy(key, cmd+2);
			printf("New Key: %s, length: %d\n", key, strlen(key));
			break;
		case '2':
			strcpy(iv, cmd+2);
			printf("New IV: %s, length: %d\n", iv, strlen(iv));
			break;
		case '3':
			exit(0);
			break;
		case '4':
			isBeg = 1;
			break;
	  }
	  last_index = cur_index+1;
	  cur_index = strchr(cur_index+1, '\n');
	}
        strcpy(last_rdbuf, readbuffer);
      }

      if (!isBeg)
	continue;

      int ret;
      fd_set rd_set;
      char global_buffer[BUFSIZE];

      FD_ZERO(&rd_set);
      FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);
      ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
      if (ret < 0 && errno == EINTR){
        continue;
      }

      if (ret < 0) {
        perror("select()");
        exit(1);
      }

      // UDP Tunnel data trasmission
      if(FD_ISSET(tap_fd, &rd_set)){
        // data from tun/tap: just read it and send it to the network 
        nread = cread(tap_fd, global_buffer, BUFSIZE);
        tap2net++;
        do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

        //printf("KEY: %s, IV: %s\n", key, iv);
        unsigned char *plain_text = global_buffer;
        unsigned int plain_len = nread;
        nread = encrypt(plain_text, plain_len, key, iv, buffer);
        //printf("encrypt: %s\n", buffer);

        unsigned char *result;
        unsigned int result_len = 32;
        result = (unsigned char*) malloc(sizeof(char) * result_len);
        unsigned char new_buf[nread+result_len];
        HMACSHA256(buffer, nread, result, result_len, key);
        //printf("hash: %s\n", result);
        memcpy(new_buf, buffer, nread);
        memcpy(new_buf+nread, result, result_len);
        nread = nread + result_len;
        //printf("client data: %s\n", new_buf);
 
        if(sendto(net_fd, new_buf, nread, 0, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
          perror("sendto() in conversation");
          exit(1);
        }
      
        do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nread);
      }

      if(FD_ISSET(net_fd, &rd_set)){
        // receive data from network and write it to the tun/tap interface. 
        if((nread = recvfrom(net_fd, global_buffer, BUFSIZE, 0, (struct sockaddr *)&remote, &remotelen)) < 0) {
          perror("recvfrom() in conversation");
        }
        net2tap++;
        do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
        //printf("server data: %s \n", global_buffer);

        unsigned char *result;
        unsigned int result_len = 32;
        result = (unsigned char*) malloc(sizeof(char) * result_len);
        memcpy(result, global_buffer+nread-result_len, result_len);
        nread = nread - result_len;
        //printf("hash: %s \n", result);

        unsigned char *tem_result;
        tem_result = (unsigned char*) malloc(sizeof(char) * result_len);
        memcpy(buffer, global_buffer, nread);
        //printf("decrypt: %s\n", buffer);
        HMACSHA256(buffer, nread, tem_result, result_len, key);
        if (testHash(result, tem_result, result_len) != result_len){
	   perror("testHash() in conversation: authentication failed\n");
	   continue;
        }
        else
	  printf("Integrity testing passed\n");
 
        //printf("KEY: %s, IV: %s\n", key, iv);
        unsigned char *cipher_text = buffer;
        unsigned int cipher_len = nread;
        nread = decrypt(cipher_text, cipher_len, key, iv, buffer);

        // now buffer[] contains a full packet or frame, write it into the tun/tap interface  
        nwrite = cwrite(tap_fd, buffer, nread);
        do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
      }
    }
    sleep(5);
    do_debug("VPN Tunnel normally close\n");
  }
  
  return(0);
}