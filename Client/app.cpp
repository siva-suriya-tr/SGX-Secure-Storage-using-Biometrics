#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unistd.h>
using namespace std;
//Not sure what headers are needed or not
//This code (theoretically) writes "Hello World, 123" to a socket over a secure TLS connection
//compiled with g++ -Wall -o client.out client.cpp -L/usr/lib -lssl -lcrypto
//Based off of: https://www.cs.utah.edu/~swalton/listings/articles/ssl_client.c
//Some of the code was taken from this post: https://stackoverflow.com/questions/52727565/client-in-c-use-gethostbyname-or-getaddrinfo

const int ERROR_STATUS = -1;



static void init_openssl()
{
	OpenSSL_add_ssl_algorithms();
	OpenSSL_add_all_ciphers();
	SSL_load_error_strings();
}

static void cleanup_openssl()
{
    EVP_cleanup();
}


/* inet_aton from https://android.googlesource.com/platform/bionic.git/+/android-4.0.1_r1/libc/inet/inet_aton.c */
static int inet_aton(const char *cp, struct in_addr *addr)
{
	u_long val, base, n;
	char c;
	u_long parts[4], *pp = parts;

	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
		val = 0; base = 10;
		if (*cp == '0') {
			if (*++cp == 'x' || *cp == 'X')
				base = 16, cp++;
			else
				base = 8;
		}
		while ((c = *cp) != '\0') {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				cp++;
				continue;
			}
			if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) + 
					(c + 10 - (islower(c) ? 'a' : 'A'));
				cp++;
				continue;
			}
			break;
		}
		if (*cp == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16-bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3 || val > 0xff)
				return (0);
			*pp++ = val, cp++;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && (!isascii(*cp) || !isspace(*cp)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

		case 1:				/* a -- 32 bits */
			break;

		case 2:				/* a.b -- 8.24 bits */
			if (val > 0xffffff)
				return (0);
			val |= parts[0] << 24;
			break;

		case 3:				/* a.b.c -- 8.8.16 bits */
			if (val > 0xffff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16);
			break;

		case 4:				/* a.b.c.d -- 8.8.8.8 bits */
			if (val > 0xff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
			break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}

static in_addr_t inet_addr(const char *cp)
{
	struct in_addr val;

	if (inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}

static int create_socket_client(const char *ip, uint32_t port) 
{
	int sockfd;
	struct sockaddr_in dest_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0) {
		printf("socket");
		exit(EXIT_FAILURE);
	}

	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(port);
	dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
	memset(&(dest_addr.sin_zero), '\0', 8);

	printf("Connecting...");
	if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
		printf("Cannot connect");
        exit(EXIT_FAILURE);
	}

	return sockfd;
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

string exec(string command) {
   char buffer[128];
   string result = "";

   // Open pipe to file
   FILE* pipe = popen(command.c_str(), "r");
   if (!pipe) {
      return "popen failed!";
   }

   // read till end of process:
   while (!feof(pipe)) {

      // use buffer to read and add to result
      if (fgets(buffer, 128, pipe) != NULL)
         result += buffer;
   }

   pclose(pipe);
   return result;
}
SSL_CTX *InitSSL_CTX(void)
{
    const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (ctx == nullptr)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int OpenConnection(const char *hostname, const char *port)
{
    struct hostent *host;
    if ((host = gethostbyname(hostname)) == nullptr)
    {
        perror(hostname);
        exit(EXIT_FAILURE);
    }

    struct addrinfo hints = {0}, *addrs;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const int status = getaddrinfo(hostname, port, &hints, &addrs);
    if (status != 0)
    {
        fprintf(stderr, "%s: %s\n", hostname, gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    int sfd, err;
    for (struct addrinfo *addr = addrs; addr != nullptr; addr = addr->ai_next)
    {
        sfd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
        if (sfd == ERROR_STATUS)
        {
            err = errno;
            continue;
        }

        if (connect(sfd, addr->ai_addr, addr->ai_addrlen) == 0)
        {
            break;
        }

        err = errno;
        sfd = ERROR_STATUS;
        close(sfd);
    }

    freeaddrinfo(addrs);

    if (sfd == ERROR_STATUS)
    {
        fprintf(stderr, "%s: %s\n", hostname, strerror(err));
        exit(EXIT_FAILURE);
    }
    return sfd;
}

void DisplayCerts(SSL *ssl)
{
    X509 *cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != nullptr)
    {
        printf("Server certificates:\n");
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        delete line;
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        delete line;
        X509_free(cert);
    }
    else
    {
        printf("Info: No client certificates configured.\n");
    }
}

void swap(int *xp, int *yp)
{
    int temp = *xp;
    *xp = *yp;
    *yp = temp;
}
 
// A function to implement bubble sort
void bubbleSort(int arr[][4], int n)
{
    int i, j;
    for (i = 0; i < n-1; i++)    
     
    // Last i elements are already in place
    for (j = 0; j < n-i-1; j++)
        if (arr[j][3] < arr[j+1][3])
        {
            swap(&arr[j][3], &arr[j+1][3]);
            swap(&arr[j][0], &arr[j+1][0]);
            swap(&arr[j][1], &arr[j+1][1]);
            swap(&arr[j][2], &arr[j+1][2]);
        }
}
template<typename T, int height, int width>
std::ostream& writemap(std::ostream& os, T (&xyt)[height][width])
{
    for (int i = 0; i < height; ++i)
    {
        for (int j = 0; j < width; ++j)
        {
            os << xyt[i][j]<<" ";
        }
        os<<"\n";
    }
    return os;
}
int main(int argc, char const *argv[])
{
    //exec("export PATH=$PATH:/home/siva/Desktop/nbis/build/bin");
    exec("cwsq .75 wsq fingerprint/101_1.tif -r 448,478,8");
    printf("Using cwsq on fingerprint reference file to generate .wsq file.\n");
    exec("mindtct -b -m1 fingerprint/101_1.wsq fingerprint/101_1");
    printf("Using mindtct on generated .wsq file to generate .xyt file.\n");
    remove("fingerprint/101_1.brw");
    remove("fingerprint/101_1.dm");
    remove("fingerprint/101_1.hcm");
    remove("fingerprint/101_1.lcm");
    remove("fingerprint/101_1.lfm");
    remove("fingerprint/101_1.min");
    remove("fingerprint/101_1.qm");
    remove("fingerprint/101_1.wsq");
    printf("Deleted rest of the files.\n");
    
    printf("Pruning .xyt file to just the best 20 rows based on their quality score.\n");
    FILE *myFile;
    int i, n, arr[300][4], row=0, col, zero=(int)'0';
    char line[512];
    myFile=fopen("fingerprint/101_1.xyt","r");
    if (myFile)
    {
    	while(fgets(line,512,myFile))
    	{
        	col = 0;
        	n = 0;
        	for(i=0;i<strlen(line);i++)
        	{
                	if(line[i]>='0' && line[i]<='9') 
                	{
                		n=10*n + (line[i]-zero);
                	}
                       else
                       {
                       	arr[row][col++]=n;
                               n=0;
                       }
                }
                row++;
        }
        fclose(myFile);
        remove("fingerprint/101_1.xyt");
	printf("Sorting rows based on quality score.\n");
        bubbleSort(arr, row);
    } 
    else
    {
        printf("Error: unable to open .xyt file. Check path.\n");
        return 1;
    }


	int xyt[20][4];
	for(i=0;i<20;i++)
	{
		xyt[i][0]=arr[i][0];
		xyt[i][1]=arr[i][1];
		xyt[i][2]=arr[i][2];
		xyt[i][3]=arr[i][3];
	}
	printf("Deleting everything except top 20.\n");
	const int width = 4;
	const int height = 20;
	std::fstream of("twenty.xyt", std::ios::out | std::ios::app);
    	if(of.is_open())
	{
	        writemap(of, xyt);
	        of << "\0";
	        of.close();
	}  
    
	FILE    *infile;
	char    *buffer;
	long    numbytes;
	infile = fopen("twenty.xyt", "r");
	if(infile == NULL)
    		return 1;
	fseek(infile, 0L, SEEK_END);
	numbytes = ftell(infile);
	fseek(infile, 0L, SEEK_SET);
	buffer = (char*)calloc(numbytes, sizeof(char));	
	if(buffer == NULL)
    		return 1;
	fread(buffer, sizeof(char), numbytes, infile);
	remove("twenty.xyt");
	fclose(infile);
	printf("The final .xyt file contents consists of:\n");
	printf("%s\n",buffer);

	printf("Establishing SSL connection to the Server's Enclave.\n");
	SSL *ssl;
	int sock;
	SSL_CTX *ctx;
	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
	const char *serv_ip = "127.0.0.1";
	uint32_t serv_port = 4431;
    	init_openssl();
    	ctx = create_context();
    	SSL_CTX_set_options(ctx, flags);
    	sock = create_socket_client(serv_ip, serv_port);
    	ssl = SSL_new(ctx);
    	SSL_set_fd(ssl, sock);
    	if (SSL_connect(ssl) <= 0)
    	{
        	printf("SSL_connect failed.");	
        	exit(EXIT_FAILURE);
	}
 	printf("\nConnection to server established.\n");
    	SSL_write(ssl, buffer, strlen(buffer));	//top 20 .xyt
    	printf("Sending pruned .xyt content to server.\n");
    	char read_buf[2048];
    	SSL_read(ssl, read_buf, sizeof(read_buf));	//T or F (to check if fingerprints match)
    	
    	if(read_buf[0] == 'T')
    	{
    		memset(read_buf, 0, sizeof(read_buf));   
    		SSL_read(ssl, read_buf, sizeof(read_buf)); //Fingerprints are a match message.
    		printf("\n%s\n",read_buf);
    		char input[100];
    		scanf("%[^\n]s",input); //Ask user for operation.
    		char *array[2];
    		int i=0;
		array[i] = strtok(input," ");
		while(array[i]!=NULL)
		{
   			array[++i] = strtok(NULL," ");
		}
		if(array[0][0]=='S' || array[0][0]=='s')
		{
			printf("Sending command and file to server.\n");
			const char *c = "SEAL\0";
    			SSL_write(ssl, c, strlen(c)+1); //Send SEAL Command to Server.
    			std::ifstream inFile;
    			inFile.open(array[1]);
    			std::stringstream strStream;
    			strStream << inFile.rdbuf(); 
    			std::string str = strStream.str(); 
    			const char * file = str.c_str();
    			SSL_write(ssl, file, strlen(file)+1);//Send content to be Sealed.
    			memset(read_buf, 0, sizeof(read_buf));   
    			SSL_read(ssl, read_buf, sizeof(read_buf));//Get message regarding Sealing success/failure.
    			printf("\n%s\n",read_buf);
		}
		else if(array[0][0]=='U' || array[0][0]=='u')
		{
			const char *f = "UNSEAL\0";
			printf("Sending command and file to server.\n");
    			SSL_write(ssl, f, strlen(f)+1); //Send UNSEAL command to server.	
    			memset(read_buf, 0, sizeof(read_buf));   
    			SSL_read(ssl, read_buf, sizeof(read_buf));//Get message regarding Sealing success/failure.
    			printf("\n%s\n",read_buf);
    			memset(read_buf, 0, sizeof(read_buf));   
    			SSL_read(ssl, read_buf, sizeof(read_buf));//Unsealed content.
    			printf("\n%s\n",read_buf);
		}   	
    	
    	}
    	else if(read_buf[0] == 'F')
    	{
    		memset(read_buf, 0, sizeof(read_buf));   
    		SSL_read(ssl, read_buf, sizeof(read_buf));//FIngerprint failed, try again.
    		printf("\n%s\n",read_buf);
    	}
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
