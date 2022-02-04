#include "Enclave_t.h"
#include "Ocall_wrappers.h"
#include <fstream>
#include "string.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "math.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
char file[2048];
size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(file);
uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
sgx_status_t status;
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
int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
}
static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printe("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

static int password_cb(char *buf, int size, int rwflag, void *password)
{
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

static EVP_PKEY *generatePrivateKey()
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    return pkey;
}

static X509 *generateCertificate(EVP_PKEY *pkey)
{
    X509 *x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), (long)60*60*24*365);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"YourCN", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_md5());
    return x509;
}

static void configure_context(SSL_CTX *ctx)
{
	EVP_PKEY *pkey = generatePrivateKey();
	X509 *x509 = generateCertificate(pkey);

	SSL_CTX_use_certificate(ctx, x509);
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	SSL_CTX_use_PrivateKey(ctx, pkey);

	RSA *rsa=RSA_generate_key(512, RSA_F4, NULL, NULL);
	SSL_CTX_set_tmp_rsa(ctx, rsa);
	RSA_free(rsa);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
}

static int create_socket_server(int port)
{
    int s, optval = 1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printe("sgx_socket");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
        printe("sgx_setsockopt");
        exit(EXIT_FAILURE);
    }
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printe("sgx_bind");
        exit(EXIT_FAILURE);
    }
    if (listen(s, 128) < 0) {
        printe("sgx_listen");
        exit(EXIT_FAILURE);
    }
    return s;
}

void ecall_start_tls_server(void)
{
	int abc[20][4] = 
	{
		{269,260,67,96}, 
		{359,387,84,91}, 
		{291,209,67,89}, 
		{202,222,84,88}, 
		{195,200,84,87}, 
		{331,90,73,86}, 
		{219,251,78,85}, 
		{366,359,78,85}, 
		{252,184,163,84}, 
		{315,354,84,84}, 
		{348,127,163,83}, 
		{367,275,163,83}, 
		{411,364,168,81}, 
		{293,340,78,80}, 
		{380,284,73,77}, 
		{361,209,157,47}, 
		{192,314,140,46}, 
		{200,125,84,46}, 
		{331,72,73,46}, 
		{185,317,45,45}
	};
    	int sock;
    	SSL_CTX *ctx;
    	printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    	init_openssl();
    	ctx = create_context();
    	configure_context(ctx);
    	sock = create_socket_server(4431);
    	if(sock < 0) 
    	{
        	printe("create_socket_client");
        	exit(EXIT_FAILURE);
    	}
    	while(1) 
    	{    
        	struct sockaddr_in addr;
        	int len = sizeof(addr);
        	SSL *cli;
        	char read_buf[2048];
        	int r = 0;
        	printl("Wait for new connection...\n");
        	int client = accept(sock, (struct sockaddr*)&addr, &len);
        	if (client < 0) 
        	{
            		printe("Unable to accept");
            		exit(EXIT_FAILURE);
        	}
		cli = SSL_new(ctx);
        	SSL_set_fd(cli, client);
		if (SSL_accept(cli) <= 0) 
		{
            		printe("SSL_accept");
            		exit(EXIT_FAILURE);
        	}
        	r = SSL_read(cli, read_buf, sizeof(read_buf));
        	//printl("read_buf: length = %d : %s", r, read_buf);
		printl("Received pruned .xyt file.\n");
		printl("Transforming into usable array format.\n");
        	char *array[80];
		int i=0;
		array[i] = strtok(read_buf," ");
		while(array[i]!=NULL)
		{
   			array[++i] = strtok(NULL," ");
		}
        	int xyt[20][4];
        	int eighty =0;
        	for(i=0;i<20;i++)
        	{
        		for(int j=0;j<4;j++)
        		{
        			xyt[i][j]=atoi(array[eighty++]);
        		}
        	}
               memset(read_buf, 0, sizeof(read_buf));        
               printl("Checking if the biometric reference provided matches with stored template using home-brewn bozoroth3.\n");
		float point[20]={0.0};
		float b = 0.2;
		int val = 0;
		int points = 0;
		printl("The distance values are:\n");
		for(i=0;i<20;i++)
		{
			val = abs(xyt[i][2] - abc[i][2]) < (360 - abs(xyt[i][2] - abc[i][2]) ) ? abs(xyt[i][2] - abc[i][2]) : (360 - abs(xyt[i][2] - abc[i][2]) ) ;
			point[i] = sqrt( pow(( xyt[i][0] - abc[i][0] ),2) + pow(( xyt[i][1] - abc[i][1] ),2) ) + b * val;  
			printl("%f\n",point[i]);
			if(point[i] < 200.0)
			{
				points++;
			}	
		
		}
		printl("The number of values within permissable limits are:\n");
		printl("%d\n",points);
		if(points >= 13)
		{
			const char *stat = "T\0";
    			SSL_write(cli, stat, strlen(stat)+1);
    			printl("Fingerprints match. Waiting for further commands.\n");
			const char *chars = "Fingerprints are a match!\nEnter SEAL (or) UNSEAL followed by the file name.\0";
    			SSL_write(cli, chars, strlen(chars)+1);
    			memset(read_buf, 0, sizeof(read_buf));
    			SSL_read(cli, read_buf, sizeof(read_buf));//Command
    			if(read_buf[0] == 'S')
    			{
    			//seal operation	
    				memset(file, 0, sizeof(file));
    				printl("Seal command and content received.\n");
    				SSL_read(cli, file, sizeof(file));//content to be sealed
    				printl("Content is:\n");
    				printl("%s\n",file);
    				printl("Sealing...\n");
    				status = seal(  (uint8_t*)&file, sizeof(file),
            				(sgx_sealed_data_t*)sealed_data, sealed_size);
    				if(status == 0)
    				{
    					printl("Sealing successful.\n");
    					const char *st = "Sealing Successful!\0";
    					SSL_write(cli, st, strlen(st)+1);
    				}
    				else
    				{
    					printl("Sealing unsuccessful.\n");
    					const char *s = "Sealing Unsuccessful:( Try again.\0";
    					SSL_write(cli, s, strlen(s)+1);
    				}	
    			}
    			else if(read_buf[0] == 'U')
    			{
    			//unseal operation
    			printl("Unseal command and filename received.\n");
    			char unsealed[2048];
    			printl("Unsealing...\n");
    			status = unseal((sgx_sealed_data_t*)sealed_data, sealed_size,
            				(uint8_t*)&unsealed, sizeof(unsealed));
    			if(status == 0)
    			{
    				printl("Unsealing successful.\n");
    				const char *ts = "Unsealing Successful!\0";
    				SSL_write(cli, ts, strlen(ts)+1);
    			}
    			else
    			{	
    				printl("Unsealing unsuccessful.\n");
    				const char *t = "Unsealing Unsuccessful:( Try again.\0";
    				SSL_write(cli, t, strlen(t)+1);
    			}
    			printl("Unsealed content is:\n");
    			printl("%s\n",unsealed);
    			SSL_write(cli, unsealed, strlen(unsealed)+1); //give client back unsealed content.
    		}
    		
	}
	else
	{
		//send failure
		const char *stat = "F\0";
    		SSL_write(cli, stat, strlen(stat)+1);
    		printl("Fingerprints do not match.\n");
		const char *chars = "Fingerprints do not match! Please try again.\0";
    		SSL_write(cli, chars, strlen(chars)+1);
	}
        SSL_free(cli);
        sgx_close(client);
    }
    sgx_close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
