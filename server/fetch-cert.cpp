#include <stdint.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <vector>
#include "base64.h"
#include "server_utils.h"
#include <cstring>

int load_cert(const char *filepath, X509 **crt)
{
	BIO *bio = NULL;
	*crt = NULL;

	/* Load encryption certificate. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, filepath)) goto free;
	*crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*crt) goto free;
	BIO_free_all(bio);
	return 0;
free:
	BIO_free_all(bio);
	X509_free(*crt);
	return 1;
}

void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size)
{
	/* Convert signed certificate to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	*crt_size = BIO_pending(bio);
	*crt_bytes = (uint8_t *)malloc(*crt_size + 1);
	BIO_read(bio, *crt_bytes, *crt_size);
	BIO_free_all(bio);
}


int main( int argc, const char* argv[] )
{
	if(argc == 3)
    {
		std::string username = argv[1];
		std::string cert_type = argv[2];
		X509 *crt = NULL;
		std::string cert_filename;

		if(cert_type == "sign")
		{
			cert_filename = "sign.pem";
		}
		else if(cert_type == "encrypt")
		{
			cert_filename = "encrypt.pem";
		}
		else
		{
			std::cerr << "fetch-cert received invalid cert_type argument.\n";
			return 1;
		}
		
		std::string cert_path = username + "/" + cert_filename;
		if (load_cert(cert_path.c_str(), &crt))
		{
			std::cerr << "fetch-cert could not load the certificate for user: " + username << std::endl;
			return 1;
		}

		uint8_t *crt_bytes = NULL;
		size_t crt_size = 0;
		crt_to_pem(crt, &crt_bytes, &crt_size);
		std::string crt_str = base64_encode(crt_bytes, crt_size);

		write_file(crt_str, "tmp-crt");
	}
	else
	{
			std::cerr << "fetch-cert received invalid number of arguments.\n";
			return 1;
	}
}
