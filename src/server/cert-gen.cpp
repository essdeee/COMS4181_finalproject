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

int pass_cb(char *buf, int size, int rwflag, void *u)
 {

     /* get pass phrase, length 'len' into 'tmp' */
     size_t len = strlen(CA_KEY_PASS.c_str());

     if (len > size)
         len = size;
     memcpy(buf, CA_KEY_PASS.c_str(), len);
     return len;
 }

int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt)
{
	BIO *bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_crt_path)) goto free;
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*ca_crt) goto free;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_key_path)) goto free;
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, pass_cb, NULL);
	if (!ca_key) goto free;
	BIO_free_all(bio);
	return 1;
free:
	BIO_free_all(bio);
	X509_free(*ca_crt);
	EVP_PKEY_free(*ca_key);
	return 0;
}

int generate_set_random_serial(X509 *crt)
{
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

int sign_csr(EVP_PKEY *ca_key, X509 *ca_crt, X509 **crt, X509_REQ *req)
{
	
	EVP_PKEY *req_pubkey = NULL;
	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto free;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt)) goto free;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*365*24*3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself on the client side). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto free;

	X509_REQ_free(req);
	return 1;

free:
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}

void print_bytes(uint8_t *data, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		printf("%c", data[i]);
	}
}

int main(int argc, char *argv[])
{
	// TODO: Will require passing in username as argument to save to the correct folder
	if(argc == 3)
	{
		//read first arg and decode as X509_REQ
		std::string csrStr = argv[1];
		std::string username = argv[2];
		std::cout << csrStr;
		std::vector<uint8_t> csrBytes = base64_decode(csrStr);
		uint8_t *csr_data = csrBytes.data();

		int csr_data_size = csrBytes.size();

		BIO *bio = NULL;
		X509_REQ* req = NULL;

		// Create a read-only BIO backed by the supplied memory buffer
		bio = BIO_new_mem_buf((void*)csr_data, csr_data_size);

		PEM_read_bio_X509_REQ(bio, &req, NULL, NULL);

		// Cleanup
		BIO_free(bio);

		/* Load CA key and cert. */
		EVP_PKEY *ca_key = NULL;
		X509 *ca_crt = NULL;
		if (!load_ca(CA_KEY_PATH.c_str(), &ca_key, CA_CERT_PATH.c_str(), &ca_crt)) 
		{
			std::cerr << "Failed to load CA certificate and/or key!\n";
			return 1;
		}

		/* Sign CSR */
		X509 *crt = NULL;

		int ret = sign_csr(ca_key, ca_crt, &crt, req);
		if (!ret) 
		{
			std::cerr << "Failed to sign the CSR! Could be a problem with CA password.\n";
			return 1;
		}

		BIO *out = NULL, *bio_err = NULL;
		std::string cert_name = username + ".pem";
		std::string cert_path = CERTS_PREFIX + cert_name;
		const char  *cPath = cert_path.c_str();
		out = BIO_new_file(cPath,"w");
		ret = PEM_write_bio_X509(out, crt);

		/* Convert key and certificate to PEM format. */
		uint8_t *crt_bytes = NULL;
		size_t crt_size = 0;

		crt_to_pem(crt, &crt_bytes, &crt_size);
		
		std::string crt_str = base64_encode(crt_bytes, crt_size);
		write_file(crt_str, TMP_CERT_FILE);
		
		/* Print key and certificate. */
		//print_bytes(crt_bytes, crt_size);

		/* Free stuff. */
		EVP_PKEY_free(ca_key);
        BIO_free_all(out);
		X509_free(ca_crt);
		X509_free(crt);
		free(crt_bytes);

		return 0;
	}
	else
	{
		std::cerr << "cert-gen received invalid number of arguments.\n";
		return 1;
	}
}
