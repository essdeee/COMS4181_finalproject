#include "client_utils.h"
#include "base64.h"
#include <memory.h>
#include <string>
#include <stdio.h>
#include <fstream>
#include <unistd.h>
#include <random>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>

/**************************** CONSTANTS ******************************/
const std::string SAVE_CERT_PATH = "client.pem";

/**************************** FUNCTIONS ******************************/
void print_hex(const BYTE* byte_arr, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%.2X", byte_arr[i]);
    }
    printf("\n");
}

std::vector<std::string> split(std::string str,std::string sep)
{
    char* cstr=const_cast<char*>(str.c_str());
    char* current;
    std::vector<std::string> arr;
    current=strtok(cstr,sep.c_str());
    while(current!=NULL){
        arr.push_back(current);
        current=strtok(NULL,sep.c_str());
    }
    return arr;
}

std::string convert_to_lower(const std::string str)
{
    std::string converted_str;
    for(char c : str)
    {
        converted_str.push_back(std::tolower(c));
    }

    return converted_str;
}

bool is_number(const std::string& s)
{
   for(int i = 0; i < s.length(); i++)//for each char in string,
   {
      if(! (s[i] >= '0' && s[i] <= '9' || s[i] == ' ') ) return false;
      //if s[i] is between '0' and '9' of if it's a whitespace (there may be some before and after
      // the number) it's ok. otherwise it isn't a number.
   }

   return true;
}

//CSR Generation start

void csr_to_pem(X509_REQ *csr, uint8_t **csr_bytes, size_t *csr_size)
{
	/* Convert signed csr to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio, csr);
	*csr_size = BIO_pending(bio);
	*csr_bytes = (uint8_t *)malloc(*csr_size + 1);
	BIO_read(bio, *csr_bytes, *csr_size);
	BIO_free_all(bio);
}

std::vector<BYTE> gen_csr(std::string client_name)
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    int             nVersion = 0;
    int             bits = 2048;
    unsigned long   e = RSA_F4;
    X509_REQ        *x509_req = NULL;
    X509_NAME       *x509_name = NULL;
    EVP_PKEY        *pKey = NULL;
    RSA             *tem = NULL;
    BIO             *out = NULL, *bio_err = NULL;
    const char      *szCountry = "US";
    const char      *szProvince = "NY";
    const char      *szCity = "NYC";
    const char      *szOrganization = "Columbia University";
    std::string      szCommonBase = "mail client ";
    //printf("%s\n", (szCommonBase + client_name).c_str());
    const char      *szCommon = "mail client"; //(szCommonBase + client_name).c_str();
    //printf("%s\n", (const unsigned char*)szCommon);
    const char      *szPath = "csr-1.pem";

    std::vector<BYTE> csr_bytes_vec;
    uint8_t* csr_bytes = NULL;
    size_t csr_size = 0;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }
    // 2. set version of x509 req
    x509_req = X509_REQ_new();
    ret = X509_REQ_set_version(x509_req, nVersion);
    if (ret != 1){
        goto free_all;
    }
    // 3. set subject of x509 req
    x509_name = X509_REQ_get_subject_name(x509_req);
    ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
    ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
    ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }   
    ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
    ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }

    // 4. set public key of x509 req
    pKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pKey, r);
    r = NULL;   // will be free rsa when EVP_PKEY_free(pKey)

    ret = X509_REQ_set_pubkey(x509_req, pKey);
    if (ret != 1){
        goto free_all;
    }

    // 5. set sign key of x509 req
    ret = X509_REQ_sign(x509_req, pKey, EVP_sha1());    // return x509_req->signature->length
    if (ret <= 0){
        goto free_all;
    }

    /* Convert csr to PEM format. */
    csr_to_pem(x509_req, &csr_bytes, &csr_size);
    for(int i = 0; i < csr_size; i++)
    {
        csr_bytes_vec.push_back(csr_bytes[i]);
    }

    //out = BIO_new_file(szPath,"w");
    //ret = PEM_write_bio_X509_REQ(out, x509_req);

    // 6. free
free_all:
    X509_REQ_free(x509_req);
    BIO_free_all(out);

    EVP_PKEY_free(pKey);
    BN_free(bne);
   
    return csr_bytes_vec; 
}

//CSR Generation end

//Certificate Saving start

int save_cert(std::string cert_str, std::string file_name)
{
    std::vector<uint8_t> certBytes = base64_decode(cert_str);
    uint8_t *cert_data = certBytes.data();
    int cert_data_size = certBytes.size();
    BIO *bio = NULL;
    X509* cert = NULL;
    // Create a read-only BIO backed by the supplied memory buffer
    bio = BIO_new_mem_buf((void*)cert_data, cert_data_size);
    PEM_read_bio_X509(bio, &cert, NULL, NULL);
    // Cleanup
    BIO_free(bio);

    BIO *out = NULL, *bio_err = NULL;
    const char *cPath = file_name.c_str(); 
    out = BIO_new_file(cPath, "w");
    int ret = PEM_write_bio_X509(out, cert);
    return ret;
}

//Certificate Saving end


//Encrypt Decrypt start
/*
std::string encrypt(const std::string &clear_text, const X509 &enc_crt)
{
	std::string encrypt_text;

    EVP_PKEY * pubkey;
    pubkey = X509_get_pubkey(enc_crt);

    RSA * rsa
    rsa = EVP_PKEY_get1_RSA(pubkey);
 
	// Get the maximum length of the data block that RSA can process at a time
	int key_len = RSA_size(rsa);
	int block_len = key_len-11; // Because the filling method is RSA_PKCS1_PADDING, so you need to subtract 11 from the key_len
 
	// Apply for memory: store encrypted ciphertext data
	char *sub_text = new char[key_len + 1];
	memset(sub_text, 0, key_len + 1);
	int ret = 0;
	int pos = 0;
	std::string sub_str;
	// Encrypt the data in segments (the return value is the length of the encrypted data)
	while (pos < clear_text.length()) {
		sub_str = clear_text.substr(pos, block_len);
		memset(sub_text, 0, key_len + 1);
		ret = RSA_public_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
		if (ret >= 0) {
			encrypt_text.append(std::string(sub_text, ret));
		}
		pos += block_len;
	}
	
	 // release memory  
    EVP_PKEY_free (pubkey);
	RSA_free(rsa);
	delete[] sub_text;
 
	return encrypt_text;
}

int load_priv_key(const char *priv_key_path, EVP_PKEY **priv_key)
{
	BIO *bio = NULL;
	*priv_key = NULL;

	// Load private key.
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, priv_key_path)) goto free;
	*priv_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!priv_key) goto free;
	BIO_free_all(bio);
	return 1;
free:
	BIO_free_all(bio);
	EVP_PKEY_free(*priv_key);
	return 0;
}

std::string decrypt(const std::string &cipher_text, EVP_PKEY **priv_key)
{
	std::string decrypt_text;
    
    RSA *rsa = EVP_PKEY_get1_RSA(priv_key);

	if (rsa == nullptr) {
		 unsigned long err = ERR_get_error(); //Get the error number
		char err_msg[1024] = { 0 };
		 ERR_error_string(err, err_msg); // Format: error:errId: library: function: reason
		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
		return std::string();
	}
 
	 // Get the maximum length of RSA single processing
	int key_len = RSA_size(rsa);
	char *sub_text = new char[key_len + 1];
	memset(sub_text, 0, key_len + 1);
	int ret = 0;
	std::string sub_str;
	int pos = 0;
	 // Decrypt the ciphertext in segments
	while (pos < cipher_text.length()) {
		sub_str = cipher_text.substr(pos, key_len);
		memset(sub_text, 0, key_len + 1);
		ret = RSA_private_decrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
		if (ret >= 0) {
			decrypt_text.append(std::string(sub_text, ret));
			printf("pos:%d, sub: %s\n", pos, sub_text);
			pos += key_len;
		}
	}
	// release memory  
	delete[] sub_text;
	RSA_free(rsa);
 
	return decrypt_text;
}
*/

//Encrypt Decrypt end
