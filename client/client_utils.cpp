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

std::string generateSalt() 
{
    const char alphanum[] =
    "./0123456789ABCDEFGHIJKLMNOPQRST"
    "UVWXYZabcdefghijklmnopqrstuvwxyz"; //salt alphanum

    std::random_device rd;  //Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<> dis(0, sizeof(alphanum)-1); //Uniform distribution on an interval
    char salt[17];          // 16 useful characters in salt (as in original code)
    salt[0] = '$';          // $6$ encodes for SHA512 hash
    salt[1] = '6';
    salt[2] = '$';
    for(int i = 3; i < 16; i++) 
    {
        salt[i] = alphanum[dis(gen)];
    }
    salt[16] = '\0';
    return std::string(salt);
}

std::string hashPassword(std::string password)
{
    std::string salt = generateSalt();
    std::string hash = crypt(password.c_str(), salt.c_str());
    return hash;
}

void print_hex(const BYTE* byte_arr, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%.2X", byte_arr[i]);
    }
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

uint8_t* gen_csr(std::string client_name)
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

    //out = BIO_new_file(szPath,"w");
    //ret = PEM_write_bio_X509_REQ(out, x509_req);

    // 6. free
free_all:
    X509_REQ_free(x509_req);
    BIO_free_all(out);

    EVP_PKEY_free(pKey);
    BN_free(bne);
   
    return csr_bytes; 
}

//CSR Generation end

//Certificate Saving start

void save_cert(std::string cert_str)
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
    const char *cPath = "client.pem";
    out = BIO_new_file(cPath, "w");
    int ret = PEM_write_bio_X509(out, cert);
}

//Certificate Saving end


/*
NOTE: THIS HASHES THE NULL-TERMINATING CHARACTER
void iterate_sha256(std::string password, BYTE* final_hash, int rounds)
{
    // Convert password into BYTE array of chars
    BYTE password_bytes[password.length()+1];
    for(int i = 0; i < password.length(); i++)
    {
        password_bytes[i] = password[i];
    }
    password_bytes[password.length()] = '\0';

    // Iteratively hash 10k times

    // First time needs to hash variable length password_bytes
    BYTE buf[SHA256_BLOCK_SIZE];
    SHA256_CTXX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, password_bytes, password.length() + 1);
    sha256_final(&ctx, buf);
    
    // Other 10,000 times hashes buffer (32 bytes)
    BYTE new_buf[SHA256_BLOCK_SIZE];
    for(int i = 0; i < rounds; i++)
    {
        SHA256_CTXX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, buf, password.length() + 1);
        sha256_final(&ctx, new_buf);
        memcpy(buf, new_buf, sizeof(buf));
    }

    // Update the final hash
    for(int i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        final_hash[i] = buf[i];
    }
}

bool simpleSHA512(std::string password, BYTE* buffer)
{
    // Convert password into BYTE array of chars 
    // NOTE: Null-terminating character is NOT hashed.
    BYTE password_bytes[password.length()];
    for(int i = 0; i < password.length(); i++)
    {
        password_bytes[i] = password[i];
    }

    SHA512_CTX context;
    if(!SHA512_Init(&context))
        return false;

    if(!SHA512_Update(&context, password_bytes, password.length()))
        return false;

    if(!SHA512_Final(buffer, &context))
        return false;

    return true;
}
*/
