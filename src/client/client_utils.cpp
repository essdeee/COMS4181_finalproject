#include "client_utils.h"
#include <memory.h>
#include <string>
#include <stdio.h>
#include <fstream>
#include <unistd.h>
#include <random>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

/**************************** CONSTANTS ******************************/
const std::string SAVE_CERT_PATH = "keypair/client.pem";
// const std::string PRIVATE_KEY_PATH = "keypair/client.key.pem"; Deprecated after switch to multiuser system
const std::string PRIVATE_KEY_SUFFIX = ".key.pem";
const std::string PRIVATE_KEY_PREFIX = "keypair/";
const std::string NEW_KEY_PATH = "keypair/new.key.pem";
const std::string CA_CERT_PATH = "keypair/cacert.pem"; // Trusted CA Cert for authenticating the server
const std::string CAT_CERT_KEY_PATH = "keypair/client_cert_key.pem";

const std::string SIGN_TMP = "tmp/sign-tmp.txt";
const std::string TMP_DECODED_MSG = "tmp/decoded-msg-tmp.txt";
const std::string TMP_DECODED_CERT = "tmp/decoded-cert-temp.pem";
const std::string TMP_DECRYPTED_MSG = "tmp/decrypted-tmp.txt";
const std::string TMP_ENCRYPT_FILE = "tmp/tmp_encr.txt";
const std::string VERIFIED_MSG = "tmp/recvd_msg.txt";
const std::string CURRENT_LOGIN_FILE = "keypair/current_login";

/**************************** FUNCTIONS ******************************/
void print_hex(const BYTE* byte_arr, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%.2X", byte_arr[i]);
    }
    printf("\n");
}

bool validMailboxChars(const std::string &str)
{    
    if (str.empty())
    {
        return false;
    }

    // First character must be alphabetic
    if (!std::isalpha(str[0]))
    {
        return false;
    }

    for(char const &c : str)
    {
        if (!std::isalpha(c) && 
        !std::isdigit(c) && 
        c != '+' && c != '-' && c != '_')
        {
            return false;
        }
    }

    return true;
}

bool validPasswordChars(const std::string &str)
{    
    if (str.empty())
    {
        return false;
    }

    // First character must be alphabetic
    if (!std::isalpha(str[0]))
    {
        return false;
    }

    for(char const &c : str)
    {
        if (!std::isalpha(c) && 
        !std::isdigit(c) && 
        c != '+' && c != '-' && c != '_' 
        && c != '!' && c != '?' && c != '$')
        {
            return false;
        }
    }

    return true;
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

int private_key_to_pem(RSA *private_key, std::string file_name)
{
    FILE * fp = fopen(file_name.c_str(), "w");
    if(!PEM_write_RSAPrivateKey(fp, private_key, NULL, 0, 0, NULL, NULL))
    {
        return 1;
    }
    fflush(fp);
    fclose(fp);
    return 0;
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
    const char      *szCommon = client_name.c_str(); //(szCommonBase + client_name).c_str();
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
    private_key_to_pem(r, NEW_KEY_PATH.c_str());

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
    BIO_free(out);
    return ret;
}

//Certificate Saving end

void appendFile(std::string const& outFile, std::string const& inFile) 
{
    static size_t const BufferSize = 8192; // 8 KB
    std::ofstream out(outFile, std::ios_base::app |
                               std::ios_base::binary |
                               std::ios_base::out);

    std::ifstream in(inFile, std::ios_base::binary |
                             std::ios_base::in);

    std::vector<char> buffer(BufferSize);
    while (in.read(&buffer[0], buffer.size())) {
        out.write(&buffer[0], buffer.size());
    }

    // Fails when "read" encounters EOF,
    // but potentially still writes *some* bytes to buffer!
    out.write(&buffer[0], in.gcount());
    out.close();
    in.close();
}

/** CRYPTO ROUTINES (ENCRYPT, DECRYPT, SIGN, VERIFY) START HERE **/
int sign(std::string cert_key, std::string file_to_sign, std::string signed_file)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    /*
     * For simple S/MIME signing use CMS_DETACHED. On OpenSSL 1.0.0 only: for
     * streaming detached set CMS_DETACHED|CMS_STREAM for streaming
     * non-detached set CMS_STREAM
     */
    int flags = CMS_DETACHED | CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key */
    tbio = BIO_new_file(cert_key.c_str(), "r");

    if (!tbio)
        goto err;

    scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!scert || !skey)
        goto err;

    /* Open content being signed */
    in = BIO_new_file(file_to_sign.c_str(), "r");

    if (!in)
        goto err;

    /* Sign content */
    cms = CMS_sign(scert, skey, NULL, in, 0);

    if (!cms)
        goto err;

    out = BIO_new_file(signed_file.c_str(), "w");
    if (!out)
        goto err;

    if (!(flags & CMS_STREAM))
        BIO_reset(in);

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, 0))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(scert);
    EVP_PKEY_free(skey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}

std::vector<BYTE> encrypt(std::string cert_key, std::string file_path)
{
    BIO *in = NULL;
    BIO *out = NULL;
    BIO *tbio = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    std::ifstream file;
    
    std::vector<BYTE> buffer;
    size_t length;

    /*
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    tbio = BIO_new_file(cert_key.c_str(), "r");

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();

    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /*
     * sk_X509_pop_free will free up recipient STACK and its contents so set
     * rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */
    in = BIO_new_file(file_path.c_str(), "r");
    
    if (!in)
        goto err;

    /* encrypt content */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);

    if (!cms)
        goto err;

    out = BIO_new_file(TMP_ENCRYPT_FILE.c_str(), "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    /** Read file to vector<BYTES> and return **/
    file.open(TMP_ENCRYPT_FILE.c_str(), std::ios_base::binary);
    file.seekg(0, file.end);
    length = file.tellg();
    file.seekg(0, file.beg);

    //read file
    if (length > 0) {
        buffer.resize(length);    
        file.read((char *)&buffer[0], length);
    }
    file.close();

    /** Delete tmp_encr (tmp file) **/
    if( remove(TMP_ENCRYPT_FILE.c_str()) != 0 )
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return buffer;
}

int decrypt(std::string cert_key, std::string file_path, std::string decrypted_file_path)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate and private key */
    tbio = BIO_new_file(cert_key.c_str(), "r");

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!rcert || !rkey)
        goto err;

    /* Open S/MIME message to decrypt */
    in = BIO_new_file(file_path.c_str(), "r");

    if (!in)
        goto err;

    /* Parse message */
    cms = SMIME_read_CMS(in, NULL);

    if (!cms)
        goto err;

    out = BIO_new_file(decrypted_file_path.c_str(), "w");
    if (!out)
        goto err;

    /* Decrypt S/MIME message */
    if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}

int verify(std::string cert_key, std::string file_to_verify, std::string verified_file)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    CMS_ContentInfo *cms = NULL;

    STACK_OF(X509) *stack = NULL;
    X509 *signcert = NULL;
    BIO *tbio2 = NULL;

    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */
    st = X509_STORE_new();

    /* Read in CA certificate */
    tbio = BIO_new_file(CA_CERT_PATH.c_str(), "r");

    if (!tbio)
        goto err;

    if (!tbio)
        goto err;

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!cacert)
        goto err;

    if (!X509_STORE_add_cert(st, cacert))
        goto err;

    /* Read in signing certificate */
    tbio2 = BIO_new_file(cert_key.c_str(), "r");

    if (!tbio2)
        goto err;

    signcert = PEM_read_bio_X509(tbio2, NULL, 0, NULL);

    if (!signcert)
        goto err;

    if(!sk_X509_push(stack, signcert))
        goto err;

    /* Open message being verified */
    in = BIO_new_file(file_to_verify.c_str(), "r");

    if (!in)
        goto err;

    /* parse message */
    cms = SMIME_read_CMS(in, &cont);

    if (!cms)
        goto err;

    /* File to output verified content to */
    out = BIO_new_file(verified_file.c_str(), "w");
    if (!out)
        goto err;

    if (!CMS_verify(cms, stack, st, cont, out, 0)) {
        fprintf(stderr, "Verification Failure\n");
        goto err;
    }

    fprintf(stderr, "Verification Successful!\n");

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(cacert);
    X509_free(signcert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    BIO_free(tbio2);
    return ret;
}


static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(BYTE c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(BYTE const* buf, unsigned long bufLen) {
  std::string ret;
  int i = 0;
  int j = 0;
  BYTE char_array_3[3];
  BYTE char_array_4[4];

  while (bufLen--) {
    char_array_3[i++] = *(buf++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';
  }

  return ret;
}

std::vector<BYTE> base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  BYTE char_array_4[4], char_array_3[3];
  std::vector<BYTE> ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
          ret.push_back(char_array_3[i]);
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
  }

  return ret;
}

int replace_file(std::string out, std::string in)
{
    std::ifstream infile(in, std::ios_base::in | std::ios_base::binary);
    std::ofstream outfile(out, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);

    if(infile.good() && outfile.good())
    {
        char buf[1024];
        do {
            infile.read(&buf[0], 1024);
            outfile.write(&buf[0], infile.gcount());
        } while (infile.gcount() > 0);

        infile.close();
        outfile.close();
        return 0;
    }
    else
    {
        std::cerr << "Could not replace file " + out + " with " + in + ".\n";
        return 1;
    }
}

std::string random_string(std::string::size_type length)
{
    static auto& chrs = "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    thread_local static std::mt19937 rg{std::random_device{}()};
    thread_local static std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

    std::string s;

    s.reserve(length);

    while(length--)
        s += chrs[pick(rg)];

    return s;
}
