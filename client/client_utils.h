#ifndef CLIENT_UTILS_H
#define CLIENT_UTILS_H
#include <string>
#include <openssl/sha.h>
#include <openssl/pem.h>

/**************************** CONSTANTS ******************************/
#define USERNAME_MAX 255

/**************************** DATA TYPES ****************************/
typedef uint8_t BYTE;            // 8-bit byte

/**************************** FUNCTION DECLARATIONS *****************/
// void iterate_sha256(std::string password, BYTE* final_hash, int rounds);
bool simpleSHA512(std::string password, BYTE* md);
std::string hashPassword(std::string password);
void print_hex(const BYTE* byte_arr, int len);

void csr_to_pem(X509_REQ *csr, uint8_t **csr_bytes, size_t *csr_size);

uint8_t* gen_csr(std::string client_name);

void save_cert(std::string cert_str);

#endif
