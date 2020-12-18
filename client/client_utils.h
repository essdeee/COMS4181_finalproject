#ifndef CLIENT_UTILS_H
#define CLIENT_UTILS_H
#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/pem.h>

/**************************** CONSTANTS ******************************/
#define USERNAME_MAX 255
extern const std::string SAVE_CERT_PATH;

/**************************** DATA TYPES ****************************/
typedef uint8_t BYTE;            // 8-bit byte

/**************************** FUNCTION DECLARATIONS *****************/
void print_hex(const BYTE* byte_arr, int len);
std::vector<std::string> split(std::string str,std::string sep);
std::string convert_to_lower(const std::string str);
bool is_number(const std::string& s);
void csr_to_pem(X509_REQ *csr, uint8_t **csr_bytes, size_t *csr_size);
std::vector<BYTE> gen_csr(std::string client_name);
int save_cert(std::string cert_str, std::string file_name);

#endif
