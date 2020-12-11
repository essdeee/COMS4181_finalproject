#ifndef CLIENT_UTILS_H
#define CLIENT_UTILS_H
#include <string>
#include <openssl/sha.h>

/**************************** CONSTANTS ******************************/
#define USERNAME_MAX 255

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;            // 8-bit byte

/**************************** FUNCTION DECLARATIONS *****************/
// void iterate_sha256(std::string password, BYTE* final_hash, int rounds);
bool simpleSHA512(std::string password, BYTE* md);
std::string hashPassword(std::string password);
void print_hex(const BYTE* byte_arr, int len);

#endif