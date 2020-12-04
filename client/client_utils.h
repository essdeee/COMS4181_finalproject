#ifndef CLIENT_UTILS_H
#define CLIENT_UTILS_H
#include <string>
#include "crypto_lib/aes.h"
#include "crypto_lib/sha256.h"

#define HMAC_SHA256_ITERS 10000
#define ENCRYPT_SHA256_ITERS 20000 

void iterate_sha256(std::string password, BYTE* final_hash, int rounds);

#endif