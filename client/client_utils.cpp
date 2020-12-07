#include "client_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"
#include <memory.h>
#include <string>

/*
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
*/