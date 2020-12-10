#include "client_utils.h"
#include <memory.h>
#include <string>

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

void print_hex(const BYTE* byte_arr, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%.2X", byte_arr[i]);
    }
}

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
*/