#include "client_utils.h"
#include <memory.h>
#include <string>
#include <stdio.h>
#include <fstream>
#include <unistd.h>
#include <random>
#include <iostream>

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