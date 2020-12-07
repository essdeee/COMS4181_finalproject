#include "request_sender.cpp"
#include "crypto_lib/aes.h"
#include "crypto_lib/sha256.h"
//#include "client_utils.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>

int main()
{
    // Take password and username
    std::string username;
    std::cout << "Enter username: ";
    std::cin >> username;
    std::string password = getpass("Enter password: ");
    
    // Hash the password
    // BYTE HMAC_key[SHA256_BLOCK_SIZE];
    //iterate_sha256(password, HMAC_key, HMAC_SHA256_ITERS);

    // std::cout << HMAC_key;

    // Establish TLS connection
    
    send_request("ca-chain.cert.pem", "/getcert", "");

    // Send username and hashedPassword via TLS
    
    // Receive cert from server    
    
    return 0;
}