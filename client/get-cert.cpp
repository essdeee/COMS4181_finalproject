#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
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

    // Validate username and password lengths
    if(username.length() > USERNAME_MAX)
    {
        std::cerr << "Username too long. Aborting.\n";
        return 1;
    }
    
    // Hash the password
    BYTE hashed_pass_buf[SHA512_DIGEST_LENGTH];
    if(!simpleSHA512(password, hashed_pass_buf))
    {
        std::cerr << "Could not successfully apply hash password. Aborting.\n";
        return 1;
    }
    print_hex(hashed_pass_buf, SHA512_DIGEST_LENGTH);
    std::cout << std::endl;

    // Get CSR
    // TODO: Francis
    BYTE csr[1024]; // Placeholder

    // Generate HTTP request
    HTTPrequest request = getcert_request(username, hashed_pass_buf, csr);

    // Establish TLS connection

    // send_request("ca-chain.cert.pem", "/getcert", "");
    send_request("ca-chain.cert.pem", request);
    
    // Receive server response

    // Write cert (from server response) to file    
    
    return 0;
}