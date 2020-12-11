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
    /*
    Because of salts, the password should get hashed on the server side
    std::string hashed_pass = hashPassword(password);
    std::cout << hashed_pass << std::endl;
    */

    // Get CSR
    // TODO: Francis
    BYTE csr[1024]; // Placeholder

    // Generate HTTP request
    HTTPrequest request = getcert_request(username, password, csr);

    // Establish TLS connection

    // send_request("ca-chain.cert.pem", "/getcert", "");
    // send_request("ca-chain.cert.pem", request);
    
    // Receive server response

    // Write cert (from server response) to file    
    
    return 0;
}