#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include "base64.h"

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        std::cerr << "Incorrect number of args. Please enter a username.\n";
        return 1;
    }

    // Take username and pass
    std::string username = argv[1];
    std::string password = getpass("Enter password: ");

    // Validate username and password lengths
    if(username.length() > USERNAME_MAX)
    {
        std::cerr << "Username too long. Aborting.\n";
        return 1;
    }

    // Get CSR
    std::vector<BYTE> csr = gen_csr(username);
    
    // Generate HTTP request
    HTTPrequest request = getcert_request(username, password, csr);

    // Send cleint request and receive response
    std::string response = send_request("ca-chain.cert.pem", request);
    
    // Write cert (from server response) to file
    std::string certstr = getcert_response(response);
    if(save_cert(certstr) == 1)
    {
        std::cerr << "Could not successfully save certificate.\n";
    }
    
    return 0;
}
