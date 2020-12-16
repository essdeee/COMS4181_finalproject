#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include "base64.h"

int main()
{
    // Read the input file (preventing overflow)
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(std::cin, line))
    {
        if (line.empty())
        {
            lines.push_back("\n");
        }
        else
        {
            lines.push_back(line + "\n"); // getline removes newline
        }
    }

    // (1) Generate recvmsg HTTP request (nothing in body, GET request)
    HTTPrequest request = recvmsg_request();

    // Send cleint request and receive response
    std::string response = send_request("ca-chain.cert.pem", request); // Must be client-auth
    
    // Get back (1) certificate from the sender (to verify signature) (2) the encrypted message
    std::vector<std::string> cert_msg = recvmsg_response(response);
    if ( cert_msg.size() != 2)
    {
        std::cerr << "Server response for recvmsg improperly formatted. Aborting.\n";
        return 1;
    }

    std::string sender_cert_str = cert_msg[0];
    std::string encrypted_msg = cert_msg[1];

    // TODO (Francis):
    // Verify signature on the message is the original sender's
    // If not, we can print to cerr and return 1

    // TODO (Francis): 
    // Decrypt message after verifying the signature
    std::string decrypted_msg;

    // Display decrypted message to client
    std::cout << decrypted_msg;

    return 0;
}
