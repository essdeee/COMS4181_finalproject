#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include "base64.h"

HTTPrequest recvmsg_request()
{
    HTTPrequest request;
    request.verb = "GET";
    request.command_line = "GET " + HTTPS_PREFIX + HOSTNAME + RECVMSG_ROUTE + " HTTP/1.0"; 
    request.hostname = HOSTNAME;
    request.port = DEFAULT_PORT;
    return request;
}

std::vector<std::string> recvmsg_response(std::string server_response)
{
    std::vector<std::string> cert_msg;
    
    // Parse and get error code if there is one
    HTTPresponse response = parse_http_response(server_response);
    std::string response_string;

    // Handle error codes with response.valid
    if(response.valid)
    {
        // Check if cert is the only thing in the body
        std::vector<std::string> split_body = split(response.body, "\n");
        if(split_body.empty() || split_body.size() != 2)
        {
            cert_msg.push_back("!Server body improperly formatted. There should be two parts: cert and message.");
            return cert_msg;
        }
        else
        {
            for( std::string cert : split_body )
            {
                cert_msg.push_back(cert);
            }
        }
    }
    else
    {
        cert_msg.push_back("!" + response.error_msg);
    }

    return cert_msg;
}

int main(int argc, char* argv[])
{
    // Request is a simple GET request using the cert that should already be on client side
    HTTPrequest request = recvmsg_request();

    // Send client request and receive response
    std::string response = send_request(request, true); // Must be client-auth
    
    // Get back (1) certificate from the sender (to verify signature) (2) the encrypted message
    std::vector<std::string> cert_msg = recvmsg_response(response);
    if ( cert_msg.size() == 1 || cert_msg.empty() || cert_msg[0][0] == '!')
    {
        std::cerr << cert_msg[0].substr(1) << std::endl;
        return 1;
    }

    std::string sender_cert_str = cert_msg[0];
    std::string encrypted_msg = cert_msg[1];

    // TODO (Francis): 
    // Decrypt message
    std::string decrypted_msg;

    // TODO (Francis):
    // Verify signature on the message is the original sender's
    // If not, we can print to cerr and return 1

    // Display decrypted message to client
    std::cout << decrypted_msg;

    return 0;
}
