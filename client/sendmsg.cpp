#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include "base64.h"

HTTPrequest sendmsg_encrypt_request(std::vector<std::string> recipients)
{
    HTTPrequest request;
    request.command_line = "POST " + HTTPS_PREFIX + HOSTNAME + CHANGEPW_ROUTE + " HTTP/1.0"; // Change to POST
    for (std::string recipient : recipients)
    {
        request.body += recipient + "\n";
    }

    return request;
}

std::vector<std::string> sendmsg_encrypt_response(std::string server_response)
{
    std::vector<std::string> encrypt_certs;
    return encrypt_certs;
}

HTTPrequest sendmsg_message_request(std::vector<std::string> messages)
{
    HTTPrequest request;
    request.command_line = "POST " + HTTPS_PREFIX + ":" + HOSTNAME + CHANGEPW_ROUTE + " HTTP/1.0"; // Change to POST
    for (std::string message : messages)
    {
        request.body += message + "\n";
    }

    return request;
}

std::string sendmsg_message_response(std::string server_response)
{
    return server_response;
}

int main(int argc, char* argv[])
{
    if(argc < 2)
    {
        std::cerr << "Incorrect number of args. Please enter recipients to send your message to.\n";
        return 1;
    }

    // Parse out the recipients from the command
    std::vector<std::string> recipients;
    for (int i = 1; i < argc; i++)
    {
        recipients.push_back(argv[i]);
    }

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

    // (1) Generate sendmsg_encrypt HTTP request
    HTTPrequest request = sendmsg_encrypt_request(recipients);
    std::cout << request.body << std::endl;

    // Send cleint request and receive response
    std::string response = send_request("ca-chain.cert.pem", request); // Must be client-auth
    
    // Write encryption certs (from server response) to file
    std::vector<std::string> encrypt_certs = sendmsg_encrypt_response(response);

    // (2) Generate sendmsg_message HTTP request

    // Encrypt each message with the encryption certs
    std::vector<std::string> signed_encrypted_messages;
    for (std::string encrypt_cert_str : encrypt_certs)
    {
        // Encrypt the message
        // Sign the message
    }

    HTTPrequest request = sendmsg_message_request(signed_encrypted_messages);
    return 0;
}
