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
    request.verb = "POST";
    request.port = DEFAULT_PORT;
    request.hostname = HOSTNAME;
    request.command_line = "POST " + HTTPS_PREFIX + HOSTNAME + SENDMSG_ENCRYPT_ROUTE + " HTTP/1.0"; // Change to POST
    for (std::string recipient : recipients)
    {
        request.body += recipient + "\n";
    }
    request.content_length = std::to_string(request.body.length());

    return request;
}

std::vector<std::string> sendmsg_encrypt_response(std::string server_response)
{
    std::vector<std::string> encrypt_certs;
    
    // Parse and get error code if there is one
    HTTPresponse response = parse_http_response(server_response);
    std::string response_string;

    // Handle error codes with response.valid
    if(response.valid)
    {
        // Check if cert is the only thing in the body
        std::vector<std::string> split_body = split(response.body, "\n");
        if(split_body.empty())
        {
            encrypt_certs.push_back("!Server body improperly formatted. No certificates in body.");
            return encrypt_certs;
        }
        else
        {
            for( std::string cert : split_body )
            {
                encrypt_certs.push_back(cert);
            }
        }
    }
    else
    {
        encrypt_certs.push_back("!" + response.error_msg);
    }

    return encrypt_certs;
}

HTTPrequest sendmsg_message_request(std::vector<std::string> messages, std::vector<std::string> recipients)
{
    HTTPrequest request;
    request.verb = "POST";
    request.port = DEFAULT_PORT;
    request.hostname = HOSTNAME;
    request.command_line = "POST " + HTTPS_PREFIX + ":" + HOSTNAME + SENDMSG_MESSAGE_ROUTE + " HTTP/1.0"; // Change to POST
    for ( std::string recipient : recipients )
    {
        request.body += recipient + ":";
    }
    for (std::string message : messages)
    {
        request.body += message + "\n";
    }
    request.content_length = std::to_string(request.body.length());

    return request;
}

std::string sendmsg_message_response(std::string server_response)
{
    // Parse and get error code if there is one
    HTTPresponse response = parse_http_response(server_response);
    std::string response_string;

    if(response.valid)
    {
        response_string = response.status_text;
    }
    else
    {
        response_string = "!" + response.error_msg;
    }

    return response_string;
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

    // Read the input message (preventing overflow)
    std::string line;
    std::string message;
    std::vector<std::string> lines;
    while (std::getline(std::cin, line))
    {
        if (line.empty())
        {
            message += "\n";
        }
        else
        {
            message += line + "\n"; // getline removes newline
        }
    }

    // (1) Generate sendmsg_encrypt HTTP request
    HTTPrequest request = sendmsg_encrypt_request(recipients);

    // Send client request and receive response
    std::string response = send_request("ca-chain.cert.pem", request, true); // Should be client-auth
    
    // Write encryption certs (from server response) to file
    std::vector<std::string> encrypt_certs = sendmsg_encrypt_response(response);

    // Check if error in response
    if( encrypt_certs.size() == 1 && encrypt_certs[0][0] == '!' ) // ! is not in base64 encoding
    {
        std::cerr << encrypt_certs[0].substr(1) << std::endl;
        std::cerr << "Did not successfully receive encryption certs for all recipients. Aborting...\n";
        return 1;
    }

    // (2) Generate sendmsg_message HTTP request
    // Encrypt each message with the encryption certs
    std::vector<std::string> signed_encrypted_messages;
    for (std::string encrypt_cert_str : encrypt_certs)
    {
        // Encrypt the message
        // Sign the message
    }

    request = sendmsg_message_request(signed_encrypted_messages, recipients);

    // Send client request and receive response
    response = send_request("ca-chain.cert.pem", request, false);

    // Parse the server response 
    std::string parsed_response = sendmsg_message_response(response);

    // Check if error in response
    if( parsed_response[0] == '!' ) // ! is not in base64 encoding
    {
        std::cerr << parsed_response.substr(1) << std::endl;
        std::cerr << "Could not deliver all messages successfully.\n";
        return 1;
    }

    std::cout << "Messages successfully delivered.\n";
    return 0;
}
