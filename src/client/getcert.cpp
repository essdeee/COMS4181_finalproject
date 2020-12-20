#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "base64.h"

HTTPrequest getcert_request(std::string username, std::string password, std::vector<BYTE> csr)
{
    HTTPrequest request;
    request.verb = "POST";
    request.command_line = "POST " + HTTPS_PREFIX + HOSTNAME + GETCERT_ROUTE + " HTTP/1.0"; // Change to POST 
    request.hostname = HOSTNAME;
    request.port = DEFAULT_PORT;
    request.body = username + "\n";
    request.body += password + "\n";
    request.body += base64_encode(csr.data(), csr.size()) + "\n";
    request.content_length = std::to_string(request.body.length());

    return request;
}

std::string getcert_response(std::string server_response)
{
    // Parse and get error code if there is one
    HTTPresponse response = parse_http_response(server_response);
    std::string response_string;

    // Check if content length matches 
    /*
    if(!response.content_length.empty() && std::stoi(response.content_length) != response.body.size())
    {
        return "!Content-length mismatch in response";
    }
    */

    // Handle error codes with response.valid
    if(response.valid)
    {
        // Check if cert is the only thing in the body
        std::vector<std::string> split_body = split(response.body, "\n");
        if(split_body.size() != 1)
        {
            response_string = "!Response body improperly formatted. Should only be one newline delimited certificate.\n";
        }
        else
        {
            response_string = split_body[0]; // This is the encoded certificate
        }
    }
    else
    {
        response_string = "!" + response.error_msg;
    }

    return response_string;
}

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
    if(username.length() > USERNAME_MAX && !validMailboxChars(username))
    {
        std::cerr << "Username invalid (too long or invalid characters). Aborting.\n";
        return 1;
    }
    if(!validPasswordChars(password))
    {
        std::cerr << "Password invalid (invalid characters). Aborting.\n";
        return 1;
    }

    // Get CSR
    std::vector<BYTE> csr = gen_csr(username);
    
    // Generate HTTP request
    HTTPrequest request = getcert_request(username, password, csr);

    // Send client request and receive response. Client authentication FALSE.
    std::string response = send_request(request, false);
    
    // Parse out the cert from the server response
    std::string certstr = getcert_response(response);
    
    // Check if error in response
    if( certstr[0] == '!' ) // ! is not in base64 encoding
    {
        std::cerr << certstr.substr(1) << std::endl;
        std::cerr << "Did not successfully save certificate.\n";
        return 1;
    }

    // PEM write methods have 0 for failure and 1 for success
    if(save_cert(certstr, SAVE_CERT_PATH) == 0)
    {
        std::cerr << "Could not successfully save certificate.\n";
        return 1;
    }
    else
    {
        std::cout << "Certificate successfully saved as " + SAVE_CERT_PATH + "\n";
    }

    // Append the key to the cert for crypto methods
    if(remove(CAT_CERT_KEY_PATH.c_str()))
    {
        std::cerr << "Could not remove existing catted cert_key in " + CAT_CERT_KEY_PATH << std::endl;
        return 1;
    }

    appendFile(CAT_CERT_KEY_PATH, "client.pem");
    appendFile(CAT_CERT_KEY_PATH, PRIVATE_KEY_PATH);
    std::cout << "Appending certificate to key to make " + CAT_CERT_KEY_PATH << std::endl;
    
    return 0;
}