#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
#include "base64.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>

HTTPrequest changepw_request(std::string username, std::string old_pass, std::string new_pass, std::vector<BYTE> csr)
{
    HTTPrequest request;
    request.verb = "POST";
    request.command_line = "POST " + HTTPS_PREFIX + HOSTNAME + CHANGEPW_ROUTE + " HTTP/1.0"; // Change to POST
    request.hostname = HOSTNAME;
    request.port = DEFAULT_PORT;
    request.body = username + "\n";
    request.body += old_pass + "\n";
    request.body += new_pass + "\n";
    request.body += base64_encode(csr.data(), csr.size()) + "\n";
    request.content_length = std::to_string(request.body.length());

    return request;
}

std::string changepw_response(std::string server_response)
{
    // Parse and get error code if there is one
    HTTPresponse response = parse_http_response(server_response);
    std::string response_string;

    // Handle error codes with response.valid
    if(response.valid)
    {
        // Check if cert is the only thing in the body
        std::vector<std::string> split_body = split(response.body, "\n");
        if(split_body.size() != 1)
        {
            response_string = "!Server body improperly formatted. Should only be one newline delimited certificate.";
        }
        else
        {
            response_string = response.body; // This is the encoded certificate
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
    std::string old_password = getpass("Enter old password: ");
    std::string new_password = getpass("Enter new password: ");

    // Validate username and password lengths
    if(username.length() > USERNAME_MAX && !validMailboxChars(username))
    {
        std::cerr << "Username invalid (too long or invalid characters). Aborting.\n";
        return 1;
    }
    if(!validPasswordChars(old_password))
    {
        std::cerr << "Old password invalid (invalid characters). Aborting.\n";
        return 1;
    }
    if(!validPasswordChars(new_password))
    {
        std::cerr << "New password invalid (invalid characters). Aborting.\n";
        return 1;
    }

    // Get CSR
    std::vector<BYTE> csr = gen_csr(username);

    // Generate HTTP request
    HTTPrequest request = changepw_request(username, old_password, new_password, csr);

    // Send cleint request and receive response. Client authentication FALSE.
    std::string response = send_request(request, false);    

    // Write cert (from server response) to file    
    std::string certstr = changepw_response(response);

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
        std::cerr << "Could not successfully save certificate on client end.\n";
        return 1;
    }
    else
    {
        std::cout << "Password changed. New certificate successfully saved as " + SAVE_CERT_PATH + "\n";
    }
    
    return 0;
}