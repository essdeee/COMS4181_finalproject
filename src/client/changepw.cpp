#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <fstream>
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
    if(argc != 2 && argc != 6)
    {
        std::cerr << "Incorrect number of args. Please enter a username.\n";
        return 1;
    }

    std::string username;
    std::string old_password;
    std::string new_password;

    // Take username and pass
    if(argc == 2)
    {
        username = argv[1];
        old_password = getpass("Enter old password: ");
        new_password = getpass("Enter new password: ");
        std::string new_password_confirm = getpass("Enter new password again to confirm: ");

        // Make sure they typed it in right twice
        if(new_password != new_password_confirm)
        {
            std::cerr << "New password not typed in same twice. Please try again.\n";
            return 1;
        }
    }
    else //argc == 6
    {
        std::string argv1 = argv[1];
        std::string argv2 = argv[2];
        std::string argv3 = argv[3];
        std::string argv4 = argv[4];
        std::string argv5 = argv[5];

        if(argv2 == "-op" && argv4 == "-np")
        {
            username = argv1;
            new_password = argv3;
            old_password = argv5;
        }
        else if(argv2 == "-np" && argv4 == "-op") 
        {
            username = argv1;
            old_password = argv3;
            new_password = argv5;
        }
        else
        {
            std::cerr << "Error in arguments. Usage: ./changepw <username> -op [pass] -np [pass]\n";
            return 1;
        }
    }

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

    // Append the key to the cert for crypto methods
    if(remove(CAT_CERT_KEY_PATH.c_str()))
    {
        std::cerr << "Could not remove existing catted cert_key in " + CAT_CERT_KEY_PATH << std::endl;
        return 1;
    }
    
    appendFile(CAT_CERT_KEY_PATH, SAVE_CERT_PATH);
    appendFile(CAT_CERT_KEY_PATH, PRIVATE_KEY_PATH);
    std::cout << "Appending certificate to key to make " + CAT_CERT_KEY_PATH << std::endl;
    
    return 0;
}