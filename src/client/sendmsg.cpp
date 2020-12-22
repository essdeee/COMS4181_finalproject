#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>

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

    // Check if content length matches 
    if(!response.content_length.empty() && std::stoi(response.content_length) != response.body.size())
    {
        encrypt_certs.push_back("!Content-length mismatch in response");
        return encrypt_certs;
    }

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
    request.command_line = "POST " + HTTPS_PREFIX + HOSTNAME + SENDMSG_MESSAGE_ROUTE + " HTTP/1.0"; // Change to POST
    for ( std::string recipient : recipients )
    {
        request.body += recipient + ":";
    }
    request.body += "\n";
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

    // Check if content length matches 
    if(!response.content_length.empty() && std::stoi(response.content_length) != response.body.size())
    {
        return "!Content-length mismatch in response";
    }

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
    if(argc < 3)
    {
        std::cerr << "Incorrect number of args. Expected usage: ./sendmsg <message path> <recipient 1> <recipient 2> ... <recipient n>.\n";
        return 1;
    }

    // Find current logged in user from current_login file
    std::ifstream current_login;
    std::string username;
    current_login.open(CURRENT_LOGIN_FILE);
    if(current_login.good())
    {
        std::getline(current_login, username);
        current_login.close();
    }
    else
    {
        std::cerr << "Could not retrieve current login user from file. User may not yet be logged in (use getcert).\n";
        return 1;
    }

    if(username.empty())
    {
        std::cerr << "Error reading current login file. User might not be logged in (use getcert).\n";
        return 1;
    }

    // Parse out the file name and recipients from the command
    std::vector<std::string> recipients;
    std::string msg_name = argv[1];
    if(username.length() > USERNAME_MAX || !validMailboxChars(username))
    {
        std::cerr << "Provided invalid username as sender. Aborting...\n";
        return 1;
    }

    // Parse out recipients
    for (int i = 2; i < argc; i++)
    {
        std::string recipient = argv[i];

        // Validate username length and characters
        if(recipient.length() > USERNAME_MAX || !validMailboxChars(recipient))
        {
            std::cerr << "Username invalid (too long or invalid characters). Aborting.\n";
            return 1;
        }
        recipients.push_back(recipient);
    }    

    // Max recipients is 35 (the number installed on the system)
    if(recipients.size() > RECIPIENTS_MAX)
    {
        std::cerr << "Too many recipients in request. Please shorten your list of recipients or split it up over multiple requests.\n";
        return 1;
    }

    // Deduplicate the recipients
    std::sort(recipients.begin(), recipients.end());
    recipients.erase(unique(recipients.begin(), recipients.end()), recipients.end());
    

    // Check if message filepath exists
    std::ifstream f(msg_name);
    if(!f.good())
    {
        std::cerr << "Message " + msg_name + " does not exist or could not open.\n";
        return 1;
    }
    else 
    {
        // Validate the file size
        f.seekg(0, std::ios::end);
        int file_size = f.tellg();
        if(file_size > MAX_MSG_SIZE)
        {
            std::cerr << "Message too large. Maximum file size is 25 MB.\n";
        }
    }
    f.close();

    // (1) Generate sendmsg_encrypt HTTP request
    HTTPrequest request = sendmsg_encrypt_request(recipients);

    // Send client request and receive response
    std::string private_key_path = PRIVATE_KEY_PREFIX + username + PRIVATE_KEY_SUFFIX;
    std::string encrypt_response = send_request(request, private_key_path, true); // Should be client-auth
    
    // Write encryption certs (from server response) to file
    std::vector<std::string> encrypt_certs = sendmsg_encrypt_response(encrypt_response);

    // Check if error in response
    if( encrypt_certs.size() == 1 && encrypt_certs[0][0] == '!' ) // ! is not in base64 encoding
    {
        std::cerr << encrypt_certs[0].substr(1) << std::endl;
        std::cerr << "Did not successfully receive encryption certs for all recipients. Aborting...\n";
        return 1;
    }

    // Did we get all the recipient certs we wanted?
    if( encrypt_certs.size() != recipients.size())
    {
        std::cerr << "ERROR: id not receive all the encryption certs from all recipients.\n";
        std::cerr << "Number of certs received: " + encrypt_certs.size() << std::endl;
        std::cerr << "Number of recipients intended: " + recipients.size() << std::endl;
    }

    // Encrypt the message with the encryption certs
    std::vector<std::string> signed_encrypted_encoded_messages;
    for (std::string encrypt_cert_str : encrypt_certs)
    {
        // Sign the message (writes to a tmp .txt file)
        sign(CAT_CERT_KEY_PATH, msg_name, SIGN_TMP);

        // Decode cert and write to temporary PEM file
        if(save_cert(encrypt_cert_str, TMP_DECODED_CERT) == 0)
        {
            std::cerr << "Could not successfully save certificate.\n";
            return 1;
        }

        // Encrypt the message
        //std::vector<BYTE> signed_encrypted_bytes = encrypt(CAT_CERT_KEY_PATH, SIGN_TMP);
        std::vector<BYTE> signed_encrypted_bytes = encrypt(TMP_DECODED_CERT, SIGN_TMP);

        // Cleanup TMP files
        if(remove(SIGN_TMP.c_str()))
        {
            std::cerr << "Error deleting signing tmp file " + SIGN_TMP << std::endl;
            return 1;
        }

        if(remove(TMP_DECODED_CERT.c_str()))
        {
            std::cerr << "Error deleting decoded crt file " + TMP_DECODED_CERT << std::endl;
            return 1;
        }

        // Encode the signed-encrypted message with base64 encoding
        std::string signed_encrypted_encoded_msg = base64_encode(signed_encrypted_bytes.data(), signed_encrypted_bytes.size());
        signed_encrypted_encoded_messages.push_back(signed_encrypted_encoded_msg);
    }

    // (2) Generate sendmsg_message HTTP request
    request = sendmsg_message_request(signed_encrypted_encoded_messages, recipients);

    // Send client request and receive response
    std::string message_response = send_request(request, private_key_path, true);

    // Parse the server response 
    std::string parsed_response = sendmsg_message_response(message_response);

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
