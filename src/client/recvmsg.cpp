#include "request_sender.cpp"
#include "client_utils.h"
#include "http_utils.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <fstream>
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

    // Check if content length matches 
    /*
    if(!response.content_length.empty() && std::stoi(response.content_length) != response.body.size())
    {
        std::cout << response.content_length << std::endl;
        std::cout << response.body.size() << std::endl;
        cert_msg.push_back("!Content-length mismatch in response");
        return cert_msg;
    }
    */

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
    std::string encoded_encrypted_signed_msg = cert_msg[1];

    // Decode message to BYTE vector and write to TMP file
    std::vector<BYTE> decoded_bytes = base64_decode(encoded_encrypted_signed_msg);
    std::ofstream outfile(TMP_DECODED_MSG, std::ios::out | std::ios::binary);
    if(outfile.good())
    {
        outfile.write((char *) decoded_bytes.data(), decoded_bytes.size());
    }
    else
    {
        std::cerr << "Could not successfully write temp message to " + TMP_DECODED_MSG << std::endl;
        return 1;
    }

    // Decode cert and write to temporary PEM file
    if(save_cert(sender_cert_str, TMP_DECODED_CERT) == 0)
    {
        std::cerr << "Could not successfully save certificate.\n";
        return 1;
    }

    // The message is now decoded, so it is of the form: Enc(Sign(m))
    // DECRYPT:
    if(decrypt(CAT_CERT_KEY_PATH, TMP_DECODED_MSG, TMP_DECRYPTED_MSG))
    {
        std::cerr << "Error decrypting data. Could not display received message.\n";
        return 1;
    }

    // VERIFY:
    if(verify(TMP_DECODED_CERT, TMP_DECRYPTED_MSG, VERIFIED_MSG))
    {
        std::cerr << "Error verifying data. Could not display received message.\n";
        return 1;
    }

    // Print the verified message to stdout!
    std::cout << "recvmsg downloaded to: " + VERIFIED_MSG << std::endl;
    std::ifstream recvdmsg;
    recvdmsg.open(VERIFIED_MSG);
    if(recvdmsg.good())
    {
        std::cout << "=== CONTENTS ===" << std::endl;
        std::string line;
        while(std::getline(recvdmsg, line))
        {
            std::cout << line << std::endl;
        }
        recvdmsg.close();
    }
    else
    {
        std::cout << "Could not open to display to stdout.\n";
    }

    // Cleanup tmp files
    if(remove(TMP_DECODED_MSG.c_str()))
    {
        std::cerr << "Could not delete tmp file: " + TMP_DECODED_MSG << std::endl;
        return 1;
    }
    if(remove(TMP_DECODED_CERT.c_str()))
    {
        std::cerr << "Could not delete tmp file: " + TMP_DECODED_CERT << std::endl;
        return 1;
    }
    if(remove(TMP_DECRYPTED_MSG.c_str()))
    {
        std::cerr << "Could not delete tmp file: " + TMP_DECRYPTED_MSG << std::endl;
        return 1;
    }

    return 0;
}
