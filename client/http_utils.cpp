#include "http_utils.h"
#include "base64.h"

/**************************** CONSTANTS ******************************/
const std::string GETCERT_ROUTE = "/getcert";
const std::string CHANGEPW_ROUTE = "/changepw";
const std::string SENDMSG_ENCRYPT_ROUTE = "/sendmsg_encrypt";
const std::string SENDMSG_MESSAGE_ROUTE = "/sendmsg_message";
const std::string RECVMSG_ROUTE = "/recvmsg";

/**************************** FUNCTIONS ******************************/
HTTPrequest getcert_request(std::string username, std::string password, std::vector<BYTE> csr)
{
    HTTPrequest request;
    request.command_line = "POST " + GETCERT_ROUTE + " HTTP/1.0"; // Change to POST 
    request.body = username + "\n";
    request.body += password + "\n";
    request.body += base64_encode(csr.data(), csr.size()) + "\n";
    request.content_length = std::to_string(request.body.length());

    return request;
}

std::string getcert_response(std::string server_response)
{
    std::string cert;
    return server_response;
}

HTTPrequest changepw_request(std::string username, std::string old_pass, std::string new_pass, std::vector<BYTE> csr)
{
    HTTPrequest request;
    request.command_line = "POST " + CHANGEPW_ROUTE + " HTTP/1.0"; // Change to POST
    request.body = username + "\n";
    request.body += old_pass + "\n";
    request.body += new_pass + "\n";
    request.body += base64_encode(csr.data(), csr.size()) + "\n";
    request.content_length = std::to_string(request.body.length());

    return request;
}

std::string changepw_response(std::string server_response)
{
    std::string cert;
    return server_response;
}

HTTPrequest sendmsg_encrypt_request(std::vector<std::string> recipients)
{
    HTTPrequest request;
    request.command_line = "POST " + CHANGEPW_ROUTE + " HTTP/1.0"; // Change to POST
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
    request.command_line = "POST " + CHANGEPW_ROUTE + " HTTP/1.0"; // Change to POST
    for (std::string message : messages)
    {
        request.body += message + "\n";
    }

    return request;
}