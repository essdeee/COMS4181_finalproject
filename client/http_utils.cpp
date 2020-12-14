#include "http_utils.h"

/**************************** CONSTANTS ******************************/
const std::string GETCERT_ROUTE = "/getcert";
const std::string CHANGEPW_ROUTE = "/changepw";
const std::string SENDMSG_ENCRYPT_ROUTE = "/sendmsg_encrypt";
const std::string SENDMSG_MESSAGE_ROUTE = "/sendmsg_message";
const std::string RECVMSG_ROUTE = "/recvmsg";

/**************************** FUNCTIONS ******************************/
HTTPrequest getcert_request(std::string username, std::string password, BYTE* csr)
{
    HTTPrequest request;
    request.command_line = "POST " + GETCERT_ROUTE + " HTTP/1.0"; // Change to POST 
    request.body = username + "\n";
    request.body += password + "\n";
    request.content_length = std::to_string(request.body.length());

    return request;
}

std::string getcert_response(std::string server_response)
{
    std::string cert;

    return server_response;
}

HTTPrequest changepw_request(std::string username, std::string old_pass, std::string new_pass, BYTE* csr)
{
    HTTPrequest request;
    request.command_line = "GET " + CHANGEPW_ROUTE + " HTTP/1.0"; // Change to POST
    request.body = username + "\n";
    request.body += old_pass + "\n";
    request.body += new_pass + "\n";
    request.content_length = std::to_string(request.body.length());

    return request;
}

std::string changepw_response(std::string server_response)
{
    std::string cert;

    return server_response;
}