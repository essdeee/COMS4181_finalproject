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
    request.command_line = "GET " + GETCERT_ROUTE + " HTTP/1.0"; // Change to POST 

    return request;
}

HTTPrequest changepw_request(std::string username, std::string old_pass, std::string new_pass, BYTE* csr)
{
    HTTPrequest request;
    request.command_line = "GET " + CHANGEPW_ROUTE + " HTTP/1.0"; // Change to POST

    return request;
}