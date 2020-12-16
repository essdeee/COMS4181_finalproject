#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H
#include "client_utils.h"

/**************************** CONSTANTS ******************************/
extern const std::string GETCERT_ROUTE;
extern const std::string CHANGEPW_ROUTE;
extern const std::string SENDMSG_ENCRYPT_ROUTE;
extern const std::string SENDMSG_MESSAGE_ROUTE;
extern const std::string RECVMSG_ROUTE;

/**************************** OBJECTS *******************************/
struct HTTPrequest
{
    std::string command_line;    // <verb> <url> <version>
    std::string content_length; // "Content-Length" is the only nonempty <option-line>
    std::string body;           // body that goes after the newline
};

/**************************** FUNCTION DECLARATIONS *****************/
HTTPrequest getcert_request(std::string username, std::string password, std::vector<BYTE> csr);
std::string getcert_response(std::string server_response);
HTTPrequest changepw_request(std::string username, std::string old_pass, std::string new_pass, std::vector<BYTE> csr);
std::string changepw_response(std::string server_response);
HTTPrequest sendmsg_encrypt_request(std::vector<std::string> recipients);
std::vector<std::string> sendmsg_encrypt_response(std::string server_response);
HTTPrequest sendmsg_message_request(std::vector<std::string> messages);
HTTPrequest recvmsg_request();
std::vector<std::string> recvmsg_response(std::string server_response);

#endif