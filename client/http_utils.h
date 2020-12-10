#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H
#include "client_utils.h"

struct HTTPrequest
{
    std::string command_line;    // <verb> <url> <version>
    std::string content_length; // "Content-Length" is the only nonempty <option-line>
    std::string body;           // body that goes after the newline
};

HTTPrequest getcert_request(std::string username, BYTE* password, BYTE* csr);
HTTPrequest changepw_request(std::string username, BYTE* old_pass, BYTE* new_pass, BYTE* csr);
HTTPrequest sendmsg_encrypt_request(std::string recipient, BYTE* cert);
HTTPrequest sendmsg_message_request(std::string recipient, BYTE* msg);
HTTPrequest recvmsg_request(BYTE* cert);

#endif