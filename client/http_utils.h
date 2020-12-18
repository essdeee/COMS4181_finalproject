#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H
#include "client_utils.h"

/**************************** CONSTANTS ******************************/
extern const std::string GETCERT_ROUTE;
extern const std::string CHANGEPW_ROUTE;
extern const std::string SENDMSG_ENCRYPT_ROUTE;
extern const std::string SENDMSG_MESSAGE_ROUTE;
extern const std::string RECVMSG_ROUTE;

extern const std::string HTTPS_PREFIX;
extern const std::string HOSTNAME;
extern const std::string DEFAULT_PORT;

/**************************** OBJECTS *******************************/
struct HTTPrequest
{
    std::string command_line;    // <verb> <url> <version>
    std::string content_length; // "Content-Length" is the only nonempty <option-line>
    std::string body;           // body that goes after the newline
    std::string hostname;       // Hostname that client wants to connect to (default:localhost)
    std::string port;           // Port that client wants to connect to
};

struct HTTPresponse
{
    std::string command_line;   // <version> <status-code> <text>
    std::string status_code;    // 200, 300, 400, etc.
    std::string status_text;    // Text after status code
    std::string content_length; // only nonempty <option-line>
    std::string body;
    bool valid;
    std::string error_msg;
};

/**************************** FUNCTION DECLARATIONS *****************/
HTTPresponse parse_http_response(std::string server_response);

#endif