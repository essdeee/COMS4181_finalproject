#include "http_utils.h"

HTTPrequest getcert_request(std::string username, BYTE* password, BYTE* csr)
{
    HTTPrequest request;
    request.command_line = "GET /getcert HTTP/1.0";

    return request;
}

HTTPrequest changepw_request(std::string username, BYTE* old_pass, BYTE* new_pass, BYTE* csr)
{
    HTTPrequest request;

    return request;
}