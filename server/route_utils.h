#ifndef ROUTE_UTILS_H
#define ROUTE_UTILS_H
#include <string>
#include "server_utils.h"

/**************************** CONSTANTS ******************************/
extern const std::string VERIFY_PASS_PATH;
extern const std::string UPDATE_PASS_PATH;
extern const std::string CERT_GEN_PATH;
extern const std::string FETCH_CERT_PATH;
extern const std::string MAIL_OUT_PATH;
extern const std::string MAIL_IN_PATH;

extern const std::string GETCERT_ROUTE;
extern const std::string CHANGEPW_ROUTE;
extern const std::string SENDMSG_ENCRYPT_ROUTE;
extern const std::string SENDMSG_MESSAGE_ROUTE;
extern const std::string RECVMSG_ROUTE;

extern const std::string FETCH_ENCRYPT_CERT;
extern const std::string FETCH_SIGN_CERT;

/**************************** FUNCTION DECLARATIONS *****************/
HTTPresponse getcert_route(int content_length, std::string request_body);
HTTPresponse changepw_route(int content_length, std::string request_body);
HTTPresponse sendmsg_encrypt_route(int content_length, std::string request_body);
HTTPresponse sendmsg_message_route(int content_length, std::string request_body);
HTTPresponse recvmsg_route(std::string username);

#endif