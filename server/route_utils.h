#ifndef ROUTE_UTILS_H
#define ROUTE_UTILS_H
#include <string>

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

/**************************** FUNCTION DECLARATIONS *****************/
std::string getcert_route(int content_length, std::string request_body);
std::string changepw_route(int content_length, std::string request_body);
std::string sendmsg_encrypt_route(int content_length, std::string request_body);
std::string sendmsg_message_route(int content_length, std::string request_body);
std::string recvmsg_route(int content_length, std::string request_body);

#endif