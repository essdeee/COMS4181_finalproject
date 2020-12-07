#ifndef ROUTE_UTILS_H
#define ROUTE_UTILS_H
#include <string>

std::string get_cert_route(int content_length, std::string request_body);
std::string change_pw_route(int content_length, std::string request_body);
std::string sendmsg_encrypt_route(int content_length, std::string request_body);
std::string sendmsg_message_route(int content_length, std::string request_body);
std::string recvmsg_route(int content_length, std::string request_body);

#endif