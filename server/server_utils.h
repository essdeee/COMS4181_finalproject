#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H
#include <string>

// CONSTANTS AND MACROS
extern const std::string VERIFY_PASS_PATH = "./../pass/bin/verify-pass";
extern const std::string UPDATE_PASS_PATH = "./../pass/bin/update-pass";
extern const std::string CERT_GEN_PATH = "./../client_certs/bin/cert-gen";
extern const std::string FETCH_CERT_PATH = "./../client_certs/bin/fetch-cert";
extern const std::string MAIL_OUT_PATH = "./../mail/bin/mail-out";
extern const std::string MAIL_IN_PATH = "./../mail/bin/mail-in";

std::vector<std::string> split(std::string str,std::string sep);
std::string route(const std::string request);

#endif