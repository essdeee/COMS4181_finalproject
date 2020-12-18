#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H
#include <string>
#include <vector>

/**************************** CONSTANTS ******************************/
#define MAILBOX_NAME_MAX 255
#define MAIL_OUT_MSG_FOUND 0
#define MAIL_OUT_EMPTY 1
#define MAIL_OUT_ERROR 2

extern const std::string PASSWORD_FILE;
extern const std::string TMP_CERT_FILE;
extern const std::string TMP_MSG_FILE;
extern const std::string HTTP_VERSION;
extern const std::string SERVER_CERT;
extern const std::string SERVER_PRIVATE_KEY;
extern const std::string MAIL_OUT_REMOVE;
extern const std::string MAIL_OUT_KEEP;

/**************************** OBJECTS ********************************/
struct HTTPrequest
{
    std::string command_line;    // <verb> <url> <version>
    std::string content_length; // "Content-Length" is the only nonempty <option-line>
    std::string body;           // body that goes after the newline
};

struct HTTPresponse
{
    std::string command_line;   // <version> <status code> <text>
    std::string status_code;    // 200, 400, 500
    int content_length;         // length of body in bytes
    std::string body;
    bool error;
};

/**************************** FUNCTION DECLARATIONS ******************/

std::string hash_password(std::string password);
std::string hash_password(std::string password, std::string salt);
std::vector<std::string> split(std::string str,std::string sep);
HTTPrequest parse_request(const std::string request);
std::string convert_to_lower(const std::string str);
HTTPresponse route(const std::string request);
bool validMailboxChars(const std::string &str);
bool doesMailboxExist(const std::string &s);
std::string getNextNumber(const std::string &mailbox_name);
std::string getEarliestNumberPath(const std::string &mailbox_name);
bool isMailboxEmpty(const std::string &mailbox_name);
std::string newMailPath(const std::string &mailbox_name, const std::string &file_name);
bool isNumeric(const std::string &str);
void write_file(std::string str, std::string filename);
#endif
