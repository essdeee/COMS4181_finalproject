#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H
#include <string>
#include <vector>

/**************************** CONSTANTS ******************************/
extern const std::string PASSWORD_FILE;
extern const std::string TEMP_CRT_FILE;

/**************************** OBJECTS ********************************/
struct HTTPrequest
{
    std::string command_line;    // <verb> <url> <version>
    std::string content_length; // "Content-Length" is the only nonempty <option-line>
    std::string body;           // body that goes after the newline
};

/**************************** FUNCTION DECLARATIONS ******************/

std::string hash_password(std::string password);
std::string hash_password(std::string password, std::string salt);
std::vector<std::string> split(std::string str,std::string sep);
HTTPrequest parse_request(const std::string request);
std::string convert_to_lower(const std::string str);
std::string route(const std::string request);
void write_file(std::string str, std::string filename);
#endif
