#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H
#include <string>

std::vector<std::string> split(std::string str,std::string sep);
std::string convert_to_lower(const std::string str);
std::string route(const std::string request);
void write_file(std::string str, std::string filename);
#endif
