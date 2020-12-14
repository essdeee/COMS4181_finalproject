#ifndef _BASE64_H_
#define _BASE64_H_

#include <vector>
#include <string>
typedef uint8_t BYTE;

std::string base64_encode(BYTE const* buf, unsigned long bufLen);
std::vector<BYTE> base64_decode(std::string const&);

#endif