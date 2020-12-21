#include <string.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <bits/stdc++.h> 
#include "server_utils.h"
#include "route_utils.h"
#include <sys/stat.h>
namespace fs = std::filesystem;

// CONSTANTS AND MACROS
const std::string PASSWORD_FILE = "password/pass/shadow";
const std::string TMP_CERT_FILE = "client_certs/tmp/tmp-crt";  // TODO: Should change with chroot
const std::string TMP_MSG_FILE = "mail/tmp/tmp-msg";           // TODO: Should change with chroot
const std::string HTTP_VERSION = "HTTP/1.0";
const std::string SERVER_CERT = "server_cert/server-cert.pem";
const std::string SERVER_PRIVATE_KEY = "server_cert/server-key.pem";
const std::string MAIL_OUT_SEND = "send";
const std::string MAIL_OUT_PEEK = "peek";

const std::string MAILBOX_PREFIX = "mail/mail/";
const std::string CERTS_PREFIX = "client_certs/certs/";

const std::string CA_CERT_PATH = "client_certs/ca-cert/cacert.pem";
const std::string CA_KEY_PATH = "client_certs/ca-cert/ca.key.pem";
const std::string CA_KEY_PASS = "toor";

const std::string DEFAULT_PORT = "8080";

std::string generateSalt() 
{
    const char alphanum[] =
    "./0123456789ABCDEFGHIJKLMNOPQRST"
    "UVWXYZabcdefghijklmnopqrstuvwxyz"; //salt alphanum

    std::random_device rd;  //Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<> dis(0, sizeof(alphanum)-1); //Uniform distribution on an interval
    char salt[17];          // 16 useful characters in salt (as in original code)
    salt[0] = '$';          // $6$ encodes for SHA512 hash
    salt[1] = '6';
    salt[2] = '$';
    for(int i = 3; i < 16; i++) 
    {
        salt[i] = alphanum[dis(gen)];
    }
    salt[16] = '\0';
    return std::string(salt);
}

std::string hash_password(std::string password)
{
    std::string salt = generateSalt();
    std::string hash = crypt(password.c_str(), salt.c_str());
    return hash;
}

std::string hash_password(std::string password, std::string salt)
{
    return crypt(password.c_str(), salt.c_str());
}

std::vector<std::string> split(std::string str,std::string sep)
{
    char* cstr=const_cast<char*>(str.c_str());
    char* current;
    std::vector<std::string> arr;
    current=strtok(cstr,sep.c_str());
    while(current!=NULL){
        arr.push_back(current);
        current=strtok(NULL,sep.c_str());
    }
    return arr;
}

std::string convert_to_lower(const std::string str)
{
    std::string converted_str;
    for(char c : str)
    {
        converted_str.push_back(std::tolower(c));
    }

    return converted_str;
}

/*
Input: (std::string) A string.
Output: (boolean) Whether a string's characters are all valid mailbox chars.
Checks whether characters are included in upper and lower case letters, digits, +, -, and _
*/
bool validMailboxChars(const std::string &str)
{    
    if (str.empty())
    {
        return false;
    }

    // First character must be alphabetic
    if (!std::isalpha(str[0]))
    {
        return false;
    }

    for(char const &c : str)
    {
        if (!std::isalpha(c) && 
        !std::isdigit(c) && 
        c != '+' && c != '-' && c != '_')
        {
            return false;
        }
    }

    return true;
}

bool validPasswordChars(const std::string &str)
{    
    if (str.empty())
    {
        return false;
    }

    // First character must be alphabetic
    if (!std::isalpha(str[0]))
    {
        return false;
    }

    for(char const &c : str)
    {
        if (!std::isalpha(c) && 
        !std::isdigit(c) && 
        c != '+' && c != '-' && c != '_' 
        && c != '!' && c != '?' && c != '$')
        {
            return false;
        }
    }

    return true;
}

/* 
Input: (std::string) Mailbox name.
Output: (bool) Whether mailbox directory exists in system or not.
Checks if mailbox path exists (used by mail-out)
*/
bool doesMailboxExist(const std::string &s)
{
    // Must check valid mailbox characters first
    if ( !validMailboxChars(s) )
    {
        return false;
    }

    std::string mailbox_path = MAILBOX_PREFIX + s;
    struct stat buffer;
    return (stat (mailbox_path.c_str(), &buffer) == 0);
}

std::string parse_url(std::string url)
{
    // Find first occurence of ://
    std::string path;
    try
    {
        size_t found = url.find_first_of(":");
        std::string protocol=url.substr(0,found); 
        std::string url_new=url.substr(found+4); //url_new is the url excluding the https part
        size_t found2 = url_new.find_first_of("/");
        path =url_new.substr(found2);
    }
    catch(const std::exception& ex)
    {
        return url;
    }

    return path;
}

HTTPrequest parse_request(const std::string request)
{
    HTTPrequest parsed_request;
    std::istringstream f(request);
    std::string line;
    std::string request_body;
    bool cmd_line_flag = true;
    bool request_body_flag = false;
    while ( std::getline(f, line) )
    {
        // Remove all carriage returns
        line.erase( std::remove(line.begin(), line.end(), '\r'), line.end());

        if (cmd_line_flag)
        {
            cmd_line_flag = false;
            parsed_request.command_line = line;
        }
        else if ( line.empty() )
        {
            request_body_flag = true;
        }
        else if ( request_body_flag )
        {
            request_body += line + "\n";
        }
        else if ( convert_to_lower(line).find("content-length:") != std::string::npos )
        {
            std::vector<std::string> split_content_len = split(line, ":");
            std::string content_len_str = split_content_len[1];
            std::string::iterator end_pos = std::remove(content_len_str.begin(), content_len_str.end(), ' ');
            content_len_str.erase(end_pos, content_len_str.end());
            parsed_request.content_length = content_len_str;
        }
        else
        {
            continue;
        }
    }

    // Parse out username, route, verb
    std::vector<std::string> first_line;
    first_line = split(parsed_request.command_line, " ");
    std::string verb = first_line[0];
    std::string route = parse_url(first_line[1]);
    std::string username;
    if ( verb == "GET" && route.find_first_of("?") != std::string::npos)
    {
        std::vector<std::string> route_username = split(route, "?");
        route = route_username[0];
        username = route_username[1];
    }

    parsed_request.verb = verb;
    parsed_request.route = route;
    parsed_request.username = username;
    parsed_request.body = request_body;
    return parsed_request;
}

HTTPresponse route(const std::string request, const std::string username, const std::string encoded_client_cert)
{
    // HTTPS response at the end
    HTTPresponse response;

    // Parse out the command line, content length, and body
    HTTPrequest parsed_request = parse_request(request);

    // Execute the program
    if(parsed_request.route == GETCERT_ROUTE)
    {
        response = getcert_route(std::stoi(parsed_request.content_length), parsed_request.body);
    }
    else if(parsed_request.route == CHANGEPW_ROUTE)
    {
        response = changepw_route(std::stoi(parsed_request.content_length), parsed_request.body);
    }
    else if(parsed_request.route == SENDMSG_ENCRYPT_ROUTE)
    {
        response = sendmsg_encrypt_route(std::stoi(parsed_request.content_length), parsed_request.body, username, encoded_client_cert);
    }
    else if(parsed_request.route == SENDMSG_MESSAGE_ROUTE)
    {
        response = sendmsg_message_route(std::stoi(parsed_request.content_length), parsed_request.body, username, encoded_client_cert);
    }
    else if(parsed_request.route == RECVMSG_ROUTE)
    {
        response = recvmsg_route(username, encoded_client_cert);
    }
    else
    {
        std::cerr << "ERROR: Route not accepted.\n";
        response.command_line = HTTP_VERSION + " 400" + " Invalid route specified in HTTPS request.";
        response.status_code = "400";
        response.error = true;
    }

    return response;
}

void write_file(std::string str, std::string filename)
{
	std::ofstream file(filename);
    if(!file.good())
    {
        std::cerr << "Error writing to file " + filename + "\n";
    }
  	file << str;
	file.close();
}

/* 
Input:  (std::string) Mailbox name.
Output: (std::string) Next message name in current mailbox.
Checks the current highest numbering of the messages in the mailbox
and returns the next number.
*/
std::string get_stem(const fs::path &p) { return (p.stem().string()); }
std::string getNextNumber(const std::string &mailbox_name)
{
    std::string mailbox_path = MAILBOX_PREFIX + mailbox_name;
    std::vector<std::string> files;

    // Iterate over the directory
    for(const auto & entry : fs::directory_iterator(mailbox_path))
    {
        try
        {
            files.push_back(get_stem(entry.path()));
        }
        catch(...)
        {
            return "ERROR";
        }
    }

    // Get the maximum number file
    int max = 0;
    for(std::string file_name : files)
    {
        /*
        // Check that file is appropriate length
        if (file_name.length() > 5)
        {
            return "ERROR";
        }
        */

        // Check that file ONLY has numbers
        if (!isNumeric(file_name))
        {
            return "ERROR";
        }
        
        // file_name.erase(0, file_name.find_first_not_of('0'));
        int num;

        // Check that file can be converted to a number
        try
        {
            num = std::stoi(file_name);
        }
        catch(std::invalid_argument &e)
        {
            return "ERROR";
        }
        
        if (num > max)
        {
            max = num;
        }
    }

    // Format new file number
    int new_num = max + 1;
    std::string num_str = std::to_string(new_num);
    if(num_str.length() > MAILBOX_NAME_MAX)
    {
        return "ERROR";
    }
    
    /*
    while(num_str.length() < 5)
    {
        num_str = "0" + num_str;
    }
    */

    return num_str;
}

std::string getEarliestNumberPath(const std::string &mailbox_name)
{
    std::string mailbox_path = MAILBOX_PREFIX + mailbox_name;
    std::vector<std::string> files;

    // Iterate over the directory
    for(const auto & entry : fs::directory_iterator(mailbox_path))
    {
        try
        {
            files.push_back(get_stem(entry.path()));
        }
        catch(...)
        {
            return "ERROR";
        }
    }

    // Get the earliest number file
    int min = INT_MAX;
    for(std::string file_name : files)
    {
        // Check that file ONLY has numbers
        if (!isNumeric(file_name))
        {
            return "ERROR";
        }
        
        // file_name.erase(0, file_name.find_first_not_of('0'));
        int num;

        // Check that file can be converted to a number
        try
        {
            num = std::stoi(file_name);
        }
        catch(std::invalid_argument &e)
        {
            return "ERROR";
        }
        
        if (num < min)
        {
            min = num;
        }
    }

    // Format new file number
    std::string num_str = std::to_string(min);
    if(num_str.length() > MAILBOX_NAME_MAX)
    {
        return "ERROR";
    }
    return MAILBOX_PREFIX + mailbox_name + "/" + num_str;
}

bool isMailboxEmpty(const std::string &mailbox_name)
{
    std::string mail_prefix = MAILBOX_PREFIX;
    std::string mailbox_path = mail_prefix + mailbox_name;
    std::vector<std::string> files;

    // Iterate over the directory
    for(const auto & entry : fs::directory_iterator(mailbox_path))
    {
        try
        {
            files.push_back(get_stem(entry.path()));
        }
        catch(...)
        {
            std::cerr << "ERROR: isDirEmpty failed when using filesystem.\n";
            return 1;
        }
    }

    return files.empty();
}

/*
Input: (std::string) A string.
Output: (boolean) Whether the string's characters are all numeric.
Gives back whether a string only has numeric characters.
*/
bool isNumeric(const std::string &str)
{
    return std::all_of(str.begin(), str.end(), ::isdigit);
}

/*
Input: (std::string) Mailbox name, (std::string) File name.
Output: (std::string) Path to new writing new file.
Gives back the appropriate path to write the new mailed file to.
*/
std::string newMailPath(const std::string &mailbox_name, const std::string &file_name)
{
    //std::string mailbox_path = MAILBOX_PREFIX + mailbox_name + "/" + file_name;
    std::string mailbox_path = MAILBOX_PREFIX + mailbox_name + "/" + file_name;
    return mailbox_path;
}

HTTPresponse server_error_response(const std::string failure_program, 
                                    const std::string error_message, 
                                    const std::string status_code)
{
    HTTPresponse error_response;
    std::cerr << error_message + " SERVER PROGRAM FAILED: " + failure_program;
    error_response.command_line = HTTP_VERSION + " " + status_code + " " + error_message;
    error_response.status_code = status_code;
    error_response.error = true;
    return error_response;
}

void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size)
{
	/* Convert signed certificate to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	*crt_size = BIO_pending(bio);
	*crt_bytes = (uint8_t *)malloc(*crt_size + 1);
	BIO_read(bio, *crt_bytes, *crt_size);
	BIO_free_all(bio);
}

static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(BYTE c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(BYTE const* buf, unsigned int bufLen) {
  std::string ret;
  int i = 0;
  int j = 0;
  BYTE char_array_3[3];
  BYTE char_array_4[4];

  while (bufLen--) {
    char_array_3[i++] = *(buf++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';
  }

  return ret;
}

std::vector<BYTE> base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  BYTE char_array_4[4], char_array_3[3];
  std::vector<BYTE> ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
          ret.push_back(char_array_3[i]);
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
  }

  return ret;
}