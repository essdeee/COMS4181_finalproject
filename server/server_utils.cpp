#include <string.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include <bits/stdc++.h> 
#include "server_utils.h"
#include "route_utils.h"

// CONSTANTS AND MACROS
const std::string PASSWORD_FILE = "pass.txt";
const std::string TMP_CERT_FILE = "tmp-crt";
const std::string HTTP_VERSION = "HTTP/1.0";

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

    parsed_request.body = request_body;
    return parsed_request;
}

std::string parse_url(std::string url)
{
    // Find first occurence of ://
    size_t found = url.find_first_of(":");
    std::string protocol=url.substr(0,found); 

    std::string url_new=url.substr(found+4); //url_new is the url excluding the https part
    size_t found2 = url_new.find_first_of("/");
    std::string path =url_new.substr(found2);
    return path;
}

HTTPresponse route(const std::string request)
{
    // HTTPS response at the end
    HTTPresponse response;

    // Parse out the command line, content length, and body
    HTTPrequest parsed_request = parse_request(request);

    // Parse out the route and integer valued content length
    std::vector<std::string> first_line;
    first_line = split(parsed_request.command_line, " ");
    std::string route = parse_url(first_line[1]);

    // Execute the program
    if(route == GETCERT_ROUTE)
    {
        response = getcert_route(std::stoi(parsed_request.content_length), parsed_request.body);
    }
    else if(route == CHANGEPW_ROUTE)
    {
        response = changepw_route(std::stoi(parsed_request.content_length), parsed_request.body);
    }
    else if(route == SENDMSG_ENCRYPT_ROUTE)
    {
        response = sendmsg_encrypt_route(std::stoi(parsed_request.content_length), parsed_request.body);
    }
    else if(route == SENDMSG_MESSAGE_ROUTE)
    {
        response = sendmsg_message_route(std::stoi(parsed_request.content_length), parsed_request.body);
    }
    else if(route == RECVMSG_ROUTE)
    {
        response = recvmsg_route(std::stoi(parsed_request.content_length), parsed_request.body);
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
  	file << str;
	file.close();
}
