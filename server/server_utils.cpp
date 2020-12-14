#include <string.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include <bits/stdc++.h> 
#include "server_utils.h"
#include "route_utils.h"

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

std::string hashPassword(std::string password)
{
    std::string salt = generateSalt();
    std::string hash = crypt(password.c_str(), salt.c_str());
    return hash;
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

std::string route(const std::string request)
{
    // HTTPS response at the end
    std::string response;

    // Parse out the route
    std::vector<std::string> request_lines;
    request_lines = split(request, "\n");
    std::vector<std::string> first_line;
    first_line = split(request_lines[0], " ");

    // Determine the route
    std::string route = first_line[1];

    // TODO: Parse out the body and content-length of the request 
    int content_length;
    std::string request_body;

    // Execute the program
    if(route == GETCERT_ROUTE)
    {
        response = getcert_route(content_length, request_body);
        response = GETCERT_ROUTE + "\n";
    }
    else if(route == CHANGEPW_ROUTE)
    {
        response = changepw_route(content_length, request_body);
        response = CHANGEPW_ROUTE + "\n";
    }
    else if(route == SENDMSG_ENCRYPT_ROUTE)
    {
        response = sendmsg_encrypt_route(content_length, request_body);
        response = SENDMSG_ENCRYPT_ROUTE + "\n";
    }
    else if(route == SENDMSG_MESSAGE_ROUTE)
    {
        response = sendmsg_message_route(content_length, request_body);
        response = SENDMSG_MESSAGE_ROUTE + "\n";
    }
    else if(route == RECVMSG_ROUTE)
    {
        response = recvmsg_route(content_length, request_body);
        response = RECVMSG_ROUTE + "\n";
    }
    else
    {
        std::cerr << "ERROR: Route not accepted.\n";
        response = "Invalid route specified in HTTPS request.\n";
    }

    return response;
}

void write_file(std::string str, std::string filename)
{
	std::ofstream file(filename);
  	file << str;
	file.close();
}
