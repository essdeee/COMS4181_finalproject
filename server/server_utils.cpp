#include <string.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include <bits/stdc++.h> 
#include "server_utils.h"
#include "route_utils.h"

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
        response = get_cert_route(content_length, request_body);
        response = GETCERT_ROUTE + "\n";
    }
    else if(route == CHANGEPW_ROUTE)
    {
        response = change_pw_route(content_length, request_body);
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

void write_file(std::string str, std::string filename){
	std::ofstream file(filename);
  	file << str;
	file.close();
}
