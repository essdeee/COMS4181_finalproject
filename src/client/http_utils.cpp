#include "http_utils.h"
#include "client_utils.h"
#include <sstream>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <bits/stdc++.h> 

/**************************** CONSTANTS ******************************/
const std::string GETCERT_ROUTE = "/getcert";
const std::string CHANGEPW_ROUTE = "/changepw";
const std::string SENDMSG_ENCRYPT_ROUTE = "/sendmsg_encrypt";
const std::string SENDMSG_MESSAGE_ROUTE = "/sendmsg_message";
const std::string RECVMSG_ROUTE = "/recvmsg";
const std::string HTTPS_PREFIX = "https://";
const std::string HOSTNAME = "localhost";
const std::string DEFAULT_PORT = "8080";

/**************************** FUNCTIONS ******************************/
std::vector<std::string> parse_command_line(std::string command_line)
{
    std::vector<std::string> parsed_line;
    size_t found = command_line.find_first_of(" ");
    if(found == std::string::npos)
    {
        parsed_line.push_back("ERROR");
        return parsed_line;
    }  

    std::string protocol = command_line.substr(0, found);
    if(protocol != "HTTP/1.0")
    {
        parsed_line.push_back("ERROR");
        return parsed_line;
    }

    std::string status_text = command_line.substr(found + 1);
    size_t found_2 = status_text.find_first_of(" ");
    std::string status = command_line.substr(found + 1, found_2);
    if(status.empty() || (status != "200" && status != "400" && status != "500"))
    {
        parsed_line.push_back("ERROR");
        return parsed_line;
    }

    std::string text = status_text.substr(found_2 + 1);
    if(text.empty())
    {
        parsed_line.push_back("ERROR");
        return parsed_line;
    }

    parsed_line.push_back(protocol);
    parsed_line.push_back(status);
    parsed_line.push_back(text);
    return parsed_line;
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

HTTPresponse parse_http_response(std::string server_response)
{
    // HTTPresponse object is returned
    std::istringstream f(server_response);
    std::string line;
    HTTPresponse response;
    response.valid = true;

    bool redirect = false;
    bool redirect_found = false;
    bool cmd_line_flag = true;
    bool response_body_flag = false;
    while ( std::getline(f, line) )
    {
        // Remove all carriage returns
        line.erase( std::remove(line.begin(), line.end(), '\r'), line.end());

        // Check if location option line exists
        if (redirect)
        {
            redirect_found = (line.find("Location:") != std::string::npos);
        }

        if (cmd_line_flag)
        {
            cmd_line_flag = false; // Save server command line
            response.command_line = line;

            std::vector<std::string> parsed_command_line = parse_command_line(line);
            if ( parsed_command_line.size() == 3 && 
                parsed_command_line.size() == 3 &&
                is_number(parsed_command_line[1]))
            {
                response.status_code = parsed_command_line[1];
                response.status_text = parsed_command_line[2];
                if (response.status_text[0] == '3' )
                {
                    redirect = true;
                }
            }
            else 
            {
                response.valid = false;
                response.error_msg = "Server response invalidly formatted. Command line invalid.";
            }
        }
        else if ( response_body_flag )
        {
            response.body += line + "\n";
        }
        else if ( convert_to_lower(line).find("content-length:") != std::string::npos )
        {
            std::vector<std::string> split_content_len = split(line, ":");
            std::string content_len_str = split_content_len[1];
            std::string::iterator end_pos = std::remove(content_len_str.begin(), content_len_str.end(), ' ');
            content_len_str.erase(end_pos, content_len_str.end());
            if ( is_number(content_len_str) )
            {
                response.content_length = content_len_str;
            }
            else
            {
                response.valid = false;
                response.error_msg = "Server response invalidly formatted. Content-length invalid.";
            }
        }
        else if ( line.empty() ) // Reached the newline delimiter, start body
        {
            response_body_flag = true;

            // Response had 300 status code but no redirect option line
            if (redirect && !redirect_found)
            {
                response.valid = false;
                response.error_msg = "Server response invalidly formatted. 300 redirect not found.";
            }
        }
        else
        {
            continue;
        }
    }

    // Error checking
    if(response.status_code[0] != '2' && response.status_code[0] != '3' && response.status_code[0] != '4' && response.status_code[0] != '5')
    {
        response.valid = false;
        response.error_msg = "Server response invalidly formatted. Expected a status code beginning 2, 3, 4, or 5.";
    }
    else if(response.status_code[0] == '4' || response.status_code[0] == '5')
    {
        response.valid = false;
        response.error_msg = "ERROR. Server responded with status:\n" + response.status_code + ": " + response.status_text;
    }

    // We put one more newline than was in the response during parsing, so take it out
    return response;
}