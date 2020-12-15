#include <iostream>
#include <fstream>
#include "server_utils.h"

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        std::cerr << "verify-pass must have two arguments. Aborting.\n";
        return 1;
    }

    // Extract user and pass from args
    std::string username = argv[1];
    std::string password = argv[2];

    // Read from password file
    std::ifstream infile(PASSWORD_FILE);
    std::vector<std::string> new_pass_file_lines;
    std::string line;
    while ( std::getline(infile, line) )
    {
        // Get data from the password file for current user
        std::vector<std::string> split_line = split(line, " ");
        if (split_line.size() != 3)
        {
            std::cerr << "Password file is corrupted. Line invalid.\n";
            return 1;
        }
        std::string true_username = split_line[0];
        std::string true_salt_hash = split_line[1];
        std::string true_pass = split_line[2];

        // Check if the password is for the current user
        if (username == true_username)
        {
            // New hash with randomly generated salt
            std::string hash = hash_password(password);
                
            // Get salt and hash from hashed_pass
            std::vector<std::string> version_salt_hash = split(hash, "$");
            if (version_salt_hash.size() != 3)
            {
                std::cerr << "Password file is corrupted. Hash not calculated correctly.\n";
                return 1;
            }
            std::string new_version = "$" + version_salt_hash[0];
            std::string new_salt = version_salt_hash[1];
            std::string new_hash = version_salt_hash[2];

            // Generate new line with new password and hashed password
            std::string new_line;
            new_line += username + " ";
            new_line += hash + " ";
            new_line += password; 
            new_pass_file_lines.push_back(new_line);
        }
        else
        {
            new_pass_file_lines.push_back(line);
        }
    }

    infile.close();

    // Write updated password file
    std::ofstream outfile(PASSWORD_FILE);
    for ( std::string new_line : new_pass_file_lines)
    {
        outfile << new_line + "\n";
    }
    outfile.close();

    return 0;
}