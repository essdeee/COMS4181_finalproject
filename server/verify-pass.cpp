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
    std::string line;
    int valid = 1; // 0 for valid, 1 for invalid
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

        // Get salt and hash from hashed_pass
        std::vector<std::string> version_salt_hash = split(true_salt_hash, "$");
        if (version_salt_hash.size() != 3)
        {
            std::cerr << "Password file is corrupted. Hash not calculated correctly.\n";
            return 1;
        }
        std::string true_version = "$" + version_salt_hash[0];
        std::string true_salt = version_salt_hash[1];
        std::string true_hash = version_salt_hash[2];

        // Check if the password is valid for the current user
        if (username == true_username)
        {
            std::string hash = hash_password(password, true_version + "$" + true_salt);
            if (hash == true_version + "$" + true_salt + "$" + true_hash)
            {
                valid = 0;
            }
        }
    }

    return valid;
}