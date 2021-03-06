#include "server_utils.h"
#include <iostream>
#include <fstream>

int main(int argc, char *argv[])
{
    // Parse out only the username
    if (argc != 3)
    {
        std::cerr << "mail-out must have a two arguments: mailbox name and peek/send. Aborting.\n";
        exit(MAIL_OUT_ERROR);
    }

    // Check if the mailbox exists
    std::string username = argv[1];
    std::string keep_or_remove = argv[2];
    if(!validMailboxChars(username) || username.length() > MAILBOX_NAME_MAX || !doesMailboxExist(username))
    {
        std::cerr << "mail-out could not identify the username. Aborting.\n";
        exit(MAIL_OUT_ERROR);
    }

    if(keep_or_remove == MAIL_OUT_PEEK)
    {
        // Check if the mailbox has any messages pending
        if(isMailboxEmpty(username))
        {
            std::cerr << username << " has 0 pending messages.\n";
            exit(MAIL_OUT_EMPTY);
        }
        else
        {
            exit(MAIL_OUT_MSG_FOUND);
        }
    }
    else if(keep_or_remove == MAIL_OUT_SEND)
    {
        // Check if the mailbox has any messages pending
        if(isMailboxEmpty(username))
        {
            std::cerr << username << " has 0 pending messages.\n";
            exit(MAIL_OUT_EMPTY);
        }

        // Get the earliest file (the one to output)
        std::string file_to_output = getEarliestNumberPath(username);
        std::ifstream f;
        std::string sender;
        std::string msg;
        f.open(file_to_output);

        // Messages should ALWAYS have two lines and only two lines: (1) sender (2) encrypted message
        if(f.good())
        {
            std::getline(f, sender);
            std::getline(f, msg);
        }
        else
        {
            std::cerr << "mail-out could not open earliest message.\n";
            exit(MAIL_OUT_ERROR);
        }    

        if(sender.empty() || msg.empty())
        {
            std::cerr << "mailbox's earliest message is empty or formatted incorrectly.\n";
            exit(MAIL_OUT_ERROR);
        }

        // Write to tmp file
        std::ofstream new_file;
        new_file.open(TMP_MSG_FILE.c_str(), std::ios::trunc);
        if(new_file.is_open())
        {
            new_file << sender;
            new_file << '\n';
            new_file << msg;
            new_file.close();
        }
        else
        {
            std::cerr << "mail-out could not write to new tmp-msg file. Aborting...\n";
            exit(MAIL_OUT_ERROR); 
        }

        // Remove original file
        if( remove(file_to_output.c_str()) != 0 )
        {
            std::cerr << "Error deleting original message file. mail-out failed. Aborting...\n";
            exit(MAIL_OUT_ERROR);
        }

        // If all goes well, we can return the msg_found status
        exit(MAIL_OUT_MSG_FOUND);
    }
    else
    {
        std::cerr << "mail-out was not passed in correct send/peek argument. Aborting.\n";
        exit(MAIL_OUT_ERROR);
    }
}