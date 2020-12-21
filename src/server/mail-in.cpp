#include "server_utils.h"
#include <iostream>
#include <fstream>

int main(int argc, char *argv[])
{
    // Parse arguments
    if (argc != 3)
    {
        std::cerr << "mail-in must have two argument: the recipient and the sender.\n";
        return 1;
    }

    // Parse and validate the recipient
    std::string recipient = argv[1];
    std::string sender = argv[2];
    if(!validMailboxChars(recipient) || recipient.length() > MAILBOX_NAME_MAX || !doesMailboxExist(recipient))
    {
        std::cerr << "mail-in could not identify the recipient. Aborting...\n";
        return 1;
    }

    // Read the input message (preventing overflow). Should only be a single line.
    std::string msg;
    std::getline(std::cin, msg);
    std::cout << "MAIL-IN SIZE:" << msg.size() << std::endl;

    // Get next message number in mailbox
    std::string next_file_name = getNextNumber(recipient);

    // Check if getNextNumber failed (should not have to worry about this)
    if (next_file_name == "ERROR")
    {
        std::cerr << "mail-in error getting next file to write in mailbox. Mailbox might be full.\n";
        return 1; 
    }

    std::string new_mail_path = newMailPath(recipient, next_file_name); // Get path to write to
    std::cout << "HERE IS THE PATH: " << new_mail_path << std::endl;

    // Write to the correct mailbox
    std::ofstream new_file;
    new_file.open(new_mail_path, std::ios::trunc);
    if(new_file.is_open())
    {
        // Format is sender<newline>mesage 
        new_file << sender;
        new_file << '\n';
        new_file << msg;
        new_file.close();
    }
    else
    {
        std::cerr << "mail-in could not write to new file in mailbox. Aborting...\n";
        return 1; 
    }

    return 0;
}