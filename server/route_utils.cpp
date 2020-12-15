#include <string.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include "route_utils.h"
#include "server_utils.h"

// CONSTANTS AND MACROS
const std::string VERIFY_PASS_PATH = "./verify-pass";
const std::string UPDATE_PASS_PATH = "./update-pass";
const std::string CERT_GEN_PATH = "./cert-gen";
const std::string FETCH_CERT_PATH = "./fetch-cert";
const std::string MAIL_OUT_PATH = "./mail-out";
const std::string MAIL_IN_PATH = "./mail-in";

const std::string GETCERT_ROUTE = "/getcert";
const std::string CHANGEPW_ROUTE = "/changepw";
const std::string SENDMSG_ENCRYPT_ROUTE = "/sendmsg_encrypt";
const std::string SENDMSG_MESSAGE_ROUTE = "/sendmsg_message";
const std::string RECVMSG_ROUTE = "/recvmsg";

int call_server_program(std::string program_name, std::vector<std::string> args)
{
    // Open up mail-out for each message we want to mailbox to send to
    int status;
    int pipe_fd[2];
    pid_t p;

    if (pipe(pipe_fd) == -1) 
    {
        std::cerr << "Pipe failed." << std::endl;
        return 1;
    }

    p = fork();
    if (p < 0) 
    {
        // Failed fork
        std::cerr << "Fork failed." << std::endl;
        return 1;
    }
    else if (p == 0)
    {
        // Child process
        close(pipe_fd[0]);               // Close the reading end of the pipe
        close(pipe_fd[1]);               // Close the writing end of the pipe
        close(STDIN_FILENO);             // Close the current stdin 
        dup2(pipe_fd[0], STDIN_FILENO);  // Replace stdin with the reading end of the pipe
        
        // Branch for each of the possible execl server programs
        if ( program_name == "verify-pass" )
        {
            // arg[0] = username
            // arg[1] = password
            status = execl(VERIFY_PASS_PATH.c_str(), VERIFY_PASS_PATH.c_str(), args[0].c_str(), args[1].c_str());
        }
        else if ( program_name == "update-pass" )
        {
            status = execl(UPDATE_PASS_PATH.c_str(), UPDATE_PASS_PATH.c_str(), args[0].c_str(), args[1].c_str());
        }
        else if ( program_name == "cert-gen" )
        {
            // arg[0] = csr string
            status = execl(CERT_GEN_PATH.c_str(), CERT_GEN_PATH.c_str(), args[0].c_str());
        }
        else if ( program_name == "fetch-cert" )
        {
            status = execl(FETCH_CERT_PATH.c_str(), FETCH_CERT_PATH.c_str(), args[0].c_str(), args[1].c_str());
        }
        else if ( program_name == "mail-out" )
        {
            status = execl(MAIL_OUT_PATH.c_str(), MAIL_OUT_PATH.c_str(), args[0].c_str());
        }
        else if ( program_name == "mail-in" )
        {
            status = execl(MAIL_IN_PATH.c_str(), MAIL_IN_PATH.c_str(), args[0].c_str(), args[1].c_str());
        }
    } 
    else 
    {
        // Parent process
        close(pipe_fd[0]); // Close the reading end of the pipe
        close(pipe_fd[1]); // Close the writing end of the pipe
        p = wait(&status);
    }

    return status;
}

std::string getcert_route(int content_length, std::string request_body)
{
    std::string response;

    // Parse out the username, password, and csr string from request
    std::vector<std::string> split_body = split(request_body, "\n");
    if (split_body.size() != 3)
    {
        std::cerr << "Request body not in valid format for getcert. Aborting.\n";
        response = "Request body not in valid format for getcert. Aborting.\n";
        return response;
    }

    std::string username = split_body[0];
    std::string password = split_body[1];
    std::string csr_string = split_body[2];
    std::vector<std::string> verify_pass_args {username, password};
 
    if (call_server_program("verify-pass", verify_pass_args) == 0)
    {
        std::cout << "Client username and password is valid. Now generating certificate...\n";
        std::vector<std::string> cert_gen_args {csr_string};
        if(call_server_program("cert-gen", cert_gen_args) == 0) // Success
        {
            // TODO: Read newly created cert from tmp file
            std::string cert; // Placeholder for now
            response = cert;
        }
        else
        {
            std::cerr << "Certificate generation failed on server end. cert-gen failed.\n";
            response = "Certificate generation failed (cert-gen failed).\n";
        }
    }
    else
    {
        std::cerr << "Client specified invalid username/password. verify-pass failed.\n";
        response = "Invalid username/password (verify-pass failed).\n";
    }

    return response;
}

std::string changepw_route(int content_length, std::string request_body)
{
    std::string response;

    // Parse out the username and passwords from request
    std::vector<std::string> split_body = split(request_body, "\n");
    if (split_body.size() != 4)
    {
        std::cerr << "Request body not in valid format for changepw. Aborting.\n";
        response = "Request body not in valid format for changepw. Aborting.\n";
        return response;
    }

    std::string username = split_body[0]; 
    std::string old_password = split_body[1];
    std::string new_password = split_body[2];
    std::string csr_string = split_body[3];
    std::vector<std::string> verify_pass_args {username, old_password};

    if (call_server_program("verify-pass", verify_pass_args) != 0)
    {
        std::cerr << "Client specified invalid username/password. verify-pass failed.\n";
        response = "Invalid username/password (verify-pass failed).\n";
        return response;
    }
    
    std::vector<std::string> mail_out_args {username};

    if (call_server_program("mail-out", mail_out_args) != 0)
    {
        std::cerr << "Message not found. mail-pass failed.\n";
        response = "Message not found. (mail-out failed).\n";
        return response;
    }
    
    std::vector<std::string> update_pass_args {username, new_password};

    if (call_server_program("update-pass", update_pass_args) != 0)
    {
        std::cerr << "Password could not be updated. update-pass failed.\n";
        response = "Password could not be updated. (update-pass failed).\n";
        return response;
    }

    // TODO: Write public key to file (?) so cert-gen can get it through stdin?
    // Passing a public key throguh command line arg seems very janky...

    std::vector<std::string> cert_gen_args {csr_string};
    if(call_server_program("cert-gen", cert_gen_args) == 0) // Success
    {
        // TODO: Read newly created cert from tmp file
        std::string cert; // Placeholder for now
        response = cert;
    }
    else
    {
        std::cerr << "Certificate generation failed on server end. cert-gen failed.\n";
        response = "Certificate generation failed (cert-gen failed).\n";
    }

    return response;
}

std::string sendmsg_encrypt_route(int content_length, std::string request_body)
{
    std::string response;

    // TODO: Parse out the recipient from request
    std::string recipient;
    std::string encryptCert = "1";
    std::vector<std::string> fetch_cert_args {recipient, encryptCert};

    if(call_server_program("fetch-cert", fetch_cert_args) == 0)
    {
        // TODO: Read fetched cert from tmp file
        std::string cert;
        response = cert;
    }
    else
    {
        std::cerr << "Encryption certificate could not be fetched on server end. fetch-cert failed.";
        response = "Encryption certificate could not be fetched (fetch-cert failed).";
    }

    return response;
}

std::string sendmsg_message_route(int content_length, std::string request_body)
{
    std::string response;

    // TODO: Parse out the message and recipient from request
    std::string recipient;
    std::string message;
    std::vector<std::string> mail_in_args {recipient, message};

    if(call_server_program("mail-in", mail_in_args) == 0)
    {
        response = "Message successfully sent to " + recipient;
    }
    else
    {
        std::cerr << "Message could not be successfully delivered. mail-in failed.";
        response = "Message could not be successfully delivered (mail-in failed).";
    }

    return response;
}

std::string recvmsg_route(int content_length, std::string request_body)
{
    std::string response;

    // TODO: Parse out the username from the request
    std::string username;
    std::vector<std::string> mail_out_args {username};

    if (call_server_program("mail-out", mail_out_args) == 0)
    {
        std::cerr << "Message not found. mail-pass failed.";
        response = "Message not found. (mail-out failed).";
        return response;
    }
    else
    {
        // TODO: Read retrieved message from tmp file
        // TODO: Also retrieve the sender of the message from the tmp file
        std::string encrypted_msg;
        std::string sender;

        // Fetch cert (contains public key to verify signature) for the sender
        std::string encryptCert = "0";
        std::vector<std::string> fetch_cert_args {sender, encryptCert};

        if(call_server_program("fetch-cert", fetch_cert_args) == 0)
        {
            // TODO: Read fetched cert from tmp file
            std::string cert;
            response = cert;
        }
        else
        {
            std::cerr << "Signing certificate could not be fetched on server end. fetch-cert failed.";
            response = "Signing certificate could not be fetched (fetch-cert failed).";
        }


        // TODO: concatenate the encrypted_msg and cert in one nicely formatted package
        response = "Hi I'm a placeholder for a nicely conatenated encrypted_msg and cert";
    }

    return response;
}