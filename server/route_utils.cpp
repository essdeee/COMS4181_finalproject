#include <string.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include "route_utils.h"

// CONSTANTS AND MACROS
extern const std::string VERIFY_PASS_PATH = "./../pass/bin/verify-pass";
extern const std::string UPDATE_PASS_PATH = "./../pass/bin/update-pass";
extern const std::string CERT_GEN_PATH = "./../client_certs/bin/cert-gen";
extern const std::string FETCH_CERT_PATH = "./../client_certs/bin/fetch-cert";
extern const std::string MAIL_OUT_PATH = "./../mail/bin/mail-out";
extern const std::string MAIL_IN_PATH = "./../mail/bin/mail-in";

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
        if ( program_name == "verify-pass")
        {
            execl(VERIFY_PASS_PATH.c_str(), VERIFY_PASS_PATH.c_str(), args[0].c_str(), args[1].c_str());
        }
        else if ( program_name == "update-pass" )
        {
            execl(UPDATE_PASS_PATH.c_str(), UPDATE_PASS_PATH.c_str(), args[0].c_str(), args[1].c_str());
        }
        else if ( program_name == "cert-gen" )
        {
            execl(CERT_GEN_PATH.c_str(), CERT_GEN_PATH.c_str(), args[0].c_str(), args[1].c_str());
        }
        else if ( program_name == "fetch-cert" )
        {
            execl(FETCH_CERT_PATH.c_str(), FETCH_CERT_PATH.c_str(), args[0].c_str(), args[1].c_str());
        }
        else if ( program_name == "mail-out" )
        {
            execl(MAIL_OUT_PATH.c_str(), MAIL_OUT_PATH.c_str(), args[0].c_str());
        }
        else if ( program_name == "mail-in" )
        {
            execl(MAIL_IN_PATH.c_str(), MAIL_IN_PATH.c_str(), args[0].c_str(), args[1].c_str());
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

std::string get_cert_route(int content_length, std::string request_body)
{
    std::string response;

    // TODO: Parse out the username and password from request
    std::string username;
    std::string password;
    std::vector<std::string> verify_pass_args {username, password};

    if (call_server_program("verify-pass", verify_pass_args))
    {
        // TODO: Write public key to file (?) so cert-gen can get it through stdin?
        // Passing a public key through command line arg seems very janky...

        std::string username;
        std::vector<std::string> cert_gen_args {username};
        if(call_server_program("cert-gen", cert_gen_args) == 0) // Success
        {
            // TODO: Read newly created cert from tmp file
            std::string cert; // Placeholder for now
            response = cert;
        }
        else
        {
            std::cerr << "Certificate generation failed on server end. cert-gen failed.";
            response = "Certificate generation failed (cert-gen failed).";
        }
    }
    else
    {
        std::cerr << "Client specified invalid username/password. verify-pass failed.";
        response = "Invalid username/password (verify-pass failed).";
    }

    return response;
}

std::string change_pw_route(int content_length, std::string request_body)
{
    std::string response;

    // TODO: Parse out the username and password from request
    std::string username;
    std::string old_password;
    std::string new_password;
    std::vector<std::string> verify_pass_args {username, old_password};

    if (call_server_program("verify-pass", verify_pass_args) != 0)
    {
        std::cerr << "Client specified invalid username/password. verify-pass failed.";
        response = "Invalid username/password (verify-pass failed).";
        return response;
    }
    
    std::vector<std::string> mail_out_args {username};

    if (call_server_program("mail-out", mail_out_args) != 0)
    {
        std::cerr << "Message not found. mail-pass failed.";
        response = "Message not found. (mail-out failed).";
        return response;
    }
    
    std::vector<std::string> update_pass_args {username, new_password};

    if (call_server_program("update-pass", update_pass_args) != 0)
    {
        std::cerr << "Password could not be updated. update-pass failed.";
        response = "Password could not be updated. (update-pass failed).";
        return response;
    }

    // TODO: Write public key to file (?) so cert-gen can get it through stdin?
    // Passing a public key throguh command line arg seems very janky...

    std::vector<std::string> cert_gen_args {username};
    if(call_server_program("cert-gen", cert_gen_args) == 0) // Success
    {
        // TODO: Read newly created cert from tmp file
        std::string cert; // Placeholder for now
        response = cert;
    }
    else
    {
        std::cerr << "Certificate generation failed on server end. cert-gen failed.";
        response = "Certificate generation failed (cert-gen failed).";
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