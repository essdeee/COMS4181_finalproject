#include <string.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <fstream>
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

const std::string FETCH_ENCRYPT_CERT = "encrypt";
const std::string FETCH_SIGN_CERT = "sign";

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
        close(pipe_fd[1]);               // Close the writing end of the pipe
        close(STDIN_FILENO);             // Close the current stdin 
        dup2(pipe_fd[0], STDIN_FILENO);  // Replace stdin with the reading end of the pipe
        
        // Branch for each of the possible execl server programs
        if ( program_name == "verify-pass" )
        {
            // arg[0] = username
            // arg[1] = password
            close(pipe_fd[0]);               // Close the reading end of the pipe
            status = execl(VERIFY_PASS_PATH.c_str(), VERIFY_PASS_PATH.c_str(), args[0].c_str(), args[1].c_str(), NULL);
        }
        else if ( program_name == "update-pass" )
        {
            close(pipe_fd[0]);               // Close the reading end of the pipe
            status = execl(UPDATE_PASS_PATH.c_str(), UPDATE_PASS_PATH.c_str(), args[0].c_str(), args[1].c_str(), NULL);
        }
        else if ( program_name == "cert-gen" )
        {
            // arg[0] = csr string
            // arg[1] = username (to save cert in correct place)
            close(pipe_fd[0]);               // Close the reading end of the pipe
            status = execl(CERT_GEN_PATH.c_str(), CERT_GEN_PATH.c_str(), args[0].c_str(), args[1].c_str(), NULL);
        }
        else if ( program_name == "fetch-cert" )
        {
            close(pipe_fd[0]);               // Close the reading end of the pipe
            status = execl(FETCH_CERT_PATH.c_str(), FETCH_CERT_PATH.c_str(), args[0].c_str(), args[1].c_str(), NULL);
        }
        else if ( program_name == "mail-out" )
        {
            close(pipe_fd[0]);               // Close the reading end of the pipe
            status = execl(MAIL_OUT_PATH.c_str(), MAIL_OUT_PATH.c_str(), args[0].c_str(), args[1].c_str(), NULL);
        }
        else if ( program_name == "mail-in" )
        {
            status = execl(MAIL_IN_PATH.c_str(), MAIL_IN_PATH.c_str(), args[0].c_str(), NULL);
        }
    } 
    else 
    {
        // Parent process
        close(pipe_fd[0]); // Close the reading end of the pipe
        if ( program_name == "mail-in")
        {   
            write(pipe_fd[1], args[1].c_str(), strlen(args[1].c_str()) + 1);
        }
        close(pipe_fd[1]); // Close the writing end of the pipe
        
        p = wait(&status);
    }

    return WEXITSTATUS(status);
}

HTTPresponse getcert_route(int content_length, std::string request_body)
{
    HTTPresponse response;
    response.error = false;

    // Make sure the content length is as expected
    if(content_length != request_body.size())
    {
        return server_error_response("getcert_route", "Request body and content-length mismatch", "400");
    }

    // Parse out the username, password, and csr string from request
    std::vector<std::string> split_body = split(request_body, "\n");
    if (split_body.size() != 3)
    {
        return server_error_response("getcert_route", "Request body not in valid format.", "400");
    }

    std::string username = split_body[0];
    std::string password = split_body[1];
    std::string csr_string = split_body[2];

    // Validate username and password
    if(username.length() > MAILBOX_NAME_MAX || !validMailboxChars(username))
    {
        return server_error_response("getcert_route", "Username in request body invalid format.", "400");
    }

    if(password.length() > MAILBOX_NAME_MAX || !validPasswordChars(password))
    {
        return server_error_response("getcert_route", "Password in request body invalid format.", "400");
    }

    std::vector<std::string> verify_pass_args {username, password};
    if (call_server_program("verify-pass", verify_pass_args) == 0)
    {
        std::cout << "Client username and password is valid. Now generating certificate...\n";
        std::vector<std::string> cert_gen_args {csr_string, username};
        if(call_server_program("cert-gen", cert_gen_args) == 0) // Success
        {
            // Read newly created certificate from tmp file
            std::string cert; // Placeholder for now
            std::ifstream infile(TMP_CERT_FILE);
            infile >> cert;
            response.body = cert;

            if( remove( TMP_CERT_FILE.c_str() ) != 0 )
            {
                return server_error_response("cert-gen", "Error deleting tmp file on server end.", "500");
            }
        }
        else
        {
            return server_error_response("cert-gen", "Certificate generation failed on server end.", "500");
        }
    }
    else
    {
        return server_error_response("cert-gen", "Client specified invalid username/password combination.", "400");
    }

    response.command_line = HTTP_VERSION + " 200 OK";
    response.status_code = "200";
    response.content_length = response.body.size();
    return response;
}

HTTPresponse changepw_route(int content_length, std::string request_body)
{
    HTTPresponse response;
    response.error = false;

    // Make sure the content length is as expected
    if(content_length != request_body.size())
    {
        return server_error_response("changepw_route", "Request body and content-length mismatch", "400");
    }

    // Parse out the username and passwords from request
    std::vector<std::string> split_body = split(request_body, "\n");
    if (split_body.size() != 4)
    {
        return server_error_response("changepw_route", "Request body not in valid format for changepw.", "400");
    }

    std::string username = split_body[0]; 
    std::string old_password = split_body[1];
    std::string new_password = split_body[2];
    std::string csr_string = split_body[3];

    // Validate username and password
    if(username.length() > MAILBOX_NAME_MAX || !validMailboxChars(username))
    {
        return server_error_response("getcert_route", "Username in request body invalid format.", "400");
    }
    if(old_password.length() > PASSWORD_MAX || !validPasswordChars(old_password))
    {
        return server_error_response("getcert_route", "Old password in request body invalid format.", "400");
    }
    if(new_password.length() > PASSWORD_MAX || !validPasswordChars(new_password))
    {
        return server_error_response("getcert_route", "New password in request body invalid format.", "400");
    }

    // The meat of the execl programs...
    // Call verify-pass to make sure the password hashes and verifies.
    std::vector<std::string> verify_pass_args {username, old_password};
    if (call_server_program("verify-pass", verify_pass_args) != 0)
    {
        return server_error_response("verify-pass", "Client specified invalid username/password.", "400");
    }
    
    // mail-out called to make sure there's no pending mail.
    std::vector<std::string> mail_out_args {username, MAIL_OUT_PEEK};
    int mail_out_return = call_server_program("mail-out", mail_out_args);
    if (mail_out_return == MAIL_OUT_MSG_FOUND)
    {
        return server_error_response("mail-out", "Message still found in inbox. Password cannot be updated yet.", "500");
    }
    else if (mail_out_return == MAIL_OUT_ERROR)
    {
        return server_error_response("mail-out", "Mail checking program failed because internal error. Please try again.", "500");
    }
    
    // cert-gen called to generate new certificate, encode, and send back to client as response body.
    std::vector<std::string> cert_gen_args {csr_string, username};
    if(call_server_program("cert-gen", cert_gen_args) == 0) // Success
    {
        std::string cert;
        std::ifstream infile(TMP_CERT_FILE);
        infile >> cert;
        response.body = cert;

        if( remove( TMP_CERT_FILE.c_str() ) != 0 )
        {
            return server_error_response("cert-gen", "Error deleting tmp file on server end.", "500");
        }
        response.body = cert;
    }
    else
    {
        return server_error_response("cert-gen", "Certificate generation failed on server end.", "500");
    }

    // update-pass finally called to update the password in the shadow file.
    std::vector<std::string> update_pass_args {username, new_password};
    if (call_server_program("update-pass", update_pass_args) != 0)
    {
        return server_error_response("update-pass", "Password could not be updated on server end.", "500");
    }

    response.command_line = HTTP_VERSION + " 200 OK";
    response.status_code = "200";
    response.content_length = response.body.size();
    return response;
}

HTTPresponse sendmsg_encrypt_route(int content_length, std::string request_body)
{
    HTTPresponse response;
    response.error = false;

    // Body is just a list of recipients
    std::vector<std::string> recipients = split(request_body, "\n");
    if (recipients.size() == 0)
    {
        std::cerr << "Request body not in valid format for sendmsg_encrypt. Aborting.\n";
        response.command_line = HTTP_VERSION + " 400" + " Request body not in valid format for sendmsg_encrypt.";
        response.status_code = "400";
        response.error = true;
        return response;
    }

    // For each recipient, fetch the encryption certificate
    for (std::string recipient : recipients)
    {
        std::string encryptCert = FETCH_ENCRYPT_CERT;
        std::vector<std::string> fetch_cert_args {recipient, encryptCert};

        if(call_server_program("fetch-cert", fetch_cert_args) == 0)
        {
            std::string cert;
            std::ifstream infile(TMP_CERT_FILE);
            infile >> cert;

            if( remove( TMP_CERT_FILE.c_str() ) != 0 )
            {
                std::cerr << "Error deleting tmp file. getcert failed on server end. Aborting.\n";
                response.command_line = HTTP_VERSION + " 500" + " Error deleting tmp file on server end.";
                response.status_code = "500";
                response.error = true;
                return response;
            }

            response.body += cert + "\n";
        }
        else
        {
            std::cerr << "Encryption certificate could not be fetched. fetch-cert failed.";
            response.command_line = HTTP_VERSION + " 500" + " Encryption certificate could not be fetched for user: " + recipient;
            response.status_code = "500";
            response.error = true;
            return response;
        }
    }

    response.command_line = HTTP_VERSION + " 200 OK";
    response.status_code = "200";
    response.content_length = response.body.size();
    return response;
}

HTTPresponse sendmsg_message_route(int content_length, std::string request_body)
{
    HTTPresponse response;
    response.error = false;

    // Split body of request into vector of {recipients, msg1, msg2, ... msg_n}
    std::vector<std::string> request_body_split = split(request_body, "\n");
    if(request_body_split.size() < 2)
    {
        std::cerr << "Request body not in valid format for sendmsg_message. Aborting.\n";
        response.command_line = HTTP_VERSION + " 400" + " Request body not in valid format for sendmsg_message.";
        response.status_code = "400";
        response.error = true;
        return response;
    }

    // Parse out the recipients and the corresponding messages
    std::vector<std::string> recipients;
    std::vector<std::string> messages;
    std::string unparsed_recipients = request_body_split[0];
    recipients = split(unparsed_recipients, ":");
    request_body_split.erase(request_body_split.begin());
    messages = request_body_split;

    if ( recipients.size() != messages.size() )
    {
        std::cerr << "Number of recipients does not match number of messages. Invalid client request.\n";
        response.command_line = HTTP_VERSION + " 400" + " Number of recipients does not match number of messages.";
        response.status_code = "400";
        response.error = true;
        return response;
    }

    // TODO: SOMEHOW GET THE SENDER FROM THE CLIENT'S CERTIFICATE

    for ( int i = 0; i < recipients.size(); i++ )
    {
        std::vector<std::string> mail_in_args {recipients[i], messages[i]};

        if(call_server_program("mail-in", mail_in_args) != 0)
        {
            std::cerr << "Message could not be successfully delivered. mail-in failed.\n";
            response.command_line = HTTP_VERSION + " 500" + " Message could not be successfully delivered on server end.";
            response.status_code = "500";
            response.error = true;
            return response;
        }
    }

    response.command_line = HTTP_VERSION + " 200 OK";
    response.status_code = "200"; // No body because no data is being sent
    response.content_length = 0;
    return response;
}

HTTPresponse recvmsg_route(std::string username)
{
    HTTPresponse response;
    response.error = false;

    std::vector<std::string> mail_out_args {username, MAIL_OUT_SEND};
    int mail_out_return = call_server_program("mail-out", mail_out_args);
    if (mail_out_return == MAIL_OUT_EMPTY)
    {
        std::cerr << "Message not found. mail-out failed.\n";
        response.command_line = HTTP_VERSION + " 500" + " No messages pending on server end.";
        response.status_code = "500";
        response.error = true;
        return response;
    }
    else if (mail_out_return == MAIL_OUT_ERROR)
    {
        std::cerr << "mail-out failed because of internal error.\n";
        response.command_line = HTTP_VERSION + " 500" + " Mail delivery failed because internal error.";
        response.status_code = "500";
        response.error = true;
        return response;
    }
    else
    {
        std::cout << mail_out_return << std::endl;
        // mail-out returned 0, so we can read the msg from the tmp file tmp-msg
        std::string msg;
        std::string encrypted_msg;
        std::string sender;
        std::string cert;

        // Read the message from tmp file
        std::ifstream msgstream(TMP_MSG_FILE);
        msgstream >> msg;
        if( remove( TMP_MSG_FILE.c_str() ) != 0 )
        {
            std::cerr << "Error deleting tmp file. mail-out failed on server end. Aborting.\n";
            response.command_line = HTTP_VERSION + " 500" + " Error deleting tmp file on server end.";
            response.status_code = "500";
            response.error = true;
            return response;
        }

        // Parse out the sender and the message
        size_t newline = msg.find_first_of("\n");
        sender = msg.substr(0, newline);
        encrypted_msg = msg.substr(newline + 1); 

        // Fetch cert (contains public key to verify signature) for the sender
        std::string encryptCert = "sign";
        std::vector<std::string> fetch_cert_args {sender, encryptCert};

        if(call_server_program("fetch-cert", fetch_cert_args) == 0)
        {
            std::ifstream infile(TMP_CERT_FILE);
            infile >> cert;

            if( remove( TMP_CERT_FILE.c_str() ) != 0 )
            {
                std::cerr << "Error deleting tmp file. fetch-cert failed on server end. Aborting.\n";
                response.command_line = HTTP_VERSION + " 500" + " Error deleting tmp file on server end.";
                response.status_code = "500";
                response.error = true;
                return response;
            }
        }
        else
        {
            std::cerr << "Signing certificate could not be fetched (fetch-cert failed).";
            response.command_line = HTTP_VERSION + " 500" + " Signing certificate could not be fetched on server end.";
            response.status_code = "500";
            response.error = true;
            return response;
        }

        response.body += cert + "\n";
        response.body += encrypted_msg;
    }

    response.command_line = HTTP_VERSION + " 200 OK";
    response.status_code = "200";
    response.content_length = response.body.size();
    return response;
}