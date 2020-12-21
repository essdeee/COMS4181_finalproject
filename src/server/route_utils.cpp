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
const std::string VERIFY_PASS_PATH = "password/bin/verify-pass";
const std::string UPDATE_PASS_PATH = "password/bin/update-pass";
const std::string CERT_GEN_PATH = "client_certs/bin/cert-gen";
const std::string FETCH_CERT_PATH = "client_certs/bin/fetch-cert";
const std::string MAIL_OUT_PATH = "mail/bin/mail-out";
const std::string MAIL_IN_PATH = "mail/bin/mail-in";

const std::string GETCERT_ROUTE = "/getcert";
const std::string CHANGEPW_ROUTE = "/changepw";
const std::string SENDMSG_ENCRYPT_ROUTE = "/sendmsg_encrypt";
const std::string SENDMSG_MESSAGE_ROUTE = "/sendmsg_message";
const std::string RECVMSG_ROUTE = "/recvmsg";

const std::string FETCH_ENCRYPT_CERT = "encrypt";
const std::string FETCH_SIGN_CERT = "sign";
const std::string GETCERT_NEW_CERT = "new";
const std::string GETCERT_OLD_CERT = "old";

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
            status = execl(FETCH_CERT_PATH.c_str(), FETCH_CERT_PATH.c_str(), args[0].c_str(), NULL);
        }
        else if ( program_name == "mail-out" )
        {
            close(pipe_fd[0]);               // Close the reading end of the pipe
            status = execl(MAIL_OUT_PATH.c_str(), MAIL_OUT_PATH.c_str(), args[0].c_str(), args[1].c_str(), NULL);
        }
        else if ( program_name == "mail-in" )
        {
            status = execl(MAIL_IN_PATH.c_str(), MAIL_IN_PATH.c_str(), args[0].c_str(), args[1].c_str(), NULL);
        }
    } 
    else 
    {
        // Parent process
        close(pipe_fd[0]); // Close the reading end of the pipe
        if ( program_name == "mail-in")
        {   
            write(pipe_fd[1], args[2].c_str(), strlen(args[2].c_str()));
        }
        close(pipe_fd[1]); // Close the writing end of the pipe
        
        p = wait(&status);
    }

    return WEXITSTATUS(status);
}

HTTPresponse validate_client_certificate(const std::string failure_program, const std::string username, const std::string encoded_client_cert)
{
    std::vector<std::string> fetch_cert_args = {username};
    bool valid = false;
    if(call_server_program("fetch-cert", fetch_cert_args) == 0)
    {
        // Extract the client cert on the server
        std::string server_client_cert;
        std::ifstream infile(TMP_CERT_FILE);
        infile >> server_client_cert;
        infile.close();

        // Delete tmp file after getting the encoded cert from fetch-cert
        if( remove( TMP_CERT_FILE.c_str() ) != 0 )
        {
            return server_error_response(failure_program, "Error deleting tmp file while validating client cert.", "500");
        }

        valid = (server_client_cert == encoded_client_cert);
    }
    else
    {
        return server_error_response(failure_program, "Could not fetch client certificate from client's directory on server end to validate.", "500");
    }

    // Client certificate could have validated with the one in directory or not
    if(!valid)
    {
        return server_error_response(failure_program, "Client certificate did not match existing certificate on serer.", "500");
    }

    HTTPresponse response;
    response.error = false;
    return response;
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

    std::string cert;       // Write to this string the base64encoded certificate
    std::string new_or_old; // Flag for client to know if this is a new cert or an old one
    std::vector<std::string> verify_pass_args {username, password};
    if (call_server_program("verify-pass", verify_pass_args) == 0)
    {
        std::cout << "Client username and password is valid. Checking for certificate...\n";

        std::vector<std::string> fetch_cert_args {username};

        // Certificate already exists on server. Send existing one back.
        if(call_server_program("fetch-cert", fetch_cert_args) == 0)
        {
            // Extract the client cert on the server
            std::cout << "Certificate already exists for " + username + ". Sending back existing cert...\n";
            new_or_old = GETCERT_OLD_CERT;
            std::ifstream infile(TMP_CERT_FILE);
            infile >> cert;
            infile.close();

            // Delete tmp file after getting the encoded cert from fetch-cert
            if( remove( TMP_CERT_FILE.c_str() ) != 0 )
            {
                return server_error_response("fetch-cert", "Error deleting tmp file while getting client cert.", "500");
            }
        }
        // Certificate does not yet exist on server. Sign the CSR and create a new cert for user.
        else
        {
            std::cout << "Certificate does not yet exist for " + username + ". Generating new cert from CSR...\n";
            new_or_old = GETCERT_NEW_CERT;
            std::vector<std::string> cert_gen_args {csr_string, username};
            if(call_server_program("cert-gen", cert_gen_args) == 0) // Success
            {
                // Read newly created certificate from tmp file
                std::ifstream infile(TMP_CERT_FILE);
                infile >> cert;

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
    }
    else
    {
        return server_error_response("cert-gen", "Client specified invalid username/password combination.", "400");
    }

    response.body += new_or_old + "\n";
    response.body += cert;
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

HTTPresponse sendmsg_encrypt_route(int content_length, std::string request_body, const std::string username, const std::string encoded_client_cert)
{
    // Perform the final validation - does the certificate match the one on file?
    HTTPresponse response = validate_client_certificate("sendmsg_encrypt_route", username, encoded_client_cert);
    if(response.error)
    {
        std::cerr << "Client authentication failed at validation step.\n";
        return response;
    }
    std::cout << "Client authentication successfully passed as: " + username << std::endl;

    // Make sure the content length is as expected
    if(content_length != request_body.size())
    {
        return server_error_response("sendmsg_encrypt_route", "Request body and content-length mismatch", "400");
    }

    // Body is just a list of recipients
    std::vector<std::string> recipients = split(request_body, "\n");
    if (recipients.size() == 0)
    {
        return server_error_response("sendmsg_encrypt_route", "Request body not in valid format for sendmsg_encrypt.", "400");
    }

    // For each recipient, fetch the encryption certificate
    for (std::string recipient : recipients)
    {
        // Validate each reicpient to make sure they're kosher
        if(recipient.length() > MAILBOX_NAME_MAX || !validMailboxChars(recipient))
        {
            return server_error_response("sendmsg_encrypt_route", "Client sent invalidly formatted recipient name in request body. ALL recipients must be valid.", "400");
        }

        // Call fetch-cert to get the current recipient's cert
        std::vector<std::string> fetch_cert_args {recipient};
        if(call_server_program("fetch-cert", fetch_cert_args) == 0)
        {
            // Get the cert from tmp file if signalled 0
            std::string cert;
            std::ifstream infile(TMP_CERT_FILE);
            infile >> cert;
            infile.close();

            if( remove( TMP_CERT_FILE.c_str() ) != 0 )
            {
                return server_error_response("sendmsg_encrypt_route", "Error deleting tmp file on server end.", "500");
            }

            // APPEND EACH CERT TO REQUEST BODY
            response.body += cert + "\n";
        }
        else
        {
            return server_error_response("sendmsg_encrypt_route", "Encryption certificate could not be fetched for user: " + recipient, "500");
        }
    }

    response.command_line = HTTP_VERSION + " 200 OK";
    response.status_code = "200";
    response.content_length = response.body.size();
    return response;
}

HTTPresponse sendmsg_message_route(int content_length, std::string request_body, const std::string username, const std::string encoded_client_cert)
{
    // Perform the final validation - does the certificate match the one on file?
    HTTPresponse response = validate_client_certificate("sendmsg_message_route", username, encoded_client_cert);
    if(response.error)
    {
        return response;
    }

    // Make sure the content length is as expected
    if(content_length != request_body.size())
    {
        return server_error_response("sendmsg_message_route", "Request body and content-length mismatch", "400");
    }

    // Split body of request into vector of {recipients, msg1, msg2, ... msg_n}
    std::vector<std::string> request_body_split = split(request_body, "\n");
    if(request_body_split.size() < 2)
    {
        return server_error_response("sendmsg_message_route", "Request body not in valid format for sendmsg_message.", "400");
    }

    // Parse out the recipients and the corresponding messages
    std::vector<std::string> recipients;
    std::vector<std::string> messages;
    std::string unparsed_recipients = request_body_split[0];
    recipients = split(unparsed_recipients, ":");
    request_body_split.erase(request_body_split.begin()); // Pops off the first entry in vector
    messages = request_body_split;
    if ( recipients.size() != messages.size() )
    {
        return server_error_response("sendmsg_message_route", "Number of recipients does not match number of messages.", "400");
    }

    // Deliver to recipients and keep track of failures
    std::vector<std::string> failed_recipients;
    for ( int i = 0; i < recipients.size(); i++ )
    {
        std::vector<std::string> mail_in_args {recipients[i], username, messages[i]};

        if(call_server_program("mail-in", mail_in_args) != 0)
        {
            std::cerr << "Message could not be successfully delivered to " + recipients[i] << " mail-in failed.\n";
            failed_recipients.push_back(recipients[i]);
            return server_error_response("mail-in", "Message could not be successfully delivered on server end.", "500");
        }
    }

    // If any failed, send an error response instead
    if(!failed_recipients.empty())
    {
        std::string delivery_fail_message = "Message could not be successfully delivered to: ";
        for (std::string recipient : failed_recipients)
        {
            delivery_fail_message += recipient + " ";
        }
        delivery_fail_message += ". All other messages delivered.\n";
        return server_error_response("mail-in", delivery_fail_message, "500");
    }

    response.command_line = HTTP_VERSION + " 200 OK";
    response.status_code = "200"; // No body because no data is being sent
    response.content_length = 0;
    return response;
}

HTTPresponse recvmsg_route(const std::string username, const std::string encoded_client_cert)
{
    // Perform the final validation - does the certificate match the one on file?
    HTTPresponse response = validate_client_certificate("recvmsg_route", username, encoded_client_cert);
    if(response.error)
    {
        return response;
    }

    std::vector<std::string> mail_out_args {username, MAIL_OUT_SEND};
    int mail_out_return = call_server_program("mail-out", mail_out_args);
    if (mail_out_return == MAIL_OUT_EMPTY)
    {
        return server_error_response("mail-out", "No messages pending on server end.", "500");
    }
    else if (mail_out_return == MAIL_OUT_ERROR)
    {
        return server_error_response("mail-out", "Mail delivery failed because internal error. Please try again.", "500");
    }
    else
    {
        // mail-out exited with MAIL_OUT_MSG_FOUND, so we can read the msg from the tmp file tmp-msg
        std::string encoded_encrypted_signed_msg;
        std::string sender;
        std::string cert;

        // Read the message from tmp file
        std::string line;
        std::string buffer;
        std::ifstream msgstream(TMP_MSG_FILE);
        while(std::getline(msgstream, line))
        {
            buffer += line + "\n";
        }
        msgstream.close();

        if( remove( TMP_MSG_FILE.c_str() ) != 0 )
        {
            return server_error_response("mail-out", "Error deleting tmp file on server end.", "500");
        }

        // Parse out the sender and the message
        std::cout << buffer << std::endl;
        std::vector<std::string> split_msg = split(buffer, "\n");
        if(split_msg.size() != 2)
        {
            return server_error_response("mail-out", "Mail found but in incorrect format. Deleted from system.", "500");
        }
        sender = split_msg[0];
        encoded_encrypted_signed_msg = split_msg[1];

        // Fetch cert (contains public key to verify signature) from the original sender
        std::vector<std::string> fetch_cert_args {sender};
        if(call_server_program("fetch-cert", fetch_cert_args) == 0)
        {
            // Fetch-cert already writes cert in base64 encoded format for you!
            std::ifstream infile(TMP_CERT_FILE);
            infile >> cert;
            if( remove( TMP_CERT_FILE.c_str() ) != 0 )
            {
                return server_error_response("fetch-cert", "Error deleting tmp file on server end.", "500");
            }
            infile.close();
        }
        else
        {
            return server_error_response("fetch-cert", "Certificate for original sender (needed for verifying) could not be fetched on server end.", "500");
        }

        response.body += cert + "\n";
        response.body += encoded_encrypted_signed_msg;
    }

    response.command_line = HTTP_VERSION + " 200 OK";
    response.status_code = "200";
    response.content_length = response.body.size();
    return response;
}