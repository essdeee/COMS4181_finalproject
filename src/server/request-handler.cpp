#include <memory>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <iostream>
#include "server_utils.h"
#include "route_utils.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace my {

template<class T> struct DeleterOf;
template<> struct DeleterOf<BIO> { void operator()(BIO *p) const { BIO_free_all(p); } };
template<> struct DeleterOf<BIO_METHOD> { void operator()(BIO_METHOD *p) const { BIO_meth_free(p); } };
template<> struct DeleterOf<SSL_CTX> { void operator()(SSL_CTX *p) const { SSL_CTX_free(p); } };

template<class OpenSSLType>
using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

my::UniquePtr<BIO> operator|(my::UniquePtr<BIO> lower, my::UniquePtr<BIO> upper)
{
    BIO_push(upper.get(), lower.release());
    return upper;
}

class StringBIO {
    std::string str_;
    my::UniquePtr<BIO_METHOD> methods_;
    my::UniquePtr<BIO> bio_;
public:
    StringBIO(StringBIO&&) = delete;
    StringBIO& operator=(StringBIO&&) = delete;

    explicit StringBIO() {
        methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
        if (methods_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_meth_new");
        }
        BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
            std::string *str = reinterpret_cast<std::string*>(BIO_get_data(bio));
            str->append(data, len);
            return len;
        });
        bio_.reset(BIO_new(methods_.get()));
        if (bio_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_new");
        }
        BIO_set_data(bio_.get(), &str_);
        BIO_set_init(bio_.get(), 1);
    }
    BIO *bio() { return bio_.get(); }
    std::string str() && { return std::move(str_); }
};

[[noreturn]] void print_errors_and_exit(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
    exit(1);
}

[[noreturn]] void print_errors_and_throw(const char *message)
{
    my::StringBIO bio;
    ERR_print_errors(bio.bio());
    throw std::runtime_error(std::string(message) + ":" + std::move(bio).str());
}

std::string receive_some_data(BIO *bio)
{
    char buffer[1024];
    int len = BIO_read(bio, buffer, sizeof(buffer));
    if (len < 0) {
        my::print_errors_and_throw("Error in BIO_read");
    } else if (len > 0) {
        return std::string(buffer, len);
    } else if (BIO_should_retry(bio)) {
        return receive_some_data(bio);
    } else {
        my::print_errors_and_throw("Empty BIO_read");
    }
}

std::vector<std::string> split_headers(const std::string& text)
{
    std::vector<std::string> lines;
    const char *start = text.c_str();
    while (const char *end = strstr(start, "\r\n")) {
        lines.push_back(std::string(start, end));
        start = end + 2;
    }
    return lines;
}

std::string receive_http_message(BIO *bio)
{
    std::string headers = my::receive_some_data(bio);
    char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
    while (end_of_headers == nullptr) {
        headers += my::receive_some_data(bio);
        end_of_headers = strstr(&headers[0], "\r\n\r\n");
    }
    std::string body = std::string(end_of_headers+4, &headers[headers.size()]);
    headers.resize(end_of_headers+2 - &headers[0]);
    size_t content_length = 0;
    for (const std::string& line : my::split_headers(headers)) {
        if (const char *colon = strchr(line.c_str(), ':')) {
            auto header_name = std::string(&line[0], colon);
            if (convert_to_lower(header_name) == "content-length") {
                content_length = std::stoul(colon+1);
            }
        }
    }

    while (body.size() < content_length) {
        body += my::receive_some_data(bio);
    }
    return headers + "\r\n" + body;
}

void send_http_response(BIO *bio, const HTTPresponse http_response)
{
    std::string response = http_response.command_line + "\r\n";
    if ( !http_response.body.empty() )
    {
        response += "Content-Length: " + std::to_string(http_response.body.size()) + "\r\n";
    }
    response += "\r\n";

    BIO_write(bio, response.data(), response.size());
    if ( !http_response.body.empty() )
    {
        BIO_write(bio, http_response.body.data(), http_response.body.size());
    }
    BIO_flush(bio);
}

HTTPresponse verify_the_certificate(SSL *ssl)
{
    HTTPresponse http_response;
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK) {
        const char *message = X509_verify_cert_error_string(err);
        fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);

        http_response.content_length = 0;
        http_response.error = 1;
        http_response.status_code = "400";
        http_response.command_line = HTTP_VERSION + " 400 recvmsg/sendmsg certificate verification error.";
        return http_response;
    }
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr) {
        fprintf(stderr, "No certificate was presented by the client's recvmsg/sendmsg request.\n");
        
        http_response.content_length = 0;
        http_response.error = 1;
        http_response.status_code = "400";
        http_response.command_line = HTTP_VERSION + " 400 recvmsg/sendmsg MUST be client-authenticated."; 
        return http_response;
    }

    // Save the cert as an encoded base64 cert string to authenticate later (when running the route)
    uint8_t *crt_bytes = NULL;
    size_t crt_size = 0;
    crt_to_pem(cert, &crt_bytes, &crt_size);
    std::string client_cert_str = base64_encode(crt_bytes, crt_size);

    // Extract the common name from the cert
    X509_NAME *subject_name_obj = X509_get_subject_name(cert);
    if (subject_name_obj == nullptr)
    {
        fprintf(stderr, "No subject name was presented by the client's certificate.\n");
        
        http_response.content_length = 0;
        http_response.error = 1;
        http_response.status_code = "400";
        http_response.command_line = HTTP_VERSION + " 400 recvmsg/sendmsg cert must have subject name."; 
        return http_response;
    }

    // Get the common name from the cert and place it into successful http response object
    char *subject_name;
    subject_name = X509_NAME_oneline(subject_name_obj, 0, 0);
    std::string subject_line = subject_name;
    OPENSSL_free(subject_name);
    X509_free(cert);

    // Parse out the common name from the subject line
    std::string username;
    std::vector<std::string> split_subject_name = split(subject_line, "/");
    bool found_common_name = false;
    for(std::string field : split_subject_name)
    {
        std::size_t found = field.find_first_of("CN=");
        if(found != std::string::npos)
        {
            username = field.substr(found + 3);
            found_common_name = true;
        }
    }
    
    if(!found_common_name)
    {
        fprintf(stderr, "No Common Name was presented by the client's certificate.\n");
        
        http_response.content_length = 0;
        http_response.error = 1;
        http_response.status_code = "400";
        http_response.command_line = HTTP_VERSION + " 400 recvmsg/sendmsg cert must have Common Name."; 
        return http_response;
    }

    http_response.error = 0;
    http_response.body = client_cert_str;
    http_response.command_line = username;
    return http_response;
}

SSL *get_ssl(BIO *bio)
{
    SSL *ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl == nullptr) {
        my::print_errors_and_exit("Error in BIO_get_ssl");
    }
    return ssl;
}

my::UniquePtr<BIO> accept_new_tcp_connection(BIO *accept_bio)
{
    if (BIO_do_accept(accept_bio) <= 0) {
        return nullptr;
    }
    return my::UniquePtr<BIO>(BIO_pop(accept_bio));
}

} // namespace my

int main()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
    auto client_auth_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
#endif

    // Load the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx.get(), SERVER_CERT.c_str(), SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), SERVER_PRIVATE_KEY.c_str(), SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server private key");
    }

    // Client-authenticated TLS options
    STACK_OF(X509_NAME) *list;
    list = SSL_load_client_CA_file(CA_CERT_PATH.c_str());
    if(list == NULL)
    {
        my::print_errors_and_exit("Error loading CA for client certificates.");
    }
    SSL_CTX_set_client_CA_list(ctx.get(), list);
    SSL_CTX_load_verify_locations(ctx.get(), CA_CERT_PATH.c_str(), NULL); // Was the chain file
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, NULL);

    // Bind to port
    auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept(DEFAULT_PORT.c_str())); // 443 is reserved for root
    if (BIO_do_accept(accept_bio.get()) <= 0) {
        my::print_errors_and_exit(("Error in BIO_do_accept binding to port " + DEFAULT_PORT).c_str());
    }

    static auto shutdown_the_socket = [fd = BIO_get_fd(accept_bio.get(), nullptr)]() {
        close(fd);
    };
    signal(SIGINT, [](int) { shutdown_the_socket(); });

    // Listen for new connections
    while (auto bio = my::accept_new_tcp_connection(accept_bio.get())) 
    {
        bio = std::move(bio)
            | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0))
            ;
        try 
        {   
            std::string request = my::receive_http_message(bio.get());
            HTTPrequest parsed_request = parse_request(request);

            // Show request header
            printf("Got request, with header: \n");
            std::cout << parsed_request.command_line << std::endl;

            // client-auth TLS logic for recvmsg and sendmsg
            std::string username;
            std::string encoded_client_cert;
            if((parsed_request.route == RECVMSG_ROUTE || 
                parsed_request.route == SENDMSG_ENCRYPT_ROUTE || 
                parsed_request.route == SENDMSG_MESSAGE_ROUTE))
            {    
                HTTPresponse client_auth_response = my::verify_the_certificate(my::get_ssl(bio.get()));
                if(client_auth_response.error)
                {
                    my::send_http_response(bio.get(), client_auth_response);
                    continue;
                }
                else
                {
                    username = client_auth_response.command_line;
                    encoded_client_cert = client_auth_response.body;
                    std::cout << "Client claims to authenticate as: " << username << std::endl;
                }
            }

            // Do the route function
            HTTPresponse http_response = route(request, username, encoded_client_cert);
            my::send_http_response(bio.get(), http_response);
        } catch (const std::exception& ex) {
            printf("Worker exited with caught exception:\n%s\n", ex.what());
            std::cerr << "Did not respond back to client.\n";
        }
    }
    printf("\nClean exit!\n");
}