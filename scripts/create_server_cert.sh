#!/bin/bash

#create web server directories
mkdir certs/server/web_server certs/server/web_server/private \
	certs/server/web_server/certs

#setup web server folder permissions
chmod 700 certs/server/web_server/private

#create web server key pair
openssl genrsa -aes256 -passout pass:web_serv_pass \
	 -out certs/server/web_server/private/web_server.key.pem 2048

#set permissions on web server private key
chmod 400 certs/server/web_server/private/web_server.key.pem

#create web server certificate signing request
openssl req -config scripts/openssl.cnf -verbose \
      -key certs/server/web_server/private/web_server.key.pem \
      -new -sha256 -out certs/server/web_server/certs/web_server.csr \
      -passin pass:web_serv_pass -subj \
      '/CN=Web Server Cert/C=US/ST=NY/L=New York City/O=Columbia University/OU=fwh2110-sd3013'

#sign the certificate signing request with the intermediate server ca
openssl ca -config scripts/openssl.cnf \
      -in certs/server/web_server/certs/web_server.csr \
      -out certs/server/web_server/certs/server-cert.pem \
      -key toor -days 365 -batch -notext -md sha256 \
      -extfile scripts/openssl.cnf -extensions server_cert

#set permissions on the web server certificate
chmod 444 certs/server/web_server/certs/server-cert.pem
