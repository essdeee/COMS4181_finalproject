#!/bin/bash

#Create server folder (represents everything on the server)
#and root ca directories
mkdir certs certs/server certs/server/ca certs/server/ca/certs certs/server/ca/clr \
	certs/server/ca/newcerts certs/server/ca/private

#setup ca folder permissions and needed files
chmod 700 certs/server/ca/private
touch certs/server/ca/index.txt
echo 1000 > certs/server/ca/serial

#create root ca key pair
openssl genrsa -aes256 -passout pass:toor -out certs/server/ca/private/ca.key.pem 4096

#set permissions on root ca private key
chmod 400 certs/server/ca/private/ca.key.pem

#create root ca certificate
openssl req -config scripts/openssl.cnf -verbose \
      -key certs/server/ca/private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out certs/server/ca/certs/cacert.pem \
      -passin pass:toor -subj \
      '/CN=Root CA/C=US/ST=NY/L=New York City/O=Columbia University/OU=fwh2110-sd3013'

#set permissions on root ca certificate 
chmod 444 certs/server/ca/certs/cacert.pem


