#!/bin/bash

# Take arguments for ca directory name
while getopts cdp: flag
do
    case "${flag}" in
        d) dirname=${OPTARG};;
        p) pass=${OPTARG};;
    esac
done

if [ -z "$pass" ]
then
    echo "ERROR: password field is empty."
    echo "Use -p to enter a password (output) for the root key."
    exit 1
fi

# Keep the path of the CA in subdirectory of home (takes arguments to generate new ca directories)
CA_PATH='server/ca'

# Prepare root CA directory
mkdir $CA_PATH
mkdir $CA_PATH/'certs' $CA_PATH/'crl' $CA_PATH/'newcerts' $CA_PATH/'private'
chmod 700 $CA_PATH/'private'
touch $CA_PATH/'index.txt'
echo 1000 > $CA_PATH/'serial'

# Copy over config file
cp root_openssl.cnf $CA_PATH/openssl.cnf

# Create the root key (prompts for password)
openssl genrsa -aes256 -passout pass:$pass -out $CA_PATH/private/ca.key.pem 4096 
chmod 400 $CA_PATH/private/ca.key.pem

# Create the root certificate
openssl req -config $CA_PATH/openssl.cnf \
      -passin pass:$pass \
      -key $CA_PATH/private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out $CA_PATH/certs/ca.cert.pem \
      -subj '/C=US/ST=NY/O=Columbia University/CN=Root CA/OU=fwh2110-sd3013'
chmod 444 $CA_PATH/certs/ca.cert.pem

# Verify the root certificate
openssl x509 -noout -text -in $CA_PATH/certs/ca.cert.pem