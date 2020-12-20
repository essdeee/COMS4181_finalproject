#create web server directories
mkdir server/server_cert server/server_cert/private \
	server/server_cert/certs

#setup web server folder permissions
chmod 700 server/server_cert/private

#create web server key pair
openssl genrsa -aes256 -passout pass:web_serv_pass \
	 -out server/server_cert/private/web_server.key.pem 2048

#set permissions on web server private key
chmod 400 server/server_cert/private/web_server.key.pem

#create web server certificate signing request
openssl req -config server/ca/openssl.cnf -verbose \
      -key server/server_cert/private/web_server.key.pem \
      -new -sha256 -out server/server_cert/certs/web_server.csr \
      -passin pass:web_serv_pass -subj \
      '/CN=Web Server Cert Test/C=US/ST=NY/L=New York City/O=Columbia University/OU=fwh2110-sd3013'

#sign the certificate signing request with the root ca
cd server/ca
openssl ca -config openssl.cnf -extensions server_cert \
      -passin pass:pass \
      -days 365 -notext -md sha256 \
      -in ./../server_cert/certs/web_server.csr \
      -out ./../server_cert/certs/web_server.cert.pem
chmod 444 server/server_cert/certs/web_server.cert.pem
cd ./../../

# Verify the intermediate certificate
openssl x509 -noout -text \
      -in server/server_cert/certs/web_server.cert.pem
openssl verify -CAfile server/ca/certs/ca.cert.pem \
      server/server_cert/certs/web_server.cert.pem