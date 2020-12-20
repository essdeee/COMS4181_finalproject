#!/bin/bash

#create sandbox dirs
cd system/
mkdir -p server/handler/{bin,lib/x86_64-linux-gnu,lib64,server_cert}
cd ..

#copy in sandbox programs and files
cp ./request-handler system/server/handler/bin/request-handler
cp certs/server/web_server/certs/server-cert.pem system/server/handler/server_cert/server-cert.pem
cp certs/server/web_server/private/web_server.key.pem system/server/handler/server_cert/server-key.pem

#copy in program dependencies
cp $HOME/../../lib/x86_64-linux-gnu/libssl.so.1.1 system/server/handler/lib/x86_64-linux-gnu/libssl.so.1.1
cp $HOME/../../lib/x86_64-linux-gnu/libcrypto.so.1.1 system/server/handler/lib/x86_64-linux-gnu/libcrypto.so.1.1
cp $HOME/../../lib/x86_64-linux-gnu/libcrypt.so.1 system/server/handler/lib/x86_64-linux-gnu/libcrypt.so.1
cp $HOME/../../lib/x86_64-linux-gnu/libstdc++.so.6 system/server/handler/lib/x86_64-linux-gnu/libstdc++.so.6
cp $HOME/../../lib/x86_64-linux-gnu/libgcc_s.so.1 system/server/handler/lib/x86_64-linux-gnu/libgcc_s.so.1
cp $HOME/../../lib/x86_64-linux-gnu/libc.so.6 system/server/handler/lib/x86_64-linux-gnu/libc.so.6
cp $HOME/../../lib/x86_64-linux-gnu/libpthread.so.0 system/server/handler/lib/x86_64-linux-gnu/libpthread.so.0
cp $HOME/../../lib/x86_64-linux-gnu/libdl.so.2 system/server/handler/lib/x86_64-linux-gnu/libdl.so.2
cp $HOME/../../lib/x86_64-linux-gnu/libm.so.6  system/server/handler/lib/x86_64-linux-gnu/libm.so.6
cp $HOME/../../lib64/ld-linux-x86-64.so.2 system/server/handler/lib64/ld-linux-x86-64.so.2

#set owners and permissions
chown root system/server/handler/bin/request-handler
chmod 101 system/server/handler/bin/request-handler
chmod u+s system/server/handler/bin/request-handler

chown root system/server/handler/bin
chmod 505 system/server/handler/bin

chown root system/server/handler/server_cert/server-cert.pem
chmod 400 system/server/handler/server_cert/server-cert.pem

chown root system/server/handler/server_cert/server-key.pem
chmod 400 system/server/handler/server_cert/server-key.pem

chown root system/server/handler/server_cert
chmod 500 system/server/handler/server_cert
