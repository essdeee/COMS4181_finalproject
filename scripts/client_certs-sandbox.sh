#!/bin/bash

#create sandbox dirs
cd system/server/handler/
mkdir -p client_certs/{bin,tmp,lib/x86_64-linux-gnu,lib64,certs,ca-cert}
cd ../../../


#copy in sandbox programs and files
cp ./cert-gen system/server/handler/client_certs/bin/cert-gen
cp ./fetch-cert system/server/handler/client_certs/bin/fetch-cert
cp certs/server/ca/certs/cacert.pem system/server/handler/client_certs/ca-cert/cacert.pem
cp certs/server/ca/private/ca.key.pem system/server/handler/client_certs/ca-cert/ca.key.pem

#copy in program dependencies
cp $HOME/../../lib/x86_64-linux-gnu/libstdc++.so.6 system/server/handler/client_certs/lib/x86_64-linux-gnu/libstdc++.so.6
cp $HOME/../../lib/x86_64-linux-gnu/libc.so.6 system/server/handler/client_certs/lib/x86_64-linux-gnu/libc.so.6
cp $HOME/../../lib/x86_64-linux-gnu/libm.so.6 system/server/handler/client_certs/lib/x86_64-linux-gnu/libm.so.6
cp $HOME/../../lib64/ld-linux-x86-64.so.2 system/server/handler/client_certs/lib64/ld-linux-x86-64.so.2
cp $HOME/../../lib/x86_64-linux-gnu/libgcc_s.so.1 system/server/handler/client_certs/lib/x86_64-linux-gnu/libgcc_s.so.1
cp $HOME/../../lib/x86_64-linux-gnu/libcrypt.so.1 system/server/handler/client_certs/lib/x86_64-linux-gnu/libcrypt.so.1
cp $HOME/../../lib/x86_64-linux-gnu/libcrypto.so.1.1 system/server/handler/client_certs/lib/x86_64-linux-gnu/libcrypto.so.1.1
cp $HOME/../../lib/x86_64-linux-gnu/libdl.so.2 system/server/handler/client_certs/lib/x86_64-linux-gnu/libdl.so.2
cp $HOME/../../lib/x86_64-linux-gnu/libpthread.so.0 system/server/handler/client_certs/lib/x86_64-linux-gnu/libpthread.so.0



#create users
if ! id cert-gen-usr &>/dev/null; then
    useradd -s /usr/bin/false -m -d /home/mailbox/cert-gen-usr cert-gen-usr
fi

if ! id fetch-cert-usr &>/dev/null; then
    useradd -s /usr/bin/false -m -d /home/mailbox/fetch-cert-usr fetch-cert-usr
fi

#set owners and permissions
chown cert-gen-usr system/server/handler/client_certs/bin/cert-gen
chmod 000 system/server/handler/client_certs/bin/cert-gen
chmod u+s system/server/handler/client_certs/bin/cert-gen
setfacl -m "u:root:--x" system/server/handler/client_certs/bin/cert-gen

chown fetch-cert-usr system/server/handler/client_certs/bin/fetch-cert
chmod 000 system/server/handler/client_certs/bin/fetch-cert
chmod u+s system/server/handler/client_certs/bin/fetch-cert
setfacl -m "u:root:--x" system/server/handler/client_certs/bin/fetch-cert

chown root system/server/handler/client_certs/bin
chmod 500 system/server/handler/client_certs/bin

chown cert-gen-usr system/server/handler/client_certs/certs
chmod 700 system/server/handler/client_certs/certs
setfacl -m "u:fetch-cert-usr:r-x" system/server/handler/client_certs/certs

chown cert-gen-usr system/server/handler/client_certs/ca-cert
chmod 500 system/server/handler/client_certs/ca-cert

