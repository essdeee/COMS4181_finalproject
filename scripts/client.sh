#!/bin/bash

#create sandbox dirs
cd system/
mkdir -p client/{bin,tmp,keypair}
cd ../


#copy in sandbox programs and files
cp ./getcert system/client/bin/getcert
cp ./changepw system/client/bin/changepw
cp ./sendmsg system/client/bin/sendmsg
cp ./recvmsg system/client/bin/recvmsg
cp certs/server/ca/certs/cacert.pem system/client/keypair/cacert.pem

#create users
if ! id get-cert-usr &>/dev/null; then
    useradd -s /usr/bin/false -m -d /home/mailbox/get-cert-usr get-cert-usr
fi

if ! id auth-cert-usr &>/dev/null; then
    useradd -s /usr/bin/false -m -d /home/mailbox/auth-cert-usr auth-cert-usr
fi

#set owners and permissions
chmod 005 system/client/bin

chown get-cert-usr system/client/bin/getcert
chmod 101 system/client/bin/getcert
chmod u+s system/client/bin/getcert

chown get-cert-usr system/client/bin/changepw
chmod 101 system/client/bin/changepw
chmod u+s system/client/bin/changepw

chown auth-cert-usr system/client/bin/sendmsg
chmod 101 system/client/bin/sendmsg
chmod u+s system/client/bin/sendmsg

chown auth-cert-usr system/client/bin/recvmsg
chmod 101 system/client/bin/recvmsg
chmod u+s system/client/bin/recvmsg

chown get-cert-usr system/client/keypair
chmod 700 system/client/keypair
setfacl -m "u:auth-cert-usr:r-x" system/client/keypair
