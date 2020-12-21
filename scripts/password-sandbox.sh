#!/bin/bash

#create sandbox dirs
cd system/server/handler/
mkdir -p password/{bin,lib/x86_64-linux-gnu,lib64,pass}
cd ../../../


#copy in sandbox programs and files
cp ./verify-pass system/server/handler/password/bin/verify-pass
cp ./update-pass system/server/handler/password/bin/update-pass
cp ./shadow system/server/handler/password/pass/shadow

#copy in program dependencies
cp $HOME/../../lib/x86_64-linux-gnu/libstdc++.so.6 system/server/handler/password/lib/x86_64-linux-gnu/libstdc++.so.6
cp $HOME/../../lib/x86_64-linux-gnu/libc.so.6 system/server/handler/password/lib/x86_64-linux-gnu/libc.so.6
cp $HOME/../../lib/x86_64-linux-gnu/libm.so.6 system/server/handler/password/lib/x86_64-linux-gnu/libm.so.6
cp $HOME/../../lib64/ld-linux-x86-64.so.2 system/server/handler/password/lib64/ld-linux-x86-64.so.2
cp $HOME/../../lib/x86_64-linux-gnu/libgcc_s.so.1 system/server/handler/password/lib/x86_64-linux-gnu/libgcc_s.so.1
cp $HOME/../../lib/x86_64-linux-gnu/libcrypt.so.1 system/server/handler/password/lib/x86_64-linux-gnu/libcrypt.so.1

#create users
if ! id verify-pass-usr &>/dev/null; then
    useradd -s /usr/bin/false -m -d /home/mailbox/verify-pass-usr verify-pass-usr
fi

if ! id update-pass-usr &>/dev/null; then
    useradd -s /usr/bin/false -m -d /home/mailbox/update-pass-usr update-pass-usr
fi

#set owners and permissions
chown verify-pass-usr system/server/handler/password/bin/verify-pass
chmod 000 system/server/handler/password/bin/verify-pass
chmod u+s system/server/handler/password/bin/verify-pass
setfacl -m "u:root:--x" system/server/handler/password/bin/verify-pass

chown update-pass-usr system/server/handler/password/bin/update-pass
chmod 000 system/server/handler/password/bin/update-pass
chmod u+s system/server/handler/password/bin/update-pass
setfacl -m "u:root:--x" system/server/handler/password/bin/update-pass

chown root system/server/handler/password/bin
chmod 500 system/server/handler/password/bin

chown update-pass-usr system/server/handler/password/pass
chmod 500 system/server/handler/password/pass
setfacl -m "u:verify-pass-usr:r-x" system/server/handler/password/pass

chown update-pass-usr system/server/handler/password/pass/shadow
chmod 600 system/server/handler/password/pass/shadow
setfacl -m "u:verify-pass-usr:r--" system/server/handler/password/pass/shadow