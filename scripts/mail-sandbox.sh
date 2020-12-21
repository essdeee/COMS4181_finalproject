#!/bin/bash

#create sandbox dirs
cd system/server/handler/
mkdir -p mail/{bin,tmp,lib/x86_64-linux-gnu,lib64}
cd mail
mkdir -p mail/{addleness,analects,annalistic,anthropomorphologically,blepharosphincterectomy,corector,durwaun,dysphasia,encampment,endoscopic,exilic,forfend,gorbellied,gushiness,muermo,neckar,outmate,outroll,overrich,philosophicotheological,pockwood,polypose,refluxed,reinsure,repine,scerne,starshine,unauthoritativeness,unminced,unrosed,untranquil,urushinic,vegetocarbonaceous,wamara,whaledom}
cd ../../../../


#make dir for each user in mail/mail


#copy in sandbox programs
cp ./mail-in system/server/handler/mail/bin/mail-in
cp ./mail-out system/server/handler/mail/bin/mail-out

#copy in program dependencies
cp $HOME/../../lib/x86_64-linux-gnu/libstdc++.so.6 system/server/handler/mail/lib/x86_64-linux-gnu/libstdc++.so.6
cp $HOME/../../lib/x86_64-linux-gnu/libc.so.6 system/server/handler/mail/lib/x86_64-linux-gnu/libc.so.6
cp $HOME/../../lib/x86_64-linux-gnu/libm.so.6 system/server/handler/mail/lib/x86_64-linux-gnu/libm.so.6
cp $HOME/../../lib64/ld-linux-x86-64.so.2 system/server/handler/mail/lib64/ld-linux-x86-64.so.2
cp $HOME/../../lib/x86_64-linux-gnu/libgcc_s.so.1 system/server/handler/mail/lib/x86_64-linux-gnu/libgcc_s.so.1
cp $HOME/../../lib/x86_64-linux-gnu/libcrypt.so.1 system/server/handler/mail/lib/x86_64-linux-gnu/libcrypt.so.1
cp $HOME/../../lib/x86_64-linux-gnu/libcrypto.so.1.1 system/server/handler/mail/lib/x86_64-linux-gnu/libcrypto.so.1.1
cp $HOME/../../lib/x86_64-linux-gnu/libdl.so.2 system/server/handler/mail/lib/x86_64-linux-gnu/libdl.so.2
cp $HOME/../../lib/x86_64-linux-gnu/libpthread.so.0 system/server/handler/mail/lib/x86_64-linux-gnu/libpthread.so.0

#create users
if ! id mail-in-usr &>/dev/null; then
    useradd -s /usr/bin/false -m -d /home/mailbox/mail-in-usr mail-in-usr
fi

if ! id mail-out-usr &>/dev/null; then
    useradd -s /usr/bin/false -m -d /home/mailbox/mail-out-usr mail-out-usr
fi

#set owners and permissions
chown mail-in-usr system/server/handler/mail/bin/mail-in
chmod 000 system/server/handler/mail/bin/mail-in
chmod u+s system/server/handler/mail/bin/mail-in
setfacl -m "u:root:--x" system/server/handler/mail/bin/mail-in

chown mail-out-usr system/server/handler/mail/bin/mail-out
chmod 000 system/server/handler/mail/bin/mail-out
chmod u+s system/server/handler/mail/bin/mail-out
setfacl -m "u:root:--x" system/server/handler/mail/bin/mail-out

chown root system/server/handler/mail/bin
chmod 500 system/server/handler/mail/bin

chown mail-in-usr system/server/handler/mail/tmp
chmod 700 system/server/handler/mail/tmp
setfacl -m "u:root:r-x" system/server/handler/mail/tmp
setfacl -m "u:mail-out-usr:rwx" system/server/handler/mail/tmp

chown mail-in-usr system/server/handler/mail/mail
chmod 700 system/server/handler/mail/mail
setfacl -m "u:mail-out-usr:rwx" system/server/handler/mail/mail

for value in {addleness,analects,annalistic,anthropomorphologically,blepharosphincterectomy,corector,durwaun,dysphasia,encampment,endoscopic,exilic,forfend,gorbellied,gushiness,muermo,neckar,outmate,outroll,overrich,philosophicotheological,pockwood,polypose,refluxed,reinsure,repine,scerne,starshine,unauthoritativeness,unminced,unrosed,untranquil,urushinic,vegetocarbonaceous,wamara,whaledom}
do
    chown mail-in-usr system/server/handler/mail/mail/$value
    chmod 700 system/server/handler/mail/mail/$value
    setfacl -m "u:mail-out-usr:rwx" system/server/handler/mail/mail/$value
done