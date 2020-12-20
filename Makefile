all: request-handler cert-gen fetch-cert verify-pass update-pass mail-out mail-in getcert changepw sendmsg recvmsg
.PHONY: all

SHELL := /bin/bash

.PHONY: install
install: request-handler cert-gen fetch-cert verify-pass update-pass mail-out mail-in getcert changepw sendmsg recvmsg
	make all
	sudo scripts/install-system.sh

request-handler: request-handler.o route_utils.o server_utils.o
	g++ request-handler.o route_utils.o server_utils.o -o request-handler -lssl -lcrypto -lcrypt -std=c++17

request-handler.o: src/server/request-handler.cpp
	g++ src/server/request-handler.cpp -c -lssl -lcrypto -std=c++17

route_utils.o: src/server/route_utils.cpp
	g++ src/server/route_utils.cpp -c -std=c++17

cert-gen: cert-gen.o server_utils.o route_utils.o
	g++ cert-gen.o server_utils.o route_utils.o -o cert-gen -lssl -lcrypto -lcrypt -std=c++17

cert-gen.o: src/server/cert-gen.cpp
	g++ src/server/cert-gen.cpp -c -lssl -lcrypto -std=c++17

fetch-cert: fetch-cert.o server_utils.o route_utils.o
	g++ fetch-cert.o server_utils.o route_utils.o -o fetch-cert -lssl -lcrypto -lcrypt -std=c++17

fetch-cert.o: src/server/fetch-cert.cpp
	g++ src/server/fetch-cert.cpp -c -lssl -lcrypto -std=c++17

verify-pass: verify-pass.o server_utils.o route_utils.o
	g++ verify-pass.o server_utils.o route_utils.o -lssl -lcrypto -lcrypt -o verify-pass -std=c++17

verify-pass.o: src/server/verify-pass.cpp
	g++ src/server/verify-pass.cpp -c -lcrypt -std=c++17

update-pass: update-pass.o server_utils.o route_utils.o
	g++ update-pass.o server_utils.o route_utils.o -lssl -lcrypto -lcrypt -o update-pass -std=c++17

update-pass.o: src/server/update-pass.cpp
	g++ src/server/update-pass.cpp -c -lcrypt -std=c++17

mail-out: mail-out.o server_utils.o route_utils.o
	g++ mail-out.o server_utils.o route_utils.o -lssl -lcrypto -lcrypt -o mail-out -std=c++17

mail-out.o: src/server/mail-out.cpp
	g++ src/server/mail-out.cpp -c -lcrypt -std=c++17

mail-in: mail-in.o server_utils.o route_utils.o
	g++ mail-in.o server_utils.o route_utils.o -lstdc++fs -lssl -lcrypto -lcrypt -o mail-in -std=c++17

mail-in.o: src/server/mail-in.cpp
	g++ src/server/mail-in.cpp -c -lcrypt -lstdc++fs -std=c++17

server_utils.o: src/server/server_utils.cpp
	g++ src/server/server_utils.cpp -c -lcrypt -std=c++17

getcert: getcert.o client_utils.o http_utils.o request_sender.o
	g++ client_utils.o getcert.o http_utils.o -o getcert -lssl -lcrypto -lcrypt -std=c++17

getcert.o: src/client/getcert.cpp request_sender.o
	g++ src/client/getcert.cpp -c -lssl -lcrypto -lcrypt -std=c++17

changepw: changepw.o client_utils.o http_utils.o request_sender.o
	g++ client_utils.o changepw.o http_utils.o -o changepw -lssl -lcrypto -lcrypt -std=c++17

changepw.o: src/client/changepw.cpp request_sender.o
	g++ src/client/changepw.cpp -c -lssl -lcrypto -lcrypt -std=c++17

sendmsg: sendmsg.o client_utils.o http_utils.o request_sender.o
	g++ sendmsg.o client_utils.o http_utils.o -o sendmsg -lssl -lcrypto -lcrypt -std=c++17

sendmsg.o: src/client/sendmsg.cpp request_sender.o
	g++ src/client/sendmsg.cpp -c -lssl -lcrypto -lcrypt -std=c++17

recvmsg: recvmsg.o client_utils.o http_utils.o request_sender.o
	g++ recvmsg.o client_utils.o http_utils.o -o recvmsg -lssl -lcrypto -lcrypt -std=c++17

recvmsg.o: src/client/recvmsg.cpp request_sender.o
	g++ src/client/recvmsg.cpp -c -lssl -lcrypto -lcrypt -std=c++17

client_utils.o: src/client/client_utils.cpp
	g++ src/client/client_utils.cpp -c -lssl -lcrypto -lcrypt -std=c++17

http_utils.o: src/client/http_utils.cpp
	g++ src/client/http_utils.cpp -c -std=c++17

request_sender.o: src/client/request_sender.cpp
	g++ src/client/request_sender.cpp -c -lssl -lcrypto -lcrypt -std=c++17

.PHONY: clean
clean:
	rm *.o request-handler cert-gen verify-pass update-pass fetch-cert mail-out mail-in getcert changepw sendmsg recvmsg
