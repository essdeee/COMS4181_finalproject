all: getcert changepw sendmsg recvmsg
.PHONY: all

getcert: getcert.o client_utils.o http_utils.o base64.o request_sender.o
	g++ client_utils.o getcert.o http_utils.o base64.o -o getcert -lssl -lcrypto -lcrypt -std=c++17
	
getcert.o: getcert.cpp request_sender.o
	g++ getcert.cpp -c -lssl -lcrypto -lcrypt -std=c++17

changepw: changepw.o client_utils.o http_utils.o base64.o request_sender.o
	g++ client_utils.o changepw.o http_utils.o base64.o -o changepw -lssl -lcrypto -lcrypt -std=c++17

changepw.o: changepw.cpp request_sender.o
	g++ changepw.cpp -c -lssl -lcrypto -lcrypt -std=c++17

sendmsg: sendmsg.o client_utils.o http_utils.o base64.o request_sender.o
	g++ sendmsg.o client_utils.o http_utils.o base64.o -o sendmsg -lssl -lcrypto -lcrypt -std=c++17

sendmsg.o: sendmsg.cpp request_sender.o
	g++ sendmsg.cpp -c -lssl -lcrypto -lcrypt -std=c++17

recvmsg: recvmsg.o client_utils.o http_utils.o base64.o request_sender.o
	g++ recvmsg.o client_utils.o http_utils.o base64.o -o recvmsg -lssl -lcrypto -lcrypt -std=c++17

recvmsg.o: recvmsg.cpp request_sender.o
	g++ recvmsg.cpp -c -lssl -lcrypto -lcrypt -std=c++17

client_utils.o: client_utils.cpp
	g++ client_utils.cpp -c -lssl -lcrypto -lcrypt -std=c++17

http_utils.o: http_utils.cpp
	g++ http_utils.cpp -c -std=c++17

base64.o: base64.cpp
	g++ base64.cpp -c -std=c++17

request_sender.o: request_sender.cpp
	g++ request_sender.cpp -c -lssl -lcrypto -lcrypt -std=c++17

.PHONY: clean
clean:
	rm *.o getcert changepw sendmsg recvmsg

