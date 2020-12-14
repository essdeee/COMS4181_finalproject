getcert: getcert.o client_utils.o http_utils.o base64.o
	g++ client_utils.o getcert.o http_utils.o base64.o -o getcert -lssl -lcrypto -lcrypt -std=c++17
	
getcert.o: getcert.cpp
	g++ getcert.cpp -c -lssl -lcrypto -lcrypt -std=c++17

client_utils.o: client_utils.cpp
	g++ client_utils.cpp -c -lssl -lcrypto -lcrypt -std=c++17

http_utils.o: http_utils.cpp
	g++ http_utils.cpp -c -std=c++17

base64.o: base64.cpp
	g++ base64.cpp -c -std=c++17

.PHONY: clean
clean:
	rm *.o getcert