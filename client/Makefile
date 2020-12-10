get-cert: get-cert.o client_utils.o http_utils.o
	g++ client_utils.o get-cert.o http_utils.o -o get-cert -lssl -lcrypto -std=c++17
	
get-cert.o: get-cert.cpp
	g++ get-cert.cpp -c -lssl -lcrypto -std=c++17

client_utils.o: client_utils.cpp
	g++ client_utils.cpp -c -lssl -lcrypto -std=c++17

http_utils.o: http_utils.cpp
	g++ http_utils.cpp -c -std=c++17

.PHONY: clean
clean:
	rm *.o get-cert