request-handler: request-handler.o route_utils.o server_utils.o
	g++ request-handler.o route_utils.o server_utils.o -o request-handler -lssl -lcrypto -std=c++17

request-handler.o: request-handler.cpp
	g++ request-handler.cpp -c -lssl -lcrypto -std=c++17

route_utils.o: route_utils.cpp
	g++ route_utils.cpp -c -std=c++17

server_utils.o: server_utils.cpp
	g++ server_utils.cpp -c -std=c++17

.PHONY: clean
clean:
	rm *.o request-handler