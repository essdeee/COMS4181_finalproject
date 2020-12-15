all: request-handler cert-gen verify-pass
.PHONY: all

request-handler: request-handler.o route_utils.o server_utils.o
	g++ request-handler.o route_utils.o server_utils.o -o request-handler -lssl -lcrypto -lcrypt -std=c++17

request-handler.o: request-handler.cpp
	g++ request-handler.cpp -c -lssl -lcrypto -std=c++17

route_utils.o: route_utils.cpp
	g++ route_utils.cpp -c -std=c++17

cert-gen: cert-gen.o server_utils.o route_utils.o base64.o
	g++ cert-gen.o server_utils.o route_utils.o base64.o -o cert-gen -lssl -lcrypto -lcrypt -std=c++17

cert-gen.o: cert-gen.cpp
	g++ cert-gen.cpp -c -lssl -lcrypto -std=c++17

verify-pass: verify-pass.o server_utils.o route_utils.o
	g++ verify-pass.o server_utils.o route_utils.o -lssl -lcrypto -lcrypt -o verify-pass -std=c++17

verify-pass.o: verify-pass.cpp
	g++ verify-pass.cpp -c -lcrypt -std=c++17

server_utils.o: server_utils.cpp
	g++ server_utils.cpp -c -lcrypt -std=c++17

base64.o: base64.cpp
	g++ base64.cpp -c -std=c++17

.PHONY: clean
clean:
	rm *.o request-handler cert-gen verify-pass
