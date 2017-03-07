all:main

main: edge_server.c
	gcc -Wall -g -o main edge_server.c -lssl -lcrypto -levent_openssl -levent -pthread

.PHONY:clean
clean:
	rm main *.o
