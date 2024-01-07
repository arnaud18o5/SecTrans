CC = gcc
CFLAGS = -I./include
LDFLAGS = -L./lib
LDLIBS = -lserver -lclient -lencryption -lssl -lcrypto -lm

all: server client

lib_encryption: src/encrypt_message.c
	$(CC) -c -fPIC $< -o lib.o
	$(CC) -shared -o libencryption.so lib.o

server: src/main_server.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o server $< $(LDLIBS)

client: src/main_client.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o client $< $(LDLIBS)

run_server: server
	@echo "Running server..."
	@LD_LIBRARY_PATH=./lib ./server

run_client: client
	@echo "Running client..."
	@LD_LIBRARY_PATH=./lib 

clean:
	rm -f server client

.PHONY: all run_server run_client clean
