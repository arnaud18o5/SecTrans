CC = gcc
CFLAGS = -I./include
LDFLAGS = -L./lib
LDLIBS = -lserver -lclient -lssl -lcrypto -lm

all: server client

encryption.o: include/encryption.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o encryption.o $< $(LDLIBS)

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
