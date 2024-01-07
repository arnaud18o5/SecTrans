CC = gcc
CFLAGS = -I./include
LDFLAGS = -L./lib
LDLIBS = -lserver -lclient -lssl -lcrypto -lm

all: server client

base_encoding.o: include/base_encoding.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o base_encoding.o $< $(LDLIBS)

hash.o: include/hash.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o hash.o $< $(LDLIBS)

server: src/main_server.c hash.o base_encoding.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o server $^ $(LDLIBS)

client: src/main_client.c hash.o base_encoding.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o client $^ $(LDLIBS)

run_server: server
	@echo "Running server..."
	@LD_LIBRARY_PATH=./lib ./server

run_client: client
	@echo "Running client..."
	@LD_LIBRARY_PATH=./lib 

clean:
	rm -f server client

.PHONY: all run_server run_client clean
