CC = gcc
CFLAGS = -I./include
LDFLAGS = -L./lib
LDLIBS = -lserver -lclient -lssl -lcrypto -lm

all: server client

base_encoding.o: include/base_encoding.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o base_encoding.o $< $(LDLIBS)

hash.o: include/hash.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o hash.o $< $(LDLIBS)

signature.o: include/signature.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o signature.o $< $(LDLIBS)

user.o: include/user.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o user.o $< $(LDLIBS)

rsa.o: include/rsa.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o rsa.o $< $(LDLIBS)

file_transfer.o: include/file_transfer.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o file_transfer.o $< $(LDLIBS)

server: src/main_server.c hash.o base_encoding.o signature.o user.o file_transfer.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o server $^ $(LDLIBS)

client: src/main_client.c hash.o base_encoding.o rsa.o signature.o file_transfer.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o sectrans $^ $(LDLIBS)

run_server: server
	@echo "Running server..."
	@LD_LIBRARY_PATH=./lib ./server

clean:
	rm -f server sectrans *.o

.PHONY: all run_server client clean
