CC = gcc
CFLAGS = -I./include
LDFLAGS = -L./lib
LDLIBS = -lserver -lclient -lssl -lcrypto -lm

all: server client

encryption.o: include/encryption.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o encryption.o $< $(LDLIBS)

base_encoding.o: include/base_encoding.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o base_encoding.o $< $(LDLIBS)

hash.o: include/hash.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o hash.o $< $(LDLIBS)
	
signature.o: include/signature.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o signature.o $< $(LDLIBS)

user.o: include/user.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o user.o $< $(LDLIBS)

server: src/main_server.c hash.o encryption.o base_encoding.o signature.o user.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o server $^ $(LDLIBS)

client: src/main_client.c hash.o encryption.o base_encoding.o
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
