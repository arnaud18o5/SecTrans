CC = gcc
CFLAGS = -I./include
LDFLAGS = -L./lib
LDLIBS = -lserver

all: server client

server: src/main_server.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o server $< $(LDLIBS)

client: src/main_client.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o client $< -lclient

run_server: server
	@echo "Running server..."
	@LD_LIBRARY_PATH=./lib ./server

run_client: client
	@echo "Running client..."
	@LD_LIBRARY_PATH=./lib 

clean:
	rm -f server client

.PHONY: all run_server run_client clean
