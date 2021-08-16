CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -lpthread

all: client server server_select

client.o: client.c
	$(CC) $(CFLAGS) -c client.c

server.o: server.c
	$(CC) $(CFLAGS) -c server.c

server_select.o: server_select.c
	$(CC) $(CFLAGS) -c server_select.c

client: client.o
	$(CC) $(CFLAGS) client.o -o client $(LDFLAGS)

server: server.o
	$(CC) $(CFLAGS) server.o -o server $(LDFLAGS)

server_select: server_select.o
	$(CC) $(CFLAGS) server_select.o -o server_select $(LDFLAGS)

clean:
	rm -f *~ *.o client server server_select core *.tar *.zip *.gzip *.bzip *.gz *.txt
