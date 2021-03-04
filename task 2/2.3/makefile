CC = gcc
CFLAGS = -Wall

all: spoof

spoof: spoofingA.o
	$(CC) $(CFLAGS) spoofingA.o -lpcap -o spoof

spoofingA.o: spoofingA.c
	$(CC) $(CFLAGS) -c spoofingA.c -o spoofingA.o

.PHONY: clean all

clean:
	rm *.o spoof