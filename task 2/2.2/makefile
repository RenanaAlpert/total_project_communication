CC = gcc
CFLAGS = -Wall

all: spoof

spoof: spoofing.o
	$(CC) $(CFLAGS) spoofing.o -lpcap -o spoof

spoofingA.o: spoofing.c
	$(CC) $(CFLAGS) -c spoofing.c -o spoofing.o

.PHONY: clean all

clean:
	rm *.o spoof