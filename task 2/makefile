CC = gcc
CFLAGS = -Wall

all: myPing sniffer snifferTCP

snifferTCP: snifferTCP.o
	$(CC) $(CFLAGS) snifferTCP.o -lpcap -o snifferTCP

myPing: myPing.o
	$(CC) $(CFLAGS) myPing.o -o myPing

myPing.o: myPing.c
	$(CC) $(CFLAGS) -c myPing.c -o myPing.o

sniffer: sniffer.o
	$(CC) $(CFLAGS) sniffer.o -lpcap -o sniffer

sniffer.o: sniffer.c
	$(CC) $(CFLAGS) -c sniffer.c -o sniffer.o

snifferTCP.o: snifferTCP.c
	$(CC) $(CFLAGS) -c snifferTCP.c -o snifferTCP.o

.PHONY: clean all

clean:
	rm *.o myPing sniffer snifferTCP
