CC = gcc
CFLAGS = -Wall

all: myPing snifferICMP snifferTCP snifferPassword

snifferPassword: snifferPassword.o
	$(CC) $(CFLAGS) snifferPassword.o -lpcap -o snifferPassword

snifferTCP: snifferTCP.o
	$(CC) $(CFLAGS) snifferTCP.o -lpcap -o snifferTCP

myPing: myPing.o
	$(CC) $(CFLAGS) myPing.o -o myPing

myPing.o: myPing.c
	$(CC) $(CFLAGS) -c myPing.c -o myPing.o

snifferICMP: snifferICMP.o
	$(CC) $(CFLAGS) snifferICMP.o -lpcap -o snifferICMP

snifferICMP.o: snifferICMP.c
	$(CC) $(CFLAGS) -c snifferICMP.c -o snifferICMP.o

snifferTCP.o: snifferTCP.c
	$(CC) $(CFLAGS) -c snifferTCP.c -o snifferTCP.o

snifferPassword.o: snifferPassword.c
	$(CC) $(CFLAGS) -c snifferPassword.c -o snifferPassword.o

.PHONY: clean all

clean:
	rm *.o myPing sniffer snifferTCP
