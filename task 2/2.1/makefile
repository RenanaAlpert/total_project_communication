CC = gcc
CFLAGS = -Wall

all:  sniffer snifferICMP snifferTCP snifferPassword

sniffer: sniffer.o
	$(CC) $(CFLAGS) sniffer.o -lpcap -o sniffer 

sniffer.o: sniffer.c
	$(CC) $(CFLAGS) -c sniffer.c -o sniffer.o

snifferPassword: snifferPassword.o
	$(CC) $(CFLAGS) snifferPassword.o -lpcap -o snifferPassword

snifferTCP: snifferTCP.o
	$(CC) $(CFLAGS) snifferTCP.o -lpcap -o snifferTCP

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
	rm *.o sniffer snifferTCP snifferICMP snifferPassword

