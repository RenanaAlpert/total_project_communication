CC = gcc
CFLAGS = -Wall

<<<<<<< HEAD:task 2/makefile
all: myPing sniffer snifferICMP snifferTCP snifferPassword

sniffer: sniffer.o
	$(CC) $(CFLAGS) sniffer.o -lpcap -o sniffer 

sniffer.o: sniffer.c
	$(CC) $(CFLAGS) -c sniffer.c -o sniffer.o
=======
all: snifferICMP snifferTCP snifferPassword
>>>>>>> cb64a07e3ade3b591fcc9bc1ea02fea9fe1bfafa:task 2/2.1/makefile

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
<<<<<<< HEAD:task 2/makefile
	rm *.o myPing sniffer snifferTCP snifferICMP snifferPassword
=======
	rm *.o snifferICMP snifferTCP snifferPassword
>>>>>>> cb64a07e3ade3b591fcc9bc1ea02fea9fe1bfafa:task 2/2.1/makefile
