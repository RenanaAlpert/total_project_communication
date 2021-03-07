CC = gcc
CFLAGS = -Wall

all: sniffAndSpoof

sniffAndSpoof: sniffAndSpoof.o
	$(CC) $(CFLAGS) sniffAndSpoof.o -lpcap -o sniffAndSpoof

sniffAndSpoof.o: sniffAndSpoof.c
	$(CC) $(CFLAGS) -c sniffAndSpoof.c -o sniffAndSpoof.o

.PHONY: clean all

clean:
	rm *.o sniffAndSpoof