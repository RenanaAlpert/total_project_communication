CC = gcc
CFLAGS = -Wall

all: spoofReq spoofRep

spoofReq: spoofingReq.o
	$(CC) $(CFLAGS) spoofingReq.o -lpcap -o spoofReq

spoofingReq.o: spoofingRequest.c
	$(CC) $(CFLAGS) -c spoofingRequest.c -o spoofingReq.o

spoofRep: spoofingRep.o
	$(CC) $(CFLAGS) spoofingRep.o -lpcap -o spoofRep

spoofingRep.o: spoofingReply.c
	$(CC) $(CFLAGS) -c spoofingReply.c -o spoofingRep.o

.PHONY: clean all

clean:
	rm *.o spoofReq spoofRep