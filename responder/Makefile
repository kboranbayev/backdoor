
# Makefile for pkt_sniffer

CC=gcc -g
CC2=gcc
CLIB=-lpcap -lcrypto

all: pkt_sniffer

pkt_sniffer: pkt_sniffer.o proc_ether.o proc_hdrs.o proc_payload.o response.o aes_evp.o
	$(CC) -o pkt_sniffer pkt_sniffer.o proc_ether.o proc_hdrs.o proc_payload.o response.o aes_evp.o $(CLIB)

# response: response.o aes_evp.o
# 	$(CC) -o response response.o aes_evp.o $(CLIB)

clean:
	rm -f *.o core pkt_sniffer

pkt_sniffer.o:
	$(CC) -c pkt_sniffer.c

proc_ether.o: 
	$(CC) -c proc_ether.c

proc_hdrs.o:
	$(CC) -c proc_hdrs.c

proc_payload.o: 
	$(CC) -c proc_payload.c

response.o:
	$(CC) -c response.c
	
aes_evp.o: 
	$(CC) -c aes_evp.c 
