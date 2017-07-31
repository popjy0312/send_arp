send_arp: main.c
	gcc -W -Wall -o send_arp main.c -lpcap

clean:
	rm send_arp
