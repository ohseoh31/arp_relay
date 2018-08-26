all : arp_test

arp_test: main.o
	g++ -g -o arp main.o -lpcap -pthread

main.o: header.h
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arp
	rm -f *.o

