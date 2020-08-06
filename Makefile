all: pcap-test

pcap-test: header.o main.o
	gcc -o pcap-test header.o main.o -lpcap

header.o: header.h header.cpp
	gcc -c -o header.o header.cpp -lpcap

main.o: main.cpp header.h
	gcc -c -o main.o main.cpp -lpcap

clean:
	rm -f pcap-test *.o 

