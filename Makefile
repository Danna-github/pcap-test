test: main.o
	gcc -o test main.cpp -lpcap

clean:
	rm *.o pcap-test

