pcap-test: main.o
	gcc -o pcap-test main.cpp -lpcap

clean:
	rm -rf *.o 

