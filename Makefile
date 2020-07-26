pcap-test: main.o
	gcc -o pcap-test main.o

main.o: main.cpp
	gcc -o main.o main.cpp

clean:
	rm *.o pcap-test

