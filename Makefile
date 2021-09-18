all: pcap-test

pcap-test: pcap-test.o
	g++ -o pcap-test pcap-test.o -lpcap

pcap-test.o: pcap-test.c protocol-headers.h

clean:
	rm -f pcap-test
	rm -f *.o