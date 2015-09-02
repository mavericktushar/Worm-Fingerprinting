worm_f: worm_fingerprinting.o
	g++ -o worm_f worm_fingerprinting.o -lpcap
worm_fingerprinting.o: worm_fingerprinting.cc worm_fingerprinting.h pcap.h
	g++ -c worm_fingerprinting.cc
clean:
	rm -f worm_f worm_fingerprinting.o
