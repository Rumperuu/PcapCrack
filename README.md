# PcapCrack
## (c) Ben Goldsworthy 2017

# Description

PcapCrack is a program to attempt to brute-force the key used to encrypt a file 
in an intercepted network packet. It uses a thread pool for distributed
processing and 9 different mutation modes (doubled, starting at each end of
the dictionary file).

# Usage

To run the program:

   `java -jar -Djava.libary.path="<path-to-libjnetpcap.so>" pa.jar <.pcap-file> <dictionary-file>`
