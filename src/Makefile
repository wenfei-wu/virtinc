main.o: util.o host.o switch.o
	gcc bin/util.o bin/host.o bin/switch.o main.c -o  bin/main.o -lpcap -pthread
util.o:
	cc -c -o bin/util.o util.c
host.o:
	cc -c -o bin/host.o host.c -lpcap
switch.o:
	cc -c -o bin/switch.o switch.c -lpcap -pthread
