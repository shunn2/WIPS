WIPS : main.o
	gcc -o WIPS main.o -lpcap
main.o : main.c
	gcc -c -o main.o main.c
