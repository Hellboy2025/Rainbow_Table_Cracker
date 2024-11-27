pr4: pr4_p.c	
	gcc -g -Wall -lcrypto -lpthread pr4_p.c -o pr4_p 

test: pr4
	time -p ./pr4_p tocrack.txt passwords.lst 8


all: pr4_p

clean:
	rm pr4_p
