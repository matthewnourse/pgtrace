all: build

build:
	gcc -std=c99 -Wall -Werror -Wfatal-errors -fno-strict-aliasing -Wstrict-aliasing -D _BSD_SOURCE -D_POSIX_C_SOURCE=200809L -O3 pgtrace.c -o pgtrace -lpcap

clean: 
	rm -f pgtrace 
