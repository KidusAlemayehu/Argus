CC = gcc
CFLAGS = -O2 -std=c11 -Wall -Iinclude

all: argus

argus: src/main.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f argus

