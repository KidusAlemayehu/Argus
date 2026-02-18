CC = gcc
CFLAGS = -O2 -std=c11 -Wall -Iinclude

all: argus

argus: src/main.c src/policy.c
	$(CC) $(CFLAGS) -o argus src/main.c src/policy.c

clean:
	rm -f argus

