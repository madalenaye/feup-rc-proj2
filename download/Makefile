.PHONY: all

CC = gcc

CLANGS = -Wall -g

all: bin/download

HOST=rcom:rcom@netlab1.fe.up.pt

FILE=files/pic1.jpg

bin/download: download.c
	mkdir -p ./bin
	$(CC) $(CFLAGS) -g -o bin/download download.c

run: bin/download
	./bin/download ftp://$(HOST)/$(FILE)
