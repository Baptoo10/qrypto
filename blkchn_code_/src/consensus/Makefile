CC ?= gcc
CXX ?= g++

CFLAGS += -Wall -Wextra -Wpedantic -Wredundant-decls \
  -Wshadow -Wpointer-arith -mavx2 -mpopcnt -maes -mbmi2 \
  -march=native -mtune=native -O3

LIBS = -lssl -lcrypto

HASHFUN_PATH = ../HashFunctions/


HASHFUNCTIONS_SOURCES = $(HASHFUN_PATH)/SHA256/sha256_file.cpp
HASHFUNCTIONS_HEADERS = $(HASHFUN_PATH)/SHA256/sha256_file.h

SOURCES = $(HASHFUNCTIONS_SOURCES) ../print_type/printtype.c

HEADERS = $(HASHFUNCTIONS_HEADERS) ../print_type/printtype.h


run_consensus: consensus_main.cpp $(SOURCES)
		$(CXX) $(CFLAGS) \
	  -o $@ $< $ $(SOURCES) $(LIBS)

sha: ../HashFunctions/SHA256/sha256.c
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto

all: run_consensus

.PHONY: clean

clean:
	rm -f run_consensus
	rm -f sha
