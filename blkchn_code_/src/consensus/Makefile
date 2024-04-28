CC ?= gcc
CXX ?= g++

CFLAGS += -Wall -Wextra -Wpedantic -Wredundant-decls \
  -Wshadow -Wpointer-arith -mavx2 -mpopcnt -maes -mbmi2 \
  -march=native -mtune=native -O3

LIBS = -lssl -lcrypto

HASHFUN_PATH = ../HashFunctions/


HASHFUNCTIONS_SOURCES = $(HASHFUN_PATH)/SHA256/sha256_file.cpp
HASHFUNCTIONS_HEADERS = $(HASHFUN_PATH)/SHA256/sha256_file.h

SOURCES = $(HASHFUNCTIONS_SOURCES)

HEADERS = $(HASHFUNCTIONS_HEADERS)


run_consensus: consensus_main.cpp $(SOURCES)
		$(CXX) $(CFLAGS) \
	  -o $@ $< $ $(SOURCES) $(LIBS)


all: run_consensus

.PHONY: clean

clean:
	rm -f run_consensus
