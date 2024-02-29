CC ?= gcc
CXX ?= g++
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -mavx2 -mpopcnt -maes -mbmi2 \
  -march=native -mtune=native -O3
NISTFLAGS += -Wno-unused-result -mavx2 -mpopcnt -maes -mbmi2 \
  -march=native -mtune=native -O3

REL_PATH = ../avx2_dilithium3-AES-R/

SOURCES = $(REL_PATH)sign.c $(REL_PATH)packing.c $(REL_PATH)polyvec.c $(REL_PATH)poly.c $(REL_PATH)ntt.S \
  $(REL_PATH)invntt.S $(REL_PATH)pointwise.S $(REL_PATH)consts.c $(REL_PATH)rejsample.c $(REL_PATH)rounding.c

HEADERS = $(REL_PATH)config.h $(REL_PATH)params.h $(REL_PATH)api.h $(REL_PATH)sign.h $(REL_PATH)packing.h \
  $(REL_PATH)polyvec.h $(REL_PATH)poly.h $(REL_PATH)ntt.h $(REL_PATH)consts.h \
  $(REL_PATH)rejsample.h $(REL_PATH)rounding.h $(REL_PATH)symmetric.h $(REL_PATH)randombytes.h

KECCAK_SOURCES = $(SOURCES) $(REL_PATH)fips202.c $(REL_PATH)fips202x4.c $(REL_PATH)symmetric-shake.c \
  $(REL_PATH)keccak4x/KeccakP-1600-times4-SIMD256.o

KECCAK_HEADERS = $(HEADERS) $(REL_PATH)fips202.h $(REL_PATH)fips202x4.h
AES_SOURCES = $(SOURCES) $(REL_PATH)fips202.c $(REL_PATH)aes256ctr.c
AES_HEADERS = $(HEADERS) $(REL_PATH)fips202.h $(REL_PATH)aes256ctr.h

gen_key_mode3: gen_key.c $(REL_PATH)randombytes.c $(AES_SOURCES) $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< $(REL_PATH)randombytes.c $(AES_SOURCES) -lssl -lcrypto



.PHONY: clean
clean:
	rm -f gen_key_mode3 gen_address