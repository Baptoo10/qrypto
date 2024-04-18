CC ?= gcc
CXX ?= g++

CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -mavx2 -mpopcnt -maes -mbmi2 \
  -march=native -mtune=native -O3

NISTFLAGS += -Wno-unused-result -mavx2 -mpopcnt -maes -mbmi2 \
  -march=native -mtune=native -O3
LDFLAGS = -lssl -lcrypto -lsqlcipher

DILITHIUM_PATH = ../avx2_dilithium3-AES-R/
HASHFUN_PATH = ../HashFunctions/

DILITHIUM_SOURCES = $(DILITHIUM_PATH)sign.c $(DILITHIUM_PATH)packing.c $(DILITHIUM_PATH)polyvec.c $(DILITHIUM_PATH)poly.c $(DILITHIUM_PATH)ntt.S \
  $(DILITHIUM_PATH)invntt.S $(DILITHIUM_PATH)pointwise.S $(DILITHIUM_PATH)consts.c $(DILITHIUM_PATH)rejsample.c $(DILITHIUM_PATH)rounding.c

KECCAK_SOURCES = $(DILITHIUM_SOURCES) $(DILITHIUM_PATH)fips202.c $(DILITHIUM_PATH)fips202x4.c $(DILITHIUM_PATH)symmetric-shake.c \
  $(DILITHIUM_PATH)keccak4x/KeccakP-1600-times4-SIMD256.o

KECCAK_HEADERS = $(HEADERS) $(DILITHIUM_PATH)fips202.h $(DILITHIUM_PATH)fips202x4.h
AES_SOURCES = $(DILITHIUM_SOURCES) $(DILITHIUM_PATH)fips202.c $(DILITHIUM_PATH)aes256ctr.c
AES_HEADERS = $(HEADERS) $(DILITHIUM_PATH)fips202.h $(DILITHIUM_PATH)aes256ctr.h

HASHFUNCTIONS_SOURCES = $(HASHFUN_PATH)/SHA256/sha256.c $(HASHFUN_PATH)/RIPEMD160/ripemd160.c
HASHFUNCTIONS_HEADERS = $(HASHFUN_PATH)/SHA256/sha256.h $(HASHFUN_PATH)/RIPEMD160/ripemd160.h

SOURCES = ../print_type/printtype.c ../base58/base58.c ./wallet_enc_dec.c $(DILITHIUM_PATH)randombytes.c \
		$(AES_SOURCES) $(HASHFUNCTIONS_SOURCES)

HEADERS = ./wallet_enc_dec.h ../print_type/printtype.h ../sqlcipher-master/tsrc/crypto.h ./config.h ../base58/base58.h $(DILITHIUM_PATH)config.h $(DILITHIUM_PATH)params.h $(DILITHIUM_PATH)api.h $(DILITHIUM_PATH)sign.h $(DILITHIUM_PATH)packing.h \
  $(DILITHIUM_PATH)polyvec.h $(DILITHIUM_PATH)poly.h $(DILITHIUM_PATH)ntt.h $(DILITHIUM_PATH)consts.h \
  $(DILITHIUM_PATH)rejsample.h $(DILITHIUM_PATH)rounding.h $(DILITHIUM_PATH)symmetric.h $(DILITHIUM_PATH)randombytes.h


gen_key_mode3: gen_key.c $(SOURCES)
		$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< $ $(SOURCES) $(LDFLAGS)


all: gen_key_mode3

.PHONY: clean
clean:
	rm -f gen_key_mode3
