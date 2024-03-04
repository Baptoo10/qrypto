CC ?= gcc
CXX ?= g++

CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -mavx2 -mpopcnt -maes -mbmi2 \
  -march=native -mtune=native -O3

NISTFLAGS += -Wno-unused-result -mavx2 -mpopcnt -maes -mbmi2 \
  -march=native -mtune=native -O3

DILITHIUM_PATH = ../avx2_dilithium3-AES-R/
HASHFUN_PATH = ../HashFunctions/

SOURCES = $(DILITHIUM_PATH)sign.c $(DILITHIUM_PATH)packing.c $(DILITHIUM_PATH)polyvec.c $(DILITHIUM_PATH)poly.c $(DILITHIUM_PATH)ntt.S \
  $(DILITHIUM_PATH)invntt.S $(DILITHIUM_PATH)pointwise.S $(DILITHIUM_PATH)consts.c $(DILITHIUM_PATH)rejsample.c $(DILITHIUM_PATH)rounding.c

HEADERS = ../base58/base58.h $(DILITHIUM_PATH)config.h $(DILITHIUM_PATH)params.h $(DILITHIUM_PATH)api.h $(DILITHIUM_PATH)sign.h $(DILITHIUM_PATH)packing.h \
  $(DILITHIUM_PATH)polyvec.h $(DILITHIUM_PATH)poly.h $(DILITHIUM_PATH)ntt.h $(DILITHIUM_PATH)consts.h \
  $(DILITHIUM_PATH)rejsample.h $(DILITHIUM_PATH)rounding.h $(DILITHIUM_PATH)symmetric.h $(DILITHIUM_PATH)randombytes.h

KECCAK_SOURCES = $(SOURCES) $(DILITHIUM_PATH)fips202.c $(DILITHIUM_PATH)fips202x4.c $(DILITHIUM_PATH)symmetric-shake.c \
  $(DILITHIUM_PATH)keccak4x/KeccakP-1600-times4-SIMD256.o

KECCAK_HEADERS = $(HEADERS) $(DILITHIUM_PATH)fips202.h $(DILITHIUM_PATH)fips202x4.h
AES_SOURCES = $(SOURCES) $(DILITHIUM_PATH)fips202.c $(DILITHIUM_PATH)aes256ctr.c
AES_HEADERS = $(HEADERS) $(DILITHIUM_PATH)fips202.h $(DILITHIUM_PATH)aes256ctr.h

HASHFUNCTIONS_SOURCES = $(HASHFUN_PATH)/SHA256/sha256.c $(HASHFUN_PATH)/RIPEMD160/ripemd160.c
HASHFUNCTIONS_HEADERS = $(HASHFUN_PATH)/SHA256/sha256.h $(HASHFUN_PATH)/RIPEMD160/ripemd160.h

gen_key_mode3: gen_key.c ../base58/base58.c $(DILITHIUM_PATH)randombytes.c $(AES_SOURCES) $(AES_HEADERS) \
  $(HASHFUNCTIONS_SOURCES) $(HASHFUNCTIONS_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< ../base58/base58.c $(DILITHIUM_PATH)randombytes.c $(AES_SOURCES) $(HASHFUNCTIONS_SOURCES) -lssl -lcrypto

walletdatencrypt: walletdat_encrypt.cpp
	$(CXX) -o $@ $< -lssl -lcrypto

walletdatdecrypt: walletdat_decrypt.cpp
	$(CXX) -o $@ $< -lssl -lcrypto

.PHONY: clean
clean:
	rm -f gen_key_mode3