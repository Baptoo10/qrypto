#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#ifndef HASHFUNCTIONS_SHA256_H
#define HASHFUNCTIONS_SHA256_H

int sha256_fun(uint8_t data[], unsigned char *hash, int rounds, size_t data_len);

#endif //HASHFUNCTIONS_SHA256_H
