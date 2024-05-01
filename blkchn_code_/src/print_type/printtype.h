#ifndef PRINT_TYPE_PRINTTYPE_H
#define PRINT_TYPE_PRINTTYPE_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
   char *showhex(const uint8_t a[], int size);
   void print_binary(const uint8_t a[], int size);
};
#endif

char *showhex(const uint8_t a[], int size);
void print_binary(const uint8_t a[], int size);

#endif //PRINT_TYPE_PRINTTYPE_H
