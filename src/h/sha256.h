#ifndef SHA256_H
#define SHA256_H

#include <stdio.h>

void print_sha256(FILE *f);
void sha256_string(FILE *f, char *out);   // new: returns hash as hex string

#endif
