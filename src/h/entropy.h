#ifndef ENTROPY_H
#define ENTROPY_H

#include <stdio.h>
#include <stddef.h>

double shannon_entropy(unsigned char *data, size_t size);
double calculate_total_entropy(FILE *f);

#endif
