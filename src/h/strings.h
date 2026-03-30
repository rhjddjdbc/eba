#ifndef STRINGS_H
#define STRINGS_H

#include <stdio.h>

// If json_out is NULL, prints to stdout. Otherwise appends JSON array elements.
void print_strings_and_heuristics(FILE *f, FILE *json_out);

#endif
