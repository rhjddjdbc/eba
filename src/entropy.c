#include "entropy.h"
#include <math.h>

#define BUFFER_SIZE 4096

double shannon_entropy(unsigned char *data, size_t size) {
    if (size == 0) return 0.0;
    int counts[256] = {0};
    for (size_t i = 0; i < size; i++) counts[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / size;
        entropy -= p * log2(p);
    }
    return entropy;
}

double calculate_total_entropy(FILE *f) {
    int counts[256] = {0};
    unsigned char buf[BUFFER_SIZE];
    size_t total = 0;
    fseek(f, 0, SEEK_SET);
    size_t bytes;
    while ((bytes = fread(buf, 1, BUFFER_SIZE, f)) > 0) {
        for (size_t i = 0; i < bytes; i++) counts[buf[i]]++;
        total += bytes;
    }
    if (total == 0) return 0.0;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / total;
        entropy -= p * log2(p);
    }
    return entropy;
}
