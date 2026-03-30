#include "sha256.h"
#include <openssl/evp.h>
#include <string.h>

#define BUFFER_SIZE 4096

void print_sha256(FILE *f) {
    char hash[65];
    sha256_string(f, hash);
    printf("SHA256: %s\n", hash);
}

void sha256_string(FILE *f, char *out) {
    if (!f || !out) {
        if (out) out[0] = '\0';
        return;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        out[0] = '\0';
        return;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        out[0] = '\0';
        return;
    }

    unsigned char buf[BUFFER_SIZE];
    size_t bytes;
    long original_pos = ftell(f);
    
    fseek(f, 0, SEEK_SET);
    while ((bytes = fread(buf, 1, BUFFER_SIZE, f)) > 0) {
        EVP_DigestUpdate(ctx, buf, bytes);
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &len) != 1) {
        EVP_MD_CTX_free(ctx);
        out[0] = '\0';
        return;
    }
    EVP_MD_CTX_free(ctx);

    // Ensure we don't overflow (hash is at most 32 bytes for SHA256)
    if (len > 32) len = 32;
    for (unsigned int i = 0; i < len; i++) {
        sprintf(out + i*2, "%02x", hash[i]);
    }
    out[len*2] = '\0';
    
    // Restore file position
    fseek(f, original_pos, SEEK_SET);
}
