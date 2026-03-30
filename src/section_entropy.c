#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/entropy.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*sec_entropy_callback_t)(const char *name, double entropy, void *userdata);

static void process_section_entropy(ElfContext *ctx, sec_entropy_callback_t cb, void *userdata) {
    for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
        Elf64_Shdr *sec = &ctx->shdrs[i];
        if (sec->sh_size == 0) continue;
        const char *name = &ctx->shstrtab[sec->sh_name];
        size_t size;
        unsigned char *data = elf_read_section_cached(ctx, sec, &size);
        if (!data) continue;
        double entropy = shannon_entropy(data, size);
        cb(name, entropy, userdata);
    }
}

static void json_sec_entropy_callback(const char *name, double entropy, void *userdata) {
    static int first = 1;
    FILE *out = (FILE*)userdata;
    if (!first) fprintf(out, ",\n");
    first = 0;
    fprintf(out, "    { \"section\": \"%s\", \"entropy\": %.6f }", name, entropy);
}

static void console_sec_entropy_callback(const char *name, double entropy, void *userdata) {
    static int first = 1;
    if (first) {
        printf("%-20s | %s\n", "Section", "Entropy");
        printf("----------------------------\n");
        first = 0;
    }
    printf("%-20s | %.6f\n", name, entropy);
}

void print_section_entropy(ElfContext *ctx, FILE *json_out) {
    if (json_out) {
        fprintf(json_out, "  \"section_entropy\": [\n");
        process_section_entropy(ctx, json_sec_entropy_callback, json_out);
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Entropy per Section ===\n");
        process_section_entropy(ctx, console_sec_entropy_callback, NULL);
        printf("\n");
    }
}
