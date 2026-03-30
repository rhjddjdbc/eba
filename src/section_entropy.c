#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/entropy.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_section_entropy(ElfContext *ctx, FILE *json_out) {
    if (json_out) {
        fprintf(json_out, "  \"section_entropy\": [\n");
        int first = 1;
        for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
            Elf64_Shdr *sec = &ctx->shdrs[i];
            if (sec->sh_size == 0) continue;
            const char *name = &ctx->shstrtab[sec->sh_name];
            unsigned char *data = malloc(sec->sh_size);
            if (!data) continue;
            fseek(ctx->f, sec->sh_offset, SEEK_SET);
            fread(data, 1, sec->sh_size, ctx->f);
            double entropy = shannon_entropy(data, sec->sh_size);
            free(data);
            if (!first) fprintf(json_out, ",\n");
            first = 0;
            fprintf(json_out, "    { \"section\": \"%s\", \"entropy\": %.6f }", name, entropy);
        }
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Entropy per Section ===\n");
        printf("%-20s | %s\n", "Section", "Entropy");
        printf("----------------------------\n");
        for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
            Elf64_Shdr *sec = &ctx->shdrs[i];
            if (sec->sh_size == 0) continue;
            const char *name = &ctx->shstrtab[sec->sh_name];
            unsigned char *data = malloc(sec->sh_size);
            if (!data) continue;
            fseek(ctx->f, sec->sh_offset, SEEK_SET);
            fread(data, 1, sec->sh_size, ctx->f);
            double entropy = shannon_entropy(data, sec->sh_size);
            free(data);
            printf("%-20s | %.6f\n", name, entropy);
        }
        printf("\n");
    }
}
