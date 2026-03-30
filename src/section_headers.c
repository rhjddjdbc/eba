#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_section_headers(ElfContext *ctx, FILE *json_out) {
    if (json_out) {
        fprintf(json_out, "  \"section_headers\": [\n");
        int first = 1;
        for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
            Elf64_Shdr *sec = &ctx->shdrs[i];
            const char *name = &ctx->shstrtab[sec->sh_name];
            if (!first) fprintf(json_out, ",\n");
            first = 0;
            fprintf(json_out, "    { \"index\": %d, \"name\": \"%s\", \"type\": %u, \"address\": \"0x%lx\", \"offset\": \"0x%lx\", \"size\": %lu }",
                    i, name, sec->sh_type, sec->sh_addr, sec->sh_offset, sec->sh_size);
        }
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Section Headers ===\n");
        printf("%-4s | %-20s | %-10s | %-18s | %-10s | %-10s\n", 
               "Nr", "Name", "Typ", "Adresse", "Offset", "Größe");
        printf("------------------------------------------------------------------------------------\n");
        for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
            Elf64_Shdr *sec = &ctx->shdrs[i];
            const char *name = &ctx->shstrtab[sec->sh_name];
            printf("%-4d | %-20s | %-10u | 0x%016lx | 0x%08lx | %-10lu\n",
                   i, name, sec->sh_type, sec->sh_addr, sec->sh_offset, sec->sh_size);
        }
        printf("\n");
    }
}
