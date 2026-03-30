#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*shdr_callback_t)(int idx, const char *name, unsigned int type,
                                uint64_t addr, uint64_t offset, size_t size,
                                void *userdata);

static void process_section_headers(ElfContext *ctx, shdr_callback_t cb, void *userdata) {
    for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
        Elf64_Shdr *sec = &ctx->shdrs[i];
        const char *name = &ctx->shstrtab[sec->sh_name];
        cb(i, name, sec->sh_type, sec->sh_addr, sec->sh_offset, sec->sh_size, userdata);
    }
}

static void json_shdr_callback(int idx, const char *name, unsigned int type,
                               uint64_t addr, uint64_t offset, size_t size,
                               void *userdata) {
    static int first = 1;
    FILE *out = (FILE*)userdata;
    if (!first) fprintf(out, ",\n");
    first = 0;
    fprintf(out, "    { \"index\": %d, \"name\": \"%s\", \"type\": %u, \"address\": \"0x%lx\", \"offset\": \"0x%lx\", \"size\": %zu }",
            idx, name, type, addr, offset, size);
}

static void console_shdr_callback(int idx, const char *name, unsigned int type,
                                  uint64_t addr, uint64_t offset, size_t size,
                                  void *userdata) {
    static int first = 1;
    if (first) {
        printf("%-4s | %-20s | %-10s | %-18s | %-10s | %-10s\n",
               "Nr", "Name", "Typ", "Adresse", "Offset", "Größe");
        printf("------------------------------------------------------------------------------------\n");
        first = 0;
    }
    printf("%-4d | %-20s | %-10u | 0x%016lx | 0x%08lx | %-10zu\n",
           idx, name, type, addr, offset, size);
}

void print_section_headers(ElfContext *ctx, FILE *json_out) {
    if (json_out) {
        fprintf(json_out, "  \"section_headers\": [\n");
        process_section_headers(ctx, json_shdr_callback, json_out);
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Section Headers ===\n");
        process_section_headers(ctx, console_shdr_callback, NULL);
        printf("\n");
    }
}
