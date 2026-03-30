#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*sym_callback_t)(const char *name, uint64_t addr, size_t size,
                               const char *type, void *userdata);

static void process_symbols(ElfContext *ctx, int limit, sym_callback_t cb, void *userdata) {
    if (!ctx->symtab || !ctx->strtab) return;

    size_t sym_count;
    Elf64_Sym *syms = elf_read_symbols(ctx, ctx->symtab, &sym_count);
    size_t str_size;
    char *strings = elf_read_strings(ctx, ctx->strtab, &str_size);
    if (!syms || !strings) {
        free(syms); free(strings);
        return;
    }

    int count = 0;
    for (size_t i = 0; i < sym_count && count < limit; i++) {
        int type = ELF64_ST_TYPE(syms[i].st_info);
        if (type == STT_FUNC || type == STT_OBJECT) {
            const char *typestr = (type == STT_FUNC) ? "function" : "object";
            cb(&strings[syms[i].st_name], syms[i].st_value, syms[i].st_size, typestr, userdata);
            count++;
        }
    }
    free(syms);
    free(strings);
}

static void json_sym_callback(const char *name, uint64_t addr, size_t size,
                              const char *type, void *userdata) {
    static int first = 1;
    FILE *out = (FILE*)userdata;
    if (!first) fprintf(out, ",\n");
    first = 0;
    fprintf(out, "    {\"name\": \"%s\", \"address\": \"0x%lx\", \"size\": %zu, \"type\": \"%s\"}",
            name, addr, size, type);
}

static void console_sym_callback(const char *name, uint64_t addr, size_t size,
                                 const char *type, void *userdata) {
    static int first_line = 1;
    if (first_line) {
        printf("%-30s | %-18s | %-10s | %s\n", "Name", "Address", "Size", "Type");
        printf("----------------------------------------------------------------------\n");
        first_line = 0;
    }
    printf("%-30s | 0x%016lx | %-10zu | %s\n", name, addr, size, type);
}

void print_symbols(ElfContext *ctx, int limit, FILE *json_out) {
    if (!ctx->symtab || !ctx->strtab) {
        if (json_out)
            fprintf(json_out, "  \"symbols\": [],\n");
        else
            printf("=== Symbols ===\n(No symbol table found)\n\n");
        return;
    }

    if (json_out) {
        fprintf(json_out, "  \"symbols\": [\n");
        process_symbols(ctx, limit, json_sym_callback, json_out);
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Symbols (first %d) ===\n", limit);
        process_symbols(ctx, limit, console_sym_callback, NULL);
        printf("\n");
    }
}
