#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_symbols(ElfContext *ctx, int limit, FILE *json_out) {
    if (!ctx->symtab || !ctx->strtab) {
        if (json_out)
            fprintf(json_out, "  \"symbols\": [],\n");
        else
            printf("=== Symbols ===\n(No symbol table found)\n\n");
        return;
    }
    
    size_t sym_count = ctx->symtab->sh_size / sizeof(Elf64_Sym);
    Elf64_Sym *syms = malloc(ctx->symtab->sh_size);
    char *strings = malloc(ctx->strtab->sh_size);
    if (!syms || !strings) {
        free(syms);
        free(strings);
        return;
    }
    
    fseek(ctx->f, ctx->symtab->sh_offset, SEEK_SET);
    fread(syms, 1, ctx->symtab->sh_size, ctx->f);
    fseek(ctx->f, ctx->strtab->sh_offset, SEEK_SET);
    fread(strings, 1, ctx->strtab->sh_size, ctx->f);
    
    if (json_out) {
        fprintf(json_out, "  \"symbols\": [\n");
        int first = 1;
        int count = 0;
        for (size_t i = 0; i < sym_count && count < limit; i++) {
            int type = ELF64_ST_TYPE(syms[i].st_info);
            if (type == STT_FUNC || type == STT_OBJECT) {
                if (!first) fprintf(json_out, ",\n");
                first = 0;
                fprintf(json_out, "    {\"name\": \"%s\", \"address\": \"0x%lx\", \"size\": %lu, \"type\": \"%s\"}",
                        &strings[syms[i].st_name], syms[i].st_value, syms[i].st_size,
                        (type == STT_FUNC) ? "function" : "object");
                count++;
            }
        }
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Symbols (first %d) ===\n", limit);
        printf("%-30s | %-18s | %-10s | %s\n", "Name", "Address", "Size", "Type");
        printf("----------------------------------------------------------------------\n");
        int count = 0;
        for (size_t i = 0; i < sym_count && count < limit; i++) {
            int type = ELF64_ST_TYPE(syms[i].st_info);
            if (type == STT_FUNC || type == STT_OBJECT) {
                printf("%-30s | 0x%016lx | %-10lu | %s\n",
                       &strings[syms[i].st_name], syms[i].st_value, syms[i].st_size,
                       (type == STT_FUNC) ? "function" : "object");
                count++;
            }
        }
        printf("\n");
    }
    
    free(syms);
    free(strings);
}
