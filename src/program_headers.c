#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>

void print_program_headers(ElfContext *ctx, FILE *json_out) {
    Elf64_Phdr *phdrs = malloc(ctx->ehdr.e_phnum * sizeof(Elf64_Phdr));
    if (!phdrs) return;
    fseek(ctx->f, ctx->ehdr.e_phoff, SEEK_SET);
    fread(phdrs, sizeof(Elf64_Phdr), ctx->ehdr.e_phnum, ctx->f);
    
    if (json_out) {
        fprintf(json_out, "  \"program_headers\": [\n");
        for (int i = 0; i < ctx->ehdr.e_phnum; i++) {
            const char *type_str = "UNKNOWN";
            switch (phdrs[i].p_type) {
                case PT_LOAD: type_str = "LOAD"; break;
                case PT_DYNAMIC: type_str = "DYNAMIC"; break;
                case PT_INTERP: type_str = "INTERP"; break;
                case PT_NOTE: type_str = "NOTE"; break;
                case PT_PHDR: type_str = "PHDR"; break;
                case PT_GNU_STACK: type_str = "GNU_STACK"; break;
                case PT_GNU_RELRO: type_str = "GNU_RELRO"; break;
            }
            fprintf(json_out, "    { \"type\": \"%s\", \"vaddr\": \"0x%lx\", \"memsz\": %lu, \"flags\": %d }%s\n",
                    type_str, phdrs[i].p_vaddr, phdrs[i].p_memsz, phdrs[i].p_flags,
                    (i == ctx->ehdr.e_phnum-1) ? "" : ",");
        }
        fprintf(json_out, "  ],\n");
    } else {
        printf("=== Program Headers ===\n");
        printf("%-12s %-18s %-12s %s\n", "Type", "Virtual Address", "Mem Size", "Flags");
        for (int i = 0; i < ctx->ehdr.e_phnum; i++) {
            const char *type_str = "UNKNOWN";
            switch (phdrs[i].p_type) {
                case PT_LOAD: type_str = "LOAD"; break;
                case PT_DYNAMIC: type_str = "DYNAMIC"; break;
                case PT_INTERP: type_str = "INTERP"; break;
                case PT_NOTE: type_str = "NOTE"; break;
                case PT_PHDR: type_str = "PHDR"; break;
                case PT_GNU_STACK: type_str = "GNU_STACK"; break;
                case PT_GNU_RELRO: type_str = "GNU_RELRO"; break;
            }
            printf("%-12s 0x%016lx %-12lu 0x%x\n",
                   type_str, phdrs[i].p_vaddr, phdrs[i].p_memsz, phdrs[i].p_flags);
        }
        printf("\n");
    }
    
    free(phdrs);
}
