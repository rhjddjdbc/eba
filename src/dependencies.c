#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_dependencies(ElfContext *ctx, FILE *json_out) {
    if (!ctx->dynstr) {
        if (json_out)
            fprintf(json_out, "  \"dependencies\": [],\n");
        else
            printf("=== Shared Library Dependencies ===\n(No dynamic section found)\n\n");
        return;
    }
    
    char *dynstr = malloc(ctx->dynstr->sh_size);
    if (!dynstr) return;
    fseek(ctx->f, ctx->dynstr->sh_offset, SEEK_SET);
    fread(dynstr, 1, ctx->dynstr->sh_size, ctx->f);
    
    Elf64_Phdr *phdrs = malloc(ctx->ehdr.e_phnum * sizeof(Elf64_Phdr));
    if (!phdrs) {
        free(dynstr);
        return;
    }
    fseek(ctx->f, ctx->ehdr.e_phoff, SEEK_SET);
    fread(phdrs, sizeof(Elf64_Phdr), ctx->ehdr.e_phnum, ctx->f);
    
    Elf64_Off dyn_offset = 0;
    Elf64_Xword dyn_size = 0;
    for (int i = 0; i < ctx->ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_offset = phdrs[i].p_offset;
            dyn_size = phdrs[i].p_filesz;
            break;
        }
    }
    
    if (!dyn_offset) {
        if (json_out)
            fprintf(json_out, "  \"dependencies\": [],\n");
        else
            printf("=== Shared Library Dependencies ===\n(No PT_DYNAMIC segment)\n\n");
        free(phdrs);
        free(dynstr);
        return;
    }
    
    Elf64_Dyn *dyns = malloc(dyn_size);
    if (!dyns) {
        free(phdrs);
        free(dynstr);
        return;
    }
    fseek(ctx->f, dyn_offset, SEEK_SET);
    fread(dyns, 1, dyn_size, ctx->f);
    
    if (json_out) {
        fprintf(json_out, "  \"dependencies\": [\n");
        int first = 1;
        for (Elf64_Dyn *d = dyns; d->d_tag != DT_NULL; d++) {
            if (d->d_tag == DT_NEEDED) {
                if (!first) fprintf(json_out, ",\n");
                first = 0;
                fprintf(json_out, "    \"%s\"", &dynstr[d->d_un.d_val]);
            }
        }
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Shared Library Dependencies ===\n");
        int count = 0;
        for (Elf64_Dyn *d = dyns; d->d_tag != DT_NULL; d++) {
            if (d->d_tag == DT_NEEDED) {
                printf("  %s\n", &dynstr[d->d_un.d_val]);
                count++;
            }
        }
        if (count == 0) printf("  (none)\n");
        printf("\n");
    }
    
    free(dyns);
    free(phdrs);
    free(dynstr);
}
