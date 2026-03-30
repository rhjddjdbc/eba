#include "h/elf_parser.h"
#include "h/elf_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void hexdump(const unsigned char *data, size_t size, unsigned long offset) {
    for (size_t i = 0; i < size; i += 16) {
        printf("%08lx: ", offset + i);
        // Hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        // ASCII representation
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

void hexview_section(ElfContext *ctx, const char *section_name) {
    for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
        const char *name = &ctx->shstrtab[ctx->shdrs[i].sh_name];
        if (strcmp(name, section_name) == 0) {
            Elf64_Shdr *sec = &ctx->shdrs[i];
            unsigned char *data = malloc(sec->sh_size);
            if (!data) {
                printf("Failed to allocate memory\n");
                return;
            }
            fseek(ctx->f, sec->sh_offset, SEEK_SET);
            size_t read = fread(data, 1, sec->sh_size, ctx->f);
            if (read != sec->sh_size) {
                printf("Failed to read section data\n");
                free(data);
                return;
            }
            
            printf("\n=== Section '%s' (offset: 0x%lx, size: 0x%lx) ===\n",
                   section_name, sec->sh_offset, sec->sh_size);
            hexdump(data, sec->sh_size, sec->sh_offset);
            
            free(data);
            return;
        }
    }
    printf("Section '%s' not found.\n", section_name);
}
