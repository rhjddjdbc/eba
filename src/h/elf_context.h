#ifndef ELF_CONTEXT_H
#define ELF_CONTEXT_H

#include <elf.h>
#include <stdio.h>

typedef struct {
    FILE *f;
    Elf64_Ehdr ehdr;
    Elf64_Shdr *shdrs;
    char *shstrtab;
    Elf64_Shdr *symtab;
    Elf64_Shdr *strtab;
    Elf64_Shdr *dynsym;
    Elf64_Shdr *dynstr;
    const char *filename;

    unsigned char **section_cache;
    size_t *section_cache_sizes;
    int section_cache_initialized;
} ElfContext;

int  init_elf_context(ElfContext *ctx, const char *filename);
void free_elf_context(ElfContext *ctx);

void *elf_read_section_cached(ElfContext *ctx, Elf64_Shdr *sec, size_t *out_size);
void *elf_read_section(ElfContext *ctx, Elf64_Shdr *sec, size_t *out_size);
void *elf_read_program_headers(ElfContext *ctx, size_t *out_count);
void *elf_read_dynamic(ElfContext *ctx, size_t *out_size);
void *elf_read_symbols(ElfContext *ctx, Elf64_Shdr *symtab, size_t *out_count);
char *elf_read_strings(ElfContext *ctx, Elf64_Shdr *strtab, size_t *out_size);
long elf_save_pos(ElfContext *ctx);
void elf_restore_pos(ElfContext *ctx, long pos);

#endif
