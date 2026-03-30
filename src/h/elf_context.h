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
} ElfContext;

int  init_elf_context(ElfContext *ctx, const char *filename);
void free_elf_context(ElfContext *ctx);

#endif
