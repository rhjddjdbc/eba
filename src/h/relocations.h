#ifndef RELOCATIONS_H
#define RELOCATIONS_H

#include <elf.h>
#include <stdio.h>

void print_relocations(FILE *f, Elf64_Ehdr *ehdr, Elf64_Shdr *shdrs, char *shstrtab, FILE *json_out);

#endif
