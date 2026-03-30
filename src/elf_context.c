#include "elf_context.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int init_elf_context(ElfContext *ctx, const char *filename) {
    if (!ctx || !filename) {
        fprintf(stderr, "init_elf_context: NULL argument\n");
        return -1;
    }
    memset(ctx, 0, sizeof(ElfContext));
    ctx->filename = filename;
    ctx->f = fopen(filename, "rb");
    if (!ctx->f) {
        perror("fopen");
        return -1;
    }
    if (fread(&ctx->ehdr, 1, sizeof(ctx->ehdr), ctx->f) != sizeof(ctx->ehdr)) {
        fprintf(stderr, "Error: Could not read ELF header\n");
        free_elf_context(ctx);
        return -1;
    }
    if (memcmp(ctx->ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file. Magic: %02x %02x %02x %02x\n",
                ctx->ehdr.e_ident[0], ctx->ehdr.e_ident[1],
                ctx->ehdr.e_ident[2], ctx->ehdr.e_ident[3]);
        free_elf_context(ctx);
        return -1;
    }
    if (ctx->ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Only 64-bit ELF files are supported. Got class: %d\n",
                ctx->ehdr.e_ident[EI_CLASS]);
        free_elf_context(ctx);
        return -1;
    }
    if (ctx->ehdr.e_shnum == 0) {
        fprintf(stderr, "Warning: No section headers in ELF file\n");
        ctx->shdrs = NULL;
        ctx->shstrtab = NULL;
        return 0;   // success, but no sections
    }
    ctx->shdrs = malloc(ctx->ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!ctx->shdrs) {
        perror("malloc shdrs");
        free_elf_context(ctx);
        return -1;
    }
    fseek(ctx->f, ctx->ehdr.e_shoff, SEEK_SET);
    if (fread(ctx->shdrs, sizeof(Elf64_Shdr), ctx->ehdr.e_shnum, ctx->f) != ctx->ehdr.e_shnum) {
        fprintf(stderr, "Error: Could not read section headers\n");
        free_elf_context(ctx);
        return -1;
    }
    if (ctx->ehdr.e_shstrndx >= ctx->ehdr.e_shnum) {
        fprintf(stderr, "Warning: Invalid shstrndx %d (max %d)\n",
                ctx->ehdr.e_shstrndx, ctx->ehdr.e_shnum);
        ctx->shstrtab = NULL;
        return 0;
    }
    Elf64_Shdr *shstr = &ctx->shdrs[ctx->ehdr.e_shstrndx];
    ctx->shstrtab = malloc(shstr->sh_size + 1);
    if (!ctx->shstrtab) {
        perror("malloc shstrtab");
        free_elf_context(ctx);
        return -1;
    }
    fseek(ctx->f, shstr->sh_offset, SEEK_SET);
    if (fread(ctx->shstrtab, 1, shstr->sh_size, ctx->f) != shstr->sh_size) {
        fprintf(stderr, "Error: Could not read shstrtab\n");
        free_elf_context(ctx);
        return -1;
    }
    ctx->shstrtab[shstr->sh_size] = '\0';
    for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
        if (ctx->shdrs[i].sh_type == SHT_SYMTAB) {
            ctx->symtab = &ctx->shdrs[i];
            if (ctx->symtab->sh_link < ctx->ehdr.e_shnum)
                ctx->strtab = &ctx->shdrs[ctx->symtab->sh_link];
        }
        if (ctx->shdrs[i].sh_type == SHT_DYNSYM) {
            ctx->dynsym = &ctx->shdrs[i];
            if (ctx->dynsym->sh_link < ctx->ehdr.e_shnum)
                ctx->dynstr = &ctx->shdrs[ctx->dynsym->sh_link];
        }
    }
    return 0;
}

void free_elf_context(ElfContext *ctx) {
    if (!ctx) return;
    if (ctx->shdrs) { free(ctx->shdrs); ctx->shdrs = NULL; }
    if (ctx->shstrtab) { free(ctx->shstrtab); ctx->shstrtab = NULL; }
    if (ctx->f) { fclose(ctx->f); ctx->f = NULL; }
    ctx->symtab = ctx->strtab = ctx->dynsym = ctx->dynstr = NULL;
}
