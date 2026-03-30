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
        fprintf(stderr, "Only 64-bit ELF files are supported.\n");
        fprintf(stderr, "This file is %d-bit (EI_CLASS = %d).\n",
                (ctx->ehdr.e_ident[EI_CLASS] == ELFCLASS32) ? 32 : 0,
                ctx->ehdr.e_ident[EI_CLASS]);
        free_elf_context(ctx);
        return -1;
    }
    if (ctx->ehdr.e_shnum == 0) {
        fprintf(stderr, "Warning: No section headers in ELF file\n");
        ctx->shdrs = NULL;
        ctx->shstrtab = NULL;
        return 0;
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

    ctx->section_cache = calloc(ctx->ehdr.e_shnum, sizeof(unsigned char*));
    ctx->section_cache_sizes = calloc(ctx->ehdr.e_shnum, sizeof(size_t));
    ctx->section_cache_initialized = 1;
    if (!ctx->section_cache || !ctx->section_cache_sizes) {
        perror("calloc section_cache");
        free_elf_context(ctx);
        return -1;
    }

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
    if (ctx->section_cache_initialized) {
        for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
            free(ctx->section_cache[i]);
        }
        free(ctx->section_cache);
        free(ctx->section_cache_sizes);
        ctx->section_cache = NULL;
        ctx->section_cache_sizes = NULL;
    }
    if (ctx->f) { fclose(ctx->f); ctx->f = NULL; }
    ctx->symtab = ctx->strtab = ctx->dynsym = ctx->dynstr = NULL;
}

void *elf_read_section_cached(ElfContext *ctx, Elf64_Shdr *sec, size_t *out_size) {
    if (!ctx || !sec || sec->sh_size == 0) return NULL;
    int idx = -1;
    for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
        if (&ctx->shdrs[i] == sec) { idx = i; break; }
    }
    if (idx < 0 || !ctx->section_cache_initialized) {
        return elf_read_section(ctx, sec, out_size);
    }
    if (ctx->section_cache[idx]) {
        if (out_size) *out_size = ctx->section_cache_sizes[idx];
        return ctx->section_cache[idx];
    }
    void *data = malloc(sec->sh_size);
    if (!data) return NULL;
    long pos = ftell(ctx->f);
    fseek(ctx->f, sec->sh_offset, SEEK_SET);
    if (fread(data, 1, sec->sh_size, ctx->f) != sec->sh_size) {
        free(data);
        fseek(ctx->f, pos, SEEK_SET);
        return NULL;
    }
    fseek(ctx->f, pos, SEEK_SET);
    ctx->section_cache[idx] = data;
    ctx->section_cache_sizes[idx] = sec->sh_size;
    if (out_size) *out_size = sec->sh_size;
    return data;
}

void *elf_read_section(ElfContext *ctx, Elf64_Shdr *sec, size_t *out_size) {
    if (!ctx || !sec || sec->sh_size == 0) return NULL;
    void *data = malloc(sec->sh_size);
    if (!data) return NULL;
    long pos = ftell(ctx->f);
    fseek(ctx->f, sec->sh_offset, SEEK_SET);
    if (fread(data, 1, sec->sh_size, ctx->f) != sec->sh_size) {
        free(data);
        fseek(ctx->f, pos, SEEK_SET);
        return NULL;
    }
    fseek(ctx->f, pos, SEEK_SET);
    if (out_size) *out_size = sec->sh_size;
    return data;
}

void *elf_read_program_headers(ElfContext *ctx, size_t *out_count) {
    if (!ctx) return NULL;
    size_t count = ctx->ehdr.e_phnum;
    if (count == 0) return NULL;
    Elf64_Phdr *phdrs = malloc(count * sizeof(Elf64_Phdr));
    if (!phdrs) return NULL;
    long pos = ftell(ctx->f);
    fseek(ctx->f, ctx->ehdr.e_phoff, SEEK_SET);
    if (fread(phdrs, sizeof(Elf64_Phdr), count, ctx->f) != count) {
        free(phdrs);
        fseek(ctx->f, pos, SEEK_SET);
        return NULL;
    }
    fseek(ctx->f, pos, SEEK_SET);
    if (out_count) *out_count = count;
    return phdrs;
}

void *elf_read_dynamic(ElfContext *ctx, size_t *out_size) {
    if (!ctx) return NULL;
    size_t phnum;
    Elf64_Phdr *phdrs = elf_read_program_headers(ctx, &phnum);
    if (!phdrs) return NULL;
    Elf64_Off dyn_offset = 0;
    Elf64_Xword dyn_size = 0;
    for (size_t i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_offset = phdrs[i].p_offset;
            dyn_size = phdrs[i].p_filesz;
            break;
        }
    }
    free(phdrs);
    if (!dyn_offset || dyn_size == 0) return NULL;
    void *dyns = malloc(dyn_size);
    if (!dyns) return NULL;
    long pos = ftell(ctx->f);
    fseek(ctx->f, dyn_offset, SEEK_SET);
    if (fread(dyns, 1, dyn_size, ctx->f) != dyn_size) {
        free(dyns);
        fseek(ctx->f, pos, SEEK_SET);
        return NULL;
    }
    fseek(ctx->f, pos, SEEK_SET);
    if (out_size) *out_size = dyn_size;
    return dyns;
}

void *elf_read_symbols(ElfContext *ctx, Elf64_Shdr *symtab, size_t *out_count) {
    if (!ctx || !symtab || symtab->sh_size == 0) return NULL;
    size_t count = symtab->sh_size / sizeof(Elf64_Sym);
    void *syms = malloc(symtab->sh_size);
    if (!syms) return NULL;
    long pos = ftell(ctx->f);
    fseek(ctx->f, symtab->sh_offset, SEEK_SET);
    if (fread(syms, 1, symtab->sh_size, ctx->f) != symtab->sh_size) {
        free(syms);
        fseek(ctx->f, pos, SEEK_SET);
        return NULL;
    }
    fseek(ctx->f, pos, SEEK_SET);
    if (out_count) *out_count = count;
    return syms;
}

char *elf_read_strings(ElfContext *ctx, Elf64_Shdr *strtab, size_t *out_size) {
    if (!ctx || !strtab || strtab->sh_size == 0) return NULL;
    char *strs = malloc(strtab->sh_size + 1);
    if (!strs) return NULL;
    long pos = ftell(ctx->f);
    fseek(ctx->f, strtab->sh_offset, SEEK_SET);
    if (fread(strs, 1, strtab->sh_size, ctx->f) != strtab->sh_size) {
        free(strs);
        fseek(ctx->f, pos, SEEK_SET);
        return NULL;
    }
    strs[strtab->sh_size] = '\0';
    fseek(ctx->f, pos, SEEK_SET);
    if (out_size) *out_size = strtab->sh_size;
    return strs;
}

long elf_save_pos(ElfContext *ctx) {
    return ctx ? ftell(ctx->f) : -1;
}

void elf_restore_pos(ElfContext *ctx, long pos) {
    if (ctx && pos >= 0) fseek(ctx->f, pos, SEEK_SET);
}
