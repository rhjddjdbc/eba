#include "relocations.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

typedef void (*reloc_callback_t)(const char *section_name, uint64_t offset,
                                 const char *symbol, unsigned long type,
                                 long addend, int has_addend, void *userdata);

static void process_relocations(FILE *f, Elf64_Ehdr *ehdr, Elf64_Shdr *shdrs,
                                char *shstrtab, reloc_callback_t cb, void *userdata) {
    if (!f || !ehdr || !shdrs || !shstrtab || !cb) return;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *relsec = &shdrs[i];
        if (relsec->sh_type != SHT_RELA && relsec->sh_type != SHT_REL) continue;
        if (relsec->sh_link >= ehdr->e_shnum) continue;
        Elf64_Shdr *symtab = &shdrs[relsec->sh_link];
        if (symtab->sh_link >= ehdr->e_shnum) continue;
        Elf64_Shdr *strtab = &shdrs[symtab->sh_link];

        char *strdata = NULL;
        Elf64_Sym *symdata = NULL;
        long original_pos = ftell(f);

        strdata = malloc(strtab->sh_size);
        if (!strdata) goto cleanup;
        symdata = malloc(symtab->sh_size);
        if (!symdata) goto cleanup;

        fseek(f, strtab->sh_offset, SEEK_SET);
        if (fread(strdata, 1, strtab->sh_size, f) != strtab->sh_size) goto cleanup;
        fseek(f, symtab->sh_offset, SEEK_SET);
        if (fread(symdata, 1, symtab->sh_size, f) != symtab->sh_size) goto cleanup;

        size_t entry_size = (relsec->sh_type == SHT_RELA) ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
        size_t num = relsec->sh_size / entry_size;
        const char *sec_name = &shstrtab[relsec->sh_name];

        for (size_t j = 0; j < num; j++) {
            if (relsec->sh_type == SHT_RELA) {
                Elf64_Rela rela;
                fseek(f, relsec->sh_offset + j * sizeof(Elf64_Rela), SEEK_SET);
                if (fread(&rela, sizeof(rela), 1, f) != 1) continue;
                uint32_t sym_idx = ELF64_R_SYM(rela.r_info);
                const char *name = (sym_idx < (symtab->sh_size / sizeof(Elf64_Sym)))
                                    ? &strdata[symdata[sym_idx].st_name] : "<unknown>";
                cb(sec_name, rela.r_offset, name, ELF64_R_TYPE(rela.r_info),
                   rela.r_addend, 1, userdata);
            } else {
                Elf64_Rel rel;
                fseek(f, relsec->sh_offset + j * sizeof(Elf64_Rel), SEEK_SET);
                if (fread(&rel, sizeof(rel), 1, f) != 1) continue;
                uint32_t sym_idx = ELF64_R_SYM(rel.r_info);
                const char *name = (sym_idx < (symtab->sh_size / sizeof(Elf64_Sym)))
                                    ? &strdata[symdata[sym_idx].st_name] : "<unknown>";
                cb(sec_name, rel.r_offset, name, ELF64_R_TYPE(rel.r_info), 0, 0, userdata);
            }
        }

    cleanup:
        free(strdata);
        free(symdata);
        fseek(f, original_pos, SEEK_SET);
    }
}

static void json_reloc_callback(const char *sec, uint64_t off, const char *sym,
                                unsigned long type, long addend, int has_addend,
                                void *userdata) {
    static int first = 1;
    FILE *out = (FILE*)userdata;
    if (!first) fprintf(out, ",\n");
    first = 0;
    fprintf(out, "    { \"section\": \"%s\", \"offset\": \"0x%016" PRIx64 "\", \"symbol\": \"%s\", \"type\": %lu",
            sec, off, sym, type);
    if (has_addend)
        fprintf(out, ", \"addend\": %ld }", addend);
    else
        fprintf(out, " }");
}

static void console_reloc_callback(const char *sec, uint64_t off, const char *sym,
                                   unsigned long type, long addend, int has_addend,
                                   void *userdata) {
    static const char *last_sec = NULL;
    if (!last_sec || strcmp(last_sec, sec) != 0) {
        if (last_sec) printf("\n");
        printf("Section: %s\n", sec);
        printf("%-18s | %-20s | %-8s | Addend\n", "Offset", "Symbol", "Type");
        last_sec = sec;
    }
    if (has_addend)
        printf("0x%016" PRIx64 " | %-20s | %-8lu | %ld\n", off, sym, type, addend);
    else
        printf("0x%016" PRIx64 " | %-20s | %-8lu | -\n", off, sym, type);
}

void print_relocations(FILE *f, Elf64_Ehdr *ehdr, Elf64_Shdr *shdrs,
                       char *shstrtab, FILE *json_out) {
    if (!f || !ehdr || !shdrs || !shstrtab) return;
    if (json_out) {
        fprintf(json_out, "  \"relocations\": [\n");
        process_relocations(f, ehdr, shdrs, shstrtab, json_reloc_callback, json_out);
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Relocations ===\n");
        process_relocations(f, ehdr, shdrs, shstrtab, console_reloc_callback, NULL);
        printf("\n");
    }
}
