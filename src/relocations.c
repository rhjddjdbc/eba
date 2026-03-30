#include "relocations.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

void print_relocations(FILE *f, Elf64_Ehdr *ehdr, Elf64_Shdr *shdrs, char *shstrtab, FILE *json_out) {
    if (!f || !ehdr || !shdrs || !shstrtab) return;
    
    if (json_out) {
        fprintf(json_out, "  \"relocations\": [\n");
        int first_rel = 1;
        for (int i = 0; i < ehdr->e_shnum; i++) {
            Elf64_Shdr *relsec = &shdrs[i];
            if (relsec->sh_type != SHT_RELA && relsec->sh_type != SHT_REL) continue;
            if (relsec->sh_link >= ehdr->e_shnum) continue;
            Elf64_Shdr *symtab = &shdrs[relsec->sh_link];
            if (symtab->sh_link >= ehdr->e_shnum) continue;
            Elf64_Shdr *strtab = &shdrs[symtab->sh_link];

            char *strdata = malloc(strtab->sh_size);
            Elf64_Sym *symdata = malloc(symtab->sh_size);
            if (!strdata || !symdata) {
                free(strdata); 
                free(symdata);
                continue;
            }
            
            long original_pos = ftell(f);
            fseek(f, strtab->sh_offset, SEEK_SET);
            if (fread(strdata, 1, strtab->sh_size, f) != strtab->sh_size) {
                free(strdata);
                free(symdata);
                continue;
            }
            fseek(f, symtab->sh_offset, SEEK_SET);
            if (fread(symdata, 1, symtab->sh_size, f) != symtab->sh_size) {
                free(strdata);
                free(symdata);
                continue;
            }

            size_t entry_size = (relsec->sh_type == SHT_RELA) ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
            size_t num = relsec->sh_size / entry_size;

            for (size_t j = 0; j < num; j++) {
                if (!first_rel) fprintf(json_out, ",\n");
                first_rel = 0;
                fprintf(json_out, "    { \"section\": \"%s\", ", &shstrtab[relsec->sh_name]);
                if (relsec->sh_type == SHT_RELA) {
                    Elf64_Rela rela;
                    fseek(f, relsec->sh_offset + j * sizeof(Elf64_Rela), SEEK_SET);
                    if (fread(&rela, sizeof(rela), 1, f) != 1) continue;
                    
                    uint32_t sym_idx = ELF64_R_SYM(rela.r_info);
                    const char *name = (sym_idx < (symtab->sh_size / sizeof(Elf64_Sym)))
                                        ? &strdata[symdata[sym_idx].st_name] : "<unknown>";
                    fprintf(json_out, "\"offset\": \"0x%016" PRIx64 "\", \"symbol\": \"%s\", \"type\": %lu, \"addend\": %ld }",
                            rela.r_offset, name, ELF64_R_TYPE(rela.r_info), rela.r_addend);
                } else {
                    Elf64_Rel rel;
                    fseek(f, relsec->sh_offset + j * sizeof(Elf64_Rel), SEEK_SET);
                    if (fread(&rel, sizeof(rel), 1, f) != 1) continue;
                    
                    uint32_t sym_idx = ELF64_R_SYM(rel.r_info);
                    const char *name = (sym_idx < (symtab->sh_size / sizeof(Elf64_Sym)))
                                        ? &strdata[symdata[sym_idx].st_name] : "<unknown>";
                    fprintf(json_out, "\"offset\": \"0x%016" PRIx64 "\", \"symbol\": \"%s\", \"type\": %lu }",
                            rel.r_offset, name, ELF64_R_TYPE(rel.r_info));
                }
            }
            free(strdata);
            free(symdata);
            fseek(f, original_pos, SEEK_SET);
        }
        fprintf(json_out, "\n  ],\n");
    } else {
        // Console output
        printf("=== Relocations ===\n");
        for (int i = 0; i < ehdr->e_shnum; i++) {
            Elf64_Shdr *relsec = &shdrs[i];
            if (relsec->sh_type != SHT_RELA && relsec->sh_type != SHT_REL) continue;
            if (relsec->sh_link >= ehdr->e_shnum) continue;
            Elf64_Shdr *symtab = &shdrs[relsec->sh_link];
            if (symtab->sh_link >= ehdr->e_shnum) continue;
            Elf64_Shdr *strtab = &shdrs[symtab->sh_link];

            char *strdata = malloc(strtab->sh_size);
            Elf64_Sym *symdata = malloc(symtab->sh_size);
            if (!strdata || !symdata) {
                free(strdata); 
                free(symdata);
                continue;
            }
            
            long original_pos = ftell(f);
            fseek(f, strtab->sh_offset, SEEK_SET);
            if (fread(strdata, 1, strtab->sh_size, f) != strtab->sh_size) {
                free(strdata);
                free(symdata);
                continue;
            }
            fseek(f, symtab->sh_offset, SEEK_SET);
            if (fread(symdata, 1, symtab->sh_size, f) != symtab->sh_size) {
                free(strdata);
                free(symdata);
                continue;
            }

            size_t entry_size = (relsec->sh_type == SHT_RELA) ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
            size_t num = relsec->sh_size / entry_size;
            printf("Section: %s (%zu entries)\n", &shstrtab[relsec->sh_name], num);
            printf("%-18s | %-20s | %-8s | Addend\n", "Offset", "Symbol", "Type");

            for (size_t j = 0; j < num; j++) {
                if (relsec->sh_type == SHT_RELA) {
                    Elf64_Rela rela;
                    fseek(f, relsec->sh_offset + j * sizeof(Elf64_Rela), SEEK_SET);
                    if (fread(&rela, sizeof(rela), 1, f) != 1) continue;
                    
                    uint32_t sym_idx = ELF64_R_SYM(rela.r_info);
                    const char *name = (sym_idx < (symtab->sh_size / sizeof(Elf64_Sym)))
                                        ? &strdata[symdata[sym_idx].st_name] : "<unknown>";
                    printf("0x%016" PRIx64 " | %-20s | %-8lu | %ld\n",
                           rela.r_offset, name, ELF64_R_TYPE(rela.r_info), rela.r_addend);
                } else {
                    Elf64_Rel rel;
                    fseek(f, relsec->sh_offset + j * sizeof(Elf64_Rel), SEEK_SET);
                    if (fread(&rel, sizeof(rel), 1, f) != 1) continue;
                    
                    uint32_t sym_idx = ELF64_R_SYM(rel.r_info);
                    const char *name = (sym_idx < (symtab->sh_size / sizeof(Elf64_Sym)))
                                        ? &strdata[symdata[sym_idx].st_name] : "<unknown>";
                    printf("0x%016" PRIx64 " | %-20s | %-8lu | -\n",
                           rel.r_offset, name, ELF64_R_TYPE(rel.r_info));
                }
            }
            free(strdata);
            free(symdata);
            fseek(f, original_pos, SEEK_SET);
            printf("\n");
        }
    }
}
