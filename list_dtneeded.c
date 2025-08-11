#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <elf-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    Elf64_Ehdr ehdr;
    fread(&ehdr, 1, sizeof(ehdr), f);
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file.\n");
        fclose(f);
        return 1;
    }

    Elf64_Phdr *phdrs = malloc(ehdr.e_phnum * sizeof(Elf64_Phdr));
    if (!phdrs) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    fseek(f, ehdr.e_phoff, SEEK_SET);
    fread(phdrs, ehdr.e_phnum, sizeof(Elf64_Phdr), f);

    Elf64_Off dyn_offset = 0;
    Elf64_Xword dyn_size = 0;

    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_offset = phdrs[i].p_offset;
            dyn_size = phdrs[i].p_filesz;
            break;
        }
    }

    if (!dyn_offset) {
        fprintf(stderr, "No PT_DYNAMIC segment found.\n");
        free(phdrs);
        fclose(f);
        return 1;
    }

    Elf64_Dyn *dyns = malloc(dyn_size);
    fseek(f, dyn_offset, SEEK_SET);
    fread(dyns, 1, dyn_size, f);

    Elf64_Off strtab_offset = 0;
    Elf64_Xword strtab_size = 0;

    // Find DT_STRTAB and DT_STRSZ
    for (Elf64_Dyn *d = dyns; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_STRTAB) {
            // d->d_un.d_ptr is virtual addr, convert to file offset by searching segments
            Elf64_Addr strtab_vaddr = d->d_un.d_ptr;
            for (int i = 0; i < ehdr.e_phnum; i++) {
                if (phdrs[i].p_type == PT_LOAD &&
                    phdrs[i].p_vaddr <= strtab_vaddr &&
                    strtab_vaddr < phdrs[i].p_vaddr + phdrs[i].p_memsz) {
                    strtab_offset = phdrs[i].p_offset + (strtab_vaddr - phdrs[i].p_vaddr);
                    break;
                }
            }
        }
        if (d->d_tag == DT_STRSZ) {
            strtab_size = d->d_un.d_val;
        }
    }

    if (!strtab_offset || !strtab_size) {
        fprintf(stderr, "Failed to locate dynamic string table.\n");
        free(dyns);
        free(phdrs);
        fclose(f);
        return 1;
    }

    char *strtab = malloc(strtab_size);
    fseek(f, strtab_offset, SEEK_SET);
    fread(strtab, 1, strtab_size, f);

    printf("DT_NEEDED dependencies:\n");
    for (Elf64_Dyn *d = dyns; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_NEEDED) {
            printf("  %s\n", &strtab[d->d_un.d_val]);
        }
    }

    free(strtab);
    free(dyns);
    free(phdrs);
    fclose(f);
    return 0;
}
