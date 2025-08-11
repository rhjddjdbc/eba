#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>

void print_section_headers(FILE *f, Elf64_Ehdr header) {
    Elf64_Shdr shdr;

    fseek(f, header.e_shoff + header.e_shentsize * header.e_shstrndx, SEEK_SET);
    fread(&shdr, 1, sizeof(shdr), f);

    char *shstrtab = malloc(shdr.sh_size);
    if (!shstrtab) {
        perror("malloc");
        return;
    }

    fseek(f, shdr.sh_offset, SEEK_SET);
    fread(shstrtab, 1, shdr.sh_size, f);

    fseek(f, header.e_shoff, SEEK_SET);
    for (int i = 0; i < header.e_shnum; i++) {
        fread(&shdr, 1, sizeof(shdr), f);
        printf("Section: %-20s | Type: %u | Addr: 0x%lx | Offset: 0x%lx | Size: 0x%lx\n",
               &shstrtab[shdr.sh_name], shdr.sh_type, shdr.sh_addr, shdr.sh_offset, shdr.sh_size);
    }

    free(shstrtab);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <elf-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    Elf64_Ehdr header;
    fread(&header, 1, sizeof(header), f);
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) {
        printf("Not a valid ELF file.\n");
        fclose(f);
        return 1;
    }

    printf("Entry point: 0x%lx\n", header.e_entry);
    printf("Machine: %d | Type: %d | Section count: %d\n", header.e_machine, header.e_type, header.e_shnum);
    printf("\n--- Sections ---\n");
    print_section_headers(f, header);
    fclose(f);
    return 0;
}
