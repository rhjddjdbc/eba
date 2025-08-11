#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <math.h>

double shannon_entropy(unsigned char *data, size_t size) {
    if (size == 0) return 0.0;
    int counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / size;
        entropy -= p * log2(p);
    }
    return entropy;
}

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

    Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    fseek(f, ehdr.e_shoff, SEEK_SET);
    fread(shdrs, ehdr.e_shnum, sizeof(Elf64_Shdr), f);

    // Read section header string table
    Elf64_Shdr shstr = shdrs[ehdr.e_shstrndx];
    char *shstrtab = malloc(shstr.sh_size);
    fseek(f, shstr.sh_offset, SEEK_SET);
    fread(shstrtab, 1, shstr.sh_size, f);

    printf("Entropy per section:\n");
    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr *sec = &shdrs[i];
        if (sec->sh_size == 0) continue;

        unsigned char *buf = malloc(sec->sh_size);
        if (!buf) {
            perror("malloc");
            continue;
        }

        fseek(f, sec->sh_offset, SEEK_SET);
        fread(buf, 1, sec->sh_size, f);

        double entropy = shannon_entropy(buf, sec->sh_size);
        printf("  %-20s: %.4f\n", &shstrtab[sec->sh_name], entropy);

        free(buf);
    }

    free(shstrtab);
    free(shdrs);
    fclose(f);
    return 0;
}

