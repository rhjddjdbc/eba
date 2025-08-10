#include <stdio.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include <inttypes.h>

#define MAX_CODE_SIZE 65536

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    unsigned char *buffer = malloc(MAX_CODE_SIZE);
    fread(buffer, 1, MAX_CODE_SIZE, f);
    fclose(f);

    csh handle;
    cs_insn *insn;
    size_t count;eba — ELF Binaries Analyser

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    count = cs_disasm(handle, buffer, MAX_CODE_SIZE, 0x0, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < 20 && j < count; j++) {
            printf("0x%"PRIx64":\t%s\t\t%s\n",
                   insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    } else {
        printf("ERROR: Failed to disassemble\n");
    }

    cs_close(&handle);
    free(buffer);
    return 0;
}
