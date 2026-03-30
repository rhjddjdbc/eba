#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>

typedef void (*phdr_callback_t)(const char *type_str, uint64_t vaddr, size_t memsz,
                                uint32_t flags, void *userdata);

static void process_program_headers(ElfContext *ctx, phdr_callback_t cb, void *userdata) {
    size_t count;
    Elf64_Phdr *phdrs = elf_read_program_headers(ctx, &count);
    if (!phdrs) return;

    for (size_t i = 0; i < count; i++) {
        const char *type_str = "UNKNOWN";
        switch (phdrs[i].p_type) {
            case PT_LOAD: type_str = "LOAD"; break;
            case PT_DYNAMIC: type_str = "DYNAMIC"; break;
            case PT_INTERP: type_str = "INTERP"; break;
            case PT_NOTE: type_str = "NOTE"; break;
            case PT_PHDR: type_str = "PHDR"; break;
            case PT_GNU_STACK: type_str = "GNU_STACK"; break;
            case PT_GNU_RELRO: type_str = "GNU_RELRO"; break;
        }
        cb(type_str, phdrs[i].p_vaddr, phdrs[i].p_memsz, phdrs[i].p_flags, userdata);
    }
    free(phdrs);
}

static void json_phdr_callback(const char *type, uint64_t vaddr, size_t memsz,
                               uint32_t flags, void *userdata) {
    static int first = 1;
    FILE *out = (FILE*)userdata;
    if (!first) fprintf(out, ",\n");
    first = 0;
    fprintf(out, "    { \"type\": \"%s\", \"vaddr\": \"0x%lx\", \"memsz\": %zu, \"flags\": %d }",
            type, vaddr, memsz, flags);
}

static void console_phdr_callback(const char *type, uint64_t vaddr, size_t memsz,
                                  uint32_t flags, void *userdata) {
    static int first = 1;
    if (first) {
        printf("%-12s %-18s %-12s %s\n", "Type", "Virtual Address", "Mem Size", "Flags");
        first = 0;
    }
    printf("%-12s 0x%016lx %-12zu 0x%x\n", type, vaddr, memsz, flags);
}

void print_program_headers(ElfContext *ctx, FILE *json_out) {
    if (json_out) {
        fprintf(json_out, "  \"program_headers\": [\n");
        process_program_headers(ctx, json_phdr_callback, json_out);
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Program Headers ===\n");
        process_program_headers(ctx, console_phdr_callback, NULL);
        printf("\n");
    }
}
