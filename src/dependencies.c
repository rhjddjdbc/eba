#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*dep_callback_t)(const char *lib, void *userdata);

static void process_dependencies(ElfContext *ctx, dep_callback_t cb, void *userdata) {
    if (!ctx->dynstr) return;

    size_t str_size;
    char *dynstr = elf_read_strings(ctx, ctx->dynstr, &str_size);
    if (!dynstr) return;

    size_t dyn_size;
    Elf64_Dyn *dyns = elf_read_dynamic(ctx, &dyn_size);
    if (!dyns) {
        free(dynstr);
        return;
    }

    size_t num = dyn_size / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < num; i++) {
        if (dyns[i].d_tag == DT_NEEDED) {
            cb(&dynstr[dyns[i].d_un.d_val], userdata);
        }
    }
    free(dyns);
    free(dynstr);
}

static void json_dep_callback(const char *lib, void *userdata) {
    static int first = 1;
    FILE *out = (FILE*)userdata;
    if (!first) fprintf(out, ",\n");
    first = 0;
    fprintf(out, "    \"%s\"", lib);
}

static void console_dep_callback(const char *lib, void *userdata) {
    static int first = 1;
    if (first) {
        printf("=== Shared Library Dependencies ===\n");
        first = 0;
    }
    printf("  %s\n", lib);
}

void print_dependencies(ElfContext *ctx, FILE *json_out) {
    if (!ctx->dynstr) {
        if (json_out)
            fprintf(json_out, "  \"dependencies\": [],\n");
        else
            printf("=== Shared Library Dependencies ===\n(No dynamic section found)\n\n");
        return;
    }

    if (json_out) {
        fprintf(json_out, "  \"dependencies\": [\n");
        process_dependencies(ctx, json_dep_callback, json_out);
        fprintf(json_out, "\n  ],\n");
    } else {
        process_dependencies(ctx, console_dep_callback, NULL);
        printf("\n");
    }
}
