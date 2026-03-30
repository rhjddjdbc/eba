#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include "common.h"
#include "elf_context.h"

typedef struct {
    char *output_dir;
    int show_strings;
    int show_relocations;
    int show_disasm;
    int output_json;
    int full_disasm;
    int show_dependencies;
    int show_symbols;
    int show_program_headers;
    char *hex_section;
    int show_section_entropy;
    int show_section_headers;
} AnalyzerConfig;

int load_config(const char *filename, AnalyzerConfig *cfg);
void print_usage(const char *progname);

void print_dependencies(ElfContext *ctx, FILE *json_out);
void print_symbols(ElfContext *ctx, int limit, FILE *json_out);
void print_program_headers(ElfContext *ctx, FILE *json_out);
void hexview_section(ElfContext *ctx, const char *section_name);
void print_section_entropy(ElfContext *ctx, FILE *json_out);
void print_section_headers(ElfContext *ctx, FILE *json_out);

#endif
