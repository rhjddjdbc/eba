#ifndef DISASSEMBLY_H
#define DISASSEMBLY_H

#include "elf_parser.h"
#include "elf_context.h"
#include <stdio.h>

void disassemble_full_to_file(ElfContext *ctx, AnalyzerConfig *cfg, FILE *json_out);

#endif
