#ifndef CFG_H
#define CFG_H

#include <capstone/capstone.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Control Flow Graph Edge 
typedef struct {
    uint64_t from;
    uint64_t to;
    char type[32];
} CFGEdge;

int get_config_bool(const char *filename, const char *key, int default_value);

size_t generate_cfg(cs_insn *insn, size_t count, CFGEdge **edges);

void cfg_export_dot(FILE *out, CFGEdge *edges, size_t edge_count);

void generate_cfg_legacy(cs_insn *insn, size_t count);

#endif
