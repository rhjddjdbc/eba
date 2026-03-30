#include "cfg.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <inttypes.h>

int get_config_bool(const char *filename, const char *key, int default_value)
{
    if (!filename || !key) return default_value;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) return default_value;
    
    char line[256];
    size_t key_len = strlen(key);
    int result = default_value;
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        
        if (line[0] == '\0' || line[0] == '#') continue;
        
        if (strncmp(line, key, key_len) == 0) {
            char *eq = strchr(line, '=');
            if (!eq) continue;
            char *val = eq + 1;
            while (*val == ' ' || *val == '\t') val++;
            
            for (char *p = val; *p; p++) *p = tolower(*p);
            if (strcmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcmp(val, "yes") == 0) {
                result = 1;
            } else if (strcmp(val, "false") == 0 || strcmp(val, "0") == 0 || strcmp(val, "no") == 0) {
                result = 0;
            }
            break;
        }
    }
    fclose(fp);
    return result;
}

static uint64_t parse_target(const char *op_str, uint64_t current_addr) {
    (void)current_addr; // not used in simple hex parsing
    if (!op_str) return 0;
    char *endptr;
    uint64_t target = strtoull(op_str, &endptr, 16);
    if (endptr != op_str) return target;
    return 0;
}

static void add_edge(CFGEdge **list, size_t *count, size_t *capacity,
                     uint64_t from, uint64_t to, const char *type) {
    if (to == 0) return;
    if (*count >= *capacity) {
        *capacity = (*capacity == 0) ? 64 : *capacity * 2;
        *list = realloc(*list, *capacity * sizeof(CFGEdge));
        if (!*list) {
            fprintf(stderr, "CFG: realloc failed\n");
            exit(EXIT_FAILURE);
        }
    }
    (*list)[*count].from = from;
    (*list)[*count].to = to;
    strncpy((*list)[*count].type, type, sizeof((*list)[0].type) - 1);
    (*list)[*count].type[sizeof((*list)[0].type) - 1] = '\0';
    (*count)++;
}

size_t generate_cfg(cs_insn *insn, size_t count, CFGEdge **edges) {
    if (!insn || count == 0 || !edges) return 0;
    
    *edges = NULL;
    size_t edge_count = 0;
    size_t capacity = 0;
    
    for (size_t i = 0; i < count; i++) {
        const char *mnemonic = insn[i].mnemonic;
        uint64_t from = insn[i].address;
        uint64_t fallthrough = (i + 1 < count && insn[i+1].address != 0) ? insn[i+1].address : 0;
        
        if (strcmp(mnemonic, "ret") == 0 || strcmp(mnemonic, "retq") == 0) {
            continue;
        }
        else if (strcmp(mnemonic, "jmp") == 0) {
            uint64_t target = parse_target(insn[i].op_str, from);
            if (target) add_edge(edges, &edge_count, &capacity, from, target, "jmp");
        }
        else if (strcmp(mnemonic, "call") == 0) {
            uint64_t target = parse_target(insn[i].op_str, from);
            if (target) add_edge(edges, &edge_count, &capacity, from, target, "call");
            if (fallthrough) add_edge(edges, &edge_count, &capacity, from, fallthrough, "fallthrough");
        }
        else if (mnemonic[0] == 'j' && strlen(mnemonic) > 1) {
            uint64_t target = parse_target(insn[i].op_str, from);
            if (target) add_edge(edges, &edge_count, &capacity, from, target, mnemonic);
            if (fallthrough) add_edge(edges, &edge_count, &capacity, from, fallthrough, "fallthrough");
        }
        else if (fallthrough) {
            add_edge(edges, &edge_count, &capacity, from, fallthrough, "sequential");
        }
    }
    return edge_count;
}

void cfg_export_dot(FILE *out, CFGEdge *edges, size_t edge_count) {
    if (!out || !edges) return;
    fprintf(out, "digraph CFG {\n");
    fprintf(out, "  node [shape=box, fontname=\"Courier\"];\n");
    fprintf(out, "  rankdir=TB;\n\n");
    for (size_t i = 0; i < edge_count; i++) {
        fprintf(out, "  \"0x%" PRIx64 "\" -> \"0x%" PRIx64 "\" [label=\"%s\"];\n",
                edges[i].from, edges[i].to, edges[i].type);
    }
    fprintf(out, "}\n");
}

void generate_cfg_legacy(cs_insn *insn, size_t count) {
    if (!insn || count == 0) return;
    printf("\n=== CFG (Control Flow) ===\n");
    for (size_t i = 0; i < count; i++) {
        const char *mnemonic = insn[i].mnemonic;
        if (strcmp(mnemonic, "jmp") == 0 ||
            strcmp(mnemonic, "call") == 0 ||
            (mnemonic[0] == 'j' && strlen(mnemonic) > 1)) {
            printf("0x%lx -> %s %s\n",
                   insn[i].address,
                   insn[i].mnemonic,
                   insn[i].op_str);
        }
    }
}
