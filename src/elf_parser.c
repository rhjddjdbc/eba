#include "h/elf_parser.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

static void trim_whitespace(char *str) {
    char *start = str;
    char *end;
    
    while(isspace((unsigned char)*start)) start++;
    
    if (*start == 0) {
        *str = 0;
        return;
    }
    
    end = start + strlen(start) - 1;
    while(end > start && isspace((unsigned char)*end)) end--;
    
    size_t len = end - start + 1;
    memmove(str, start, len);
    str[len] = '\0';
}

int load_config(const char *filename, AnalyzerConfig *cfg) {
    if (!filename || !cfg) return 0;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        if (!cfg->output_dir) {
            cfg->output_dir = strdup("output");
        }
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        
        if (line[0] == '\0' || line[0] == '#') continue;
        
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");
        
        if (!key || !value) continue;
        
        trim_whitespace(key);
        trim_whitespace(value);
        
        if (strcmp(key, "output_dir") == 0) {
            if (cfg->output_dir)
                free(cfg->output_dir);
            cfg->output_dir = strdup(value);
        }
    }
    
    fclose(fp);
    
    if (!cfg->output_dir) {
        cfg->output_dir = strdup("output");
    }
    
    return 1;
}

void print_usage(const char *progname) {
    printf("Usage: %s [options] <elf-file>\n", progname);
    printf("Options:\n");
    printf("  -h, --help          Show this help\n");
    printf("  -v, --version       Show version\n");
    printf("  -s, --strings       Show strings\n");
    printf("  -r, --reloc         Show relocations\n");
    printf("  -d, --disasm        Disassemble sections\n");
    printf("  -j, --json          Output results in JSON format\n");
    printf("  -o, --output DIR    Set output directory (default: output)\n");
    printf("  -e, --deps          Show shared library dependencies\n");
    printf("  -y, --symbols       Show symbols (first 100)\n");
    printf("  -p, --program       Show program headers\n");
    printf("  -x, --hexview SEC   Hexdump a section\n");
    printf("  -E, --sec-entropy   Show entropy per section\n");
    printf("  -H, --sec-headers   Show section headers table\n");
    printf("\nExamples:\n");
    printf("  %s --strings --reloc /bin/ls\n", progname);
    printf("  %s --deps --symbols /bin/ls\n", progname);
    printf("  %s --hexview .text /bin/ls\n", progname);
    printf("  %s --sec-entropy /bin/ls\n", progname);
    printf("  %s --sec-headers /bin/ls\n", progname);
    printf("  %s --disasm --json /bin/ls\n", progname);
}
