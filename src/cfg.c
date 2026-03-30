#include "cfg.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int get_config_bool(const char *filename, const char *key, int default_value)
{
    if (!filename || !key) return default_value;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) return default_value;

    char line[256];
    size_t key_len = strlen(key);

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        
        if (line[0] == '\0' || line[0] == '#') continue;
        
        if (strncmp(line, key, key_len) == 0) {
            char *eq = strchr(line, '=');
            if (!eq) continue;

            char *val = eq + 1;
            while (*val == ' ' || *val == '\t') val++;
            
            // Convert to lowercase for comparison
            for (char *p = val; *p; p++) *p = tolower(*p);

            if (strcmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcmp(val, "yes") == 0) {
                fclose(fp);
                return 1;
            }
            if (strcmp(val, "false") == 0 || strcmp(val, "0") == 0 || strcmp(val, "no") == 0) {
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    return default_value;
}

void generate_cfg(cs_insn *insn, size_t count)
{
    if (!insn || count == 0) return;
    
    printf("\n=== CFG (Control Flow) ===\n");
    for (size_t i = 0; i < count; i++) {
        if (strcmp(insn[i].mnemonic, "jmp") == 0 ||
            strcmp(insn[i].mnemonic, "call") == 0 ||
            strstr(insn[i].mnemonic, "j")) {
            printf("0x%lx -> %s %s\n",
                   insn[i].address,
                   insn[i].mnemonic,
                   insn[i].op_str);
        }
    }
}
