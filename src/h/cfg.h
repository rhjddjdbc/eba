#ifndef CFG_H
#define CFG_H

#include <capstone/capstone.h>
#include <stddef.h>

int get_config_bool(const char *filename, const char *key, int default_value);

void generate_cfg(cs_insn *insn, size_t count);

#endif
