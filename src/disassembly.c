#include "disassembly.h"
#include "cfg.h"
#include <capstone/capstone.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <ctype.h>
#include <sys/stat.h>  

static void safe_strcpy(char *dest, const char *src, size_t dest_size) {
    if (!dest || dest_size == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

static void ensure_trailing_slash(char *path, size_t size) {
    size_t len = strlen(path);
    if (len > 0 && path[len-1] != '/' && len + 1 < size) {
        strcat(path, "/");
    }
}

static int create_dir_if_not_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 1;
        fprintf(stderr, "Error: %s exists but is not a directory\n", path);
        return 0;
    }
    if (mkdir(path, 0755) != 0) {
        fprintf(stderr, "Warning: Could not create directory %s: %s\n", path, strerror(errno));
        return 0;
    }
    return 1;
}

static char* lookup_func_name(ElfContext *ctx, uint64_t addr)
{
    if (!ctx || !ctx->symtab || !ctx->strtab) return NULL;
    
    size_t sym_count = ctx->symtab->sh_size / sizeof(Elf64_Sym);
    Elf64_Sym *syms = malloc(ctx->symtab->sh_size);
    char *strings = malloc(ctx->strtab->sh_size);
    if (!syms || !strings) {
        free(syms);
        free(strings);
        return NULL;
    }
    
    long original_pos = ftell(ctx->f);
    
    fseek(ctx->f, ctx->symtab->sh_offset, SEEK_SET);
    if (fread(syms, 1, ctx->symtab->sh_size, ctx->f) != ctx->symtab->sh_size) {
        free(syms);
        free(strings);
        fseek(ctx->f, original_pos, SEEK_SET);
        return NULL;
    }
    
    fseek(ctx->f, ctx->strtab->sh_offset, SEEK_SET);
    if (fread(strings, 1, ctx->strtab->sh_size, ctx->f) != ctx->strtab->sh_size) {
        free(syms);
        free(strings);
        fseek(ctx->f, original_pos, SEEK_SET);
        return NULL;
    }
    
    char *found = NULL;
    for (size_t i = 0; i < sym_count; i++) {
        if (ELF64_ST_TYPE(syms[i].st_info) == STT_FUNC &&
            syms[i].st_value == addr) {
            found = strdup(strings + syms[i].st_name);
            break;
        }
    }
    
    free(syms);
    free(strings);
    fseek(ctx->f, original_pos, SEEK_SET);
    return found;
}

static void write_insn(FILE *out, cs_insn *insn)
{
    if (!out || !insn) return;
    fprintf(out, "0x%016" PRIx64 ":\t%s\t%s\n",
            insn->address, insn->mnemonic, insn->op_str);
}

void disassemble_full_to_file(ElfContext *ctx, AnalyzerConfig *cfg, FILE *json_out)
{
    if (!ctx || !ctx->f || !cfg) return;
    
    char output_dir[4096];
    safe_strcpy(output_dir, cfg->output_dir, sizeof(output_dir));
    ensure_trailing_slash(output_dir, sizeof(output_dir));
    
    if (!create_dir_if_not_exists(output_dir)) {
        fprintf(stderr, "Cannot create output directory, using current directory\n");
        safe_strcpy(output_dir, "./", sizeof(output_dir));
    }
    
    char json_dir[4096];
    snprintf(json_dir, sizeof(json_dir), "%sjson", output_dir);
    create_dir_if_not_exists(json_dir);
    
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d_%H-%M-%S", tm_info);
    
    const char *name = strrchr(ctx->filename, '/');
    name = name ? name + 1 : ctx->filename;
    
    char clean_name[256];
    safe_strcpy(clean_name, name, sizeof(clean_name));
    
    char fullpath[4096];
    snprintf(fullpath, sizeof(fullpath), "%sfull_program.asm", output_dir);
    FILE *full_out = fopen(fullpath, "w");
    if (full_out) {
        fprintf(full_out, "; Full program disassembly of %s\n", ctx->filename);
        fprintf(full_out, "; Generated: %s\n\n", timestr);
    }
    
    if (json_out) {
        fprintf(json_out, " \"disassembly_sections\": [\n");
    }
    
    int any_section = 0;
    int first_sec_json = 1;
    int disasm_all = get_config_bool("config.ini", "disasm_all", 0);
    
    for (int i = 0; i < ctx->ehdr.e_shnum; i++) {
        Elf64_Shdr *sec = &ctx->shdrs[i];
        const char *secname = &ctx->shstrtab[sec->sh_name];
        if (sec->sh_size == 0 || sec->sh_addr == 0) continue;
        
        int do_disasm = disasm_all;
        if (!do_disasm) {
            if (strcmp(secname, ".init") == 0 && get_config_bool("config.ini", "disasm_init", 1)) do_disasm = 1;
            else if (strcmp(secname, ".fini") == 0 && get_config_bool("config.ini", "disasm_fini", 1)) do_disasm = 1;
            else if (strstr(secname, ".text") != NULL && get_config_bool("config.ini", "disasm_text", 1)) do_disasm = 1;
            else if (strstr(secname, ".plt") != NULL && get_config_bool("config.ini", "disasm_plt", 1)) do_disasm = 1;
            else if (strcmp(secname, ".got") == 0 && get_config_bool("config.ini", "disasm_got", 1)) do_disasm = 1;
            else if (strcmp(secname, ".rodata") == 0 && get_config_bool("config.ini", "disasm_rodata", 1)) do_disasm = 1;
            else if (strcmp(secname, ".data.rel.ro") == 0 && get_config_bool("config.ini", "disasm_data_rel_ro", 1)) do_disasm = 1;
            else if (strcmp(secname, ".eh_frame") == 0 && get_config_bool("config.ini", "disasm_eh_frame", 1)) do_disasm = 1;
            else if (strcmp(secname, ".init_array") == 0 && get_config_bool("config.ini", "disasm_init_array", 1)) do_disasm = 1;
            else if (strcmp(secname, ".fini_array") == 0 && get_config_bool("config.ini", "disasm_fini_array", 1)) do_disasm = 1;
        }
        if (!do_disasm) continue;
        
        printf("Disassembling: %s (%zu bytes)\n", secname, sec->sh_size);
        
        unsigned char *code = malloc(sec->sh_size);
        if (!code) {
            fprintf(stderr, "malloc failed for section %s\n", secname);
            continue;
        }
        
        long original_pos = ftell(ctx->f);
        fseek(ctx->f, sec->sh_offset, SEEK_SET);
        if (fread(code, 1, sec->sh_size, ctx->f) != sec->sh_size) {
            fprintf(stderr, "Failed to read section %s\n", secname);
            free(code);
            fseek(ctx->f, original_pos, SEEK_SET);
            continue;
        }
        
        csh handle;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            fprintf(stderr, "Capstone init failed for %s\n", secname);
            free(code);
            fseek(ctx->f, original_pos, SEEK_SET);
            continue;
        }
        
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
        
        cs_insn *insn;
        size_t count = cs_disasm(handle, code, sec->sh_size, sec->sh_addr, 0, &insn);
        if (count == 0) {
            fprintf(stderr, "No instructions disassembled in %s (possibly data section)\n", secname);
            cs_close(&handle);
            free(code);
            fseek(ctx->f, original_pos, SEEK_SET);
            continue;
        }
        
        any_section = 1;
        
        char sec_filename[256];
        if (secname[0] == '.') {
            safe_strcpy(sec_filename, secname + 1, sizeof(sec_filename));
        } else {
            safe_strcpy(sec_filename, secname, sizeof(sec_filename));
        }
        
        char secpath[4096];
        snprintf(secpath, sizeof(secpath), "%s%s.asm", output_dir, sec_filename);
        FILE *sec_out = fopen(secpath, "w");
        if (sec_out) {
            fprintf(sec_out, "; Section: %s\n; Address: 0x%" PRIx64 " - 0x%" PRIx64 "\n\n",
                    secname, sec->sh_addr, sec->sh_addr + sec->sh_size);
        }
        
        if (full_out) {
            fprintf(full_out, "\n\n;;; Section: %s ;;;\n;; Address: 0x%" PRIx64 "\n\n", secname, sec->sh_addr);
        }
        
        if (json_out) {
            if (!first_sec_json) fprintf(json_out, ",\n");
            first_sec_json = 0;
            fprintf(json_out, " { \"section\": \"%s\", \"address\": \"0x%" PRIx64 "\", \"size\": %zu, \"instructions\": %zu, \"file\": \"%s\"",
                    secname, sec->sh_addr, sec->sh_size, count, secpath);
            fprintf(json_out, ", \"functions\": [");
        }
        
        FILE *func_file = NULL;
        int func_id = 0;
        int first_func_json = 1;
        
        for (size_t j = 0; j < count; j++) {
            int is_start = 0;
            if (strcmp(insn[j].mnemonic, "push") == 0 && strstr(insn[j].op_str, "rbp"))
                is_start = 1;
            else if (strcmp(insn[j].mnemonic, "endbr64") == 0)
                is_start = 1;
            else if (strcmp(insn[j].mnemonic, "sub") == 0 && strstr(insn[j].op_str, "rsp"))
                is_start = 1;
            
            if (is_start) {
                if (func_file) fclose(func_file);
                char *fname = lookup_func_name(ctx, insn[j].address);
                char funcpath[4096];
                if (fname)
                    snprintf(funcpath, sizeof(funcpath), "%s%s_%s.asm", output_dir, sec_filename, fname);
                else
                    snprintf(funcpath, sizeof(funcpath), "%s%s_func_%d.asm", output_dir, sec_filename, func_id);
                func_file = fopen(funcpath, "w");
                if (func_file) {
                    fprintf(func_file, "; Function: %s (%s, 0x%" PRIx64 ")\n\n",
                            fname ? fname : "unknown", secname, insn[j].address);
                }
                if (json_out && func_file) {
                    if (!first_func_json) fprintf(json_out, ", ");
                    first_func_json = 0;
                    fprintf(json_out, "{\"index\": %d, \"name\": \"%s\", \"address\": \"0x%" PRIx64 "\", \"file\": \"%s\"}",
                            func_id, fname ? fname : "unknown", insn[j].address, funcpath);
                }
                if (fname) free(fname);
                func_id++;
            }
            
            if (sec_out) write_insn(sec_out, &insn[j]);
            if (func_file) write_insn(func_file, &insn[j]);
            if (full_out) write_insn(full_out, &insn[j]);
            
            if (strcmp(insn[j].mnemonic, "ret") == 0 ||
                strcmp(insn[j].mnemonic, "retq") == 0) {
                if (func_file) {
                    fclose(func_file);
                    func_file = NULL;
                }
            }
        }
        
        CFGEdge *edges = NULL;
        size_t edge_count = generate_cfg(insn, count, &edges);
        if (edge_count > 0) {
            char cfgpath[4096];
            snprintf(cfgpath, sizeof(cfgpath), "%s%s_cfg.dot", output_dir, sec_filename);
            FILE *cfg_out = fopen(cfgpath, "w");
            if (cfg_out) {
                cfg_export_dot(cfg_out, edges, edge_count);
                fclose(cfg_out);
                printf("  CFG saved to: %s\n", cfgpath);
            }
            free(edges);
        }
        
        if (func_file) fclose(func_file);
        if (sec_out) fclose(sec_out);
        if (json_out) fprintf(json_out, "] }");
        
        cs_free(insn, count);
        cs_close(&handle);
        free(code);
        fseek(ctx->f, original_pos, SEEK_SET);
    }
    
    if (json_out) fprintf(json_out, "\n ],\n");
    if (full_out) fclose(full_out);
    
    if (any_section) {
        printf(GREEN "Disassembly saved in: %s\n" RESET, output_dir);
    }
}
