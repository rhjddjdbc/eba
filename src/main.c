#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "h/elf_parser.h"
#include "h/elf_context.h"
#include "h/sha256.h"
#include "h/entropy.h"
#include "h/strings.h"
#include "h/relocations.h"
#include "h/disassembly.h"

#define VERSION "1.0.1"

static void print_version(void) {
    printf("ELF Binary Analyzer v%s\n", VERSION);
}

static void handle_error(const char *msg, int fatal) {
    fprintf(stderr, RED "Error: %s\n" RESET, msg);
    if (fatal) exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    AnalyzerConfig cfg = {0};

    static struct option long_options[] = {
        {"help",         no_argument,       0, 'h'},
        {"version",      no_argument,       0, 'v'},
        {"strings",      no_argument,       0, 's'},
        {"reloc",        no_argument,       0, 'r'},
        {"disasm",       no_argument,       0, 'd'},
        {"json",         no_argument,       0, 'j'},
        {"output",       required_argument, 0, 'o'},
        {"deps",         no_argument,       0, 'e'},
        {"symbols",      no_argument,       0, 'y'},
        {"program",      no_argument,       0, 'p'},
        {"hexview",      required_argument, 0, 'x'},
        {"sec-entropy",  no_argument,       0, 'E'},
        {"sec-headers",  no_argument,       0, 'H'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hsrdjvo:eypx:EH", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            case 's':
                cfg.show_strings = 1;
                break;
            case 'r':
                cfg.show_relocations = 1;
                break;
            case 'd':
                cfg.show_disasm = 1;
                break;
            case 'j':
                cfg.output_json = 1;
                break;
            case 'o':
                if (cfg.output_dir)
                    free(cfg.output_dir);
                cfg.output_dir = strdup(optarg);
                break;
            case 'e':
                cfg.show_dependencies = 1;
                break;
            case 'y':
                cfg.show_symbols = 1;
                break;
            case 'p':
                cfg.show_program_headers = 1;
                break;
            case 'x':
                cfg.hex_section = strdup(optarg);
                break;
            case 'E':
                cfg.show_section_entropy = 1;
                break;
            case 'H':
                cfg.show_section_headers = 1;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, RED "Error: No ELF file given.\n" RESET);
        print_usage(argv[0]);
        return 1;
    }

    const char *filename = argv[optind];

    FILE *test_f = fopen(filename, "rb");
    if (!test_f) {
        handle_error("Cannot open file", 1);
    }
    fclose(test_f);

    ElfContext ctx;
    if (init_elf_context(&ctx, filename) != 0) {
        free(cfg.output_dir);
        if (cfg.hex_section) free(cfg.hex_section);
        handle_error("Failed to initialize ELF context", 1);
    }

    if (cfg.hex_section) {
        hexview_section(&ctx, cfg.hex_section);
        free_elf_context(&ctx);
        free(cfg.output_dir);
        free(cfg.hex_section);
        return 0;
    }

    load_config("config.ini", &cfg);

    if (!cfg.output_dir)
        cfg.output_dir = strdup("output");

    FILE *json_out = NULL;
    char output_dir[MAX_PATH_LEN] = {0};
    char json_dir[MAX_PATH_LEN] = {0};

    if (cfg.output_json) {
        time_t t = time(NULL);
        struct tm *tm_info = localtime(&t);
        char timestr[64];
        strftime(timestr, sizeof(timestr), "%Y-%m-%d_%H-%M-%S", tm_info);

        const char *name = strrchr(filename, '/');
        name = name ? name + 1 : filename;

        char clean_name[256];
        strncpy(clean_name, name, sizeof(clean_name) - 1);
        clean_name[sizeof(clean_name) - 1] = '\0';

        char base_dir[MAX_PATH_LEN];
        strncpy(base_dir, cfg.output_dir, sizeof(base_dir) - 1);
        base_dir[sizeof(base_dir) - 1] = '\0';

        size_t len = strlen(base_dir);
        if (len > 0 && base_dir[len-1] != '/') {
            strncat(base_dir, "/", sizeof(base_dir) - len - 1);
        }

        mkdir(base_dir, 0755);
        snprintf(output_dir, sizeof(output_dir), "%s%s_%s", base_dir, clean_name, timestr);
        mkdir(output_dir, 0755);

        snprintf(json_dir, sizeof(json_dir), "%s/json", output_dir);
        mkdir(json_dir, 0755);

        char json_path[MAX_PATH_LEN];
        snprintf(json_path, sizeof(json_path), "%s/analysis.json", json_dir);
        json_out = fopen(json_path, "w");
        if (!json_out) {
            fprintf(stderr, YELLOW "Warning: Could not create JSON file, using stdout\n" RESET);
            json_out = stdout;
        } else {
            fprintf(json_out, "{\n");
            fprintf(json_out, "  \"file\": \"%s\",\n", filename);
            fprintf(json_out, "  \"entry_point\": \"0x%" PRIx64 "\",\n", ctx.ehdr.e_entry);
            fprintf(json_out, "  \"analyzer_version\": \"%s\",\n", VERSION);
            fprintf(json_out, "  \"timestamp\": \"%s\",\n", timestr);
        }
    } else {
        printf(CYAN "=== ELF Binary Analyzer v%s ===\n" RESET, VERSION);
        printf("File        : %s\n", filename);
        printf("Entry Point : 0x%" PRIx64 "\n", ctx.ehdr.e_entry);
        printf("Machine     : ");
        switch(ctx.ehdr.e_machine) {
            case EM_X86_64: printf("x86-64\n"); break;
            case EM_386: printf("Intel 80386\n"); break;
            case EM_ARM: printf("ARM\n"); break;
            case EM_AARCH64: printf("AArch64\n"); break;
            default: printf("Unknown (0x%x)\n", ctx.ehdr.e_machine);
        }
        printf("Type        : ");
        switch(ctx.ehdr.e_type) {
            case ET_EXEC: printf("Executable\n"); break;
            case ET_DYN: printf("Shared object\n"); break;
            case ET_REL: printf("Relocatable\n"); break;
            default: printf("Unknown (0x%x)\n", ctx.ehdr.e_type);
        }
        printf("Section cnt : %d\n", ctx.ehdr.e_shnum);
        printf("Program cnt : %d\n\n", ctx.ehdr.e_phnum);
    }

    // SHA256
    char hash[65] = {0};
    sha256_string(ctx.f, hash);
    if (json_out)
        fprintf(json_out, "  \"sha256\": \"%s\",\n", hash);
    else
        printf("SHA256      : %s\n", hash);

    double ent = calculate_total_entropy(ctx.f);
    if (json_out)
        fprintf(json_out, "  \"entropy\": %.6f,\n", ent);
    else
        printf("Total Entropy : %.4f\n\n", ent);

    if (cfg.show_section_entropy)
        print_section_entropy(&ctx, json_out);
    if (cfg.show_section_headers)
        print_section_headers(&ctx, json_out);
    if (cfg.show_strings)
        print_strings_and_heuristics(ctx.f, json_out);
    if (cfg.show_relocations)
        print_relocations(ctx.f, &ctx.ehdr, ctx.shdrs, ctx.shstrtab, json_out);
    if (cfg.show_dependencies)
        print_dependencies(&ctx, json_out);
    if (cfg.show_symbols)
        print_symbols(&ctx, MAX_SYMBOLS, json_out);
    if (cfg.show_program_headers)
        print_program_headers(&ctx, json_out);

    if (cfg.show_disasm) {
        char *old_output_dir = cfg.output_dir;
        if (output_dir[0] != '\0') {
            cfg.output_dir = output_dir;
        }
        disassemble_full_to_file(&ctx, &cfg, json_out);
        if (output_dir[0] != '\0') {
            cfg.output_dir = old_output_dir;
        }
    }

    if (json_out) {
        fprintf(json_out, "  \"status\": \"completed\"\n}\n");
        if (json_out != stdout) {
            fclose(json_out);
            printf(GREEN "JSON output saved to: %s/analysis.json\n" RESET, json_dir);
        }
    }

    free_elf_context(&ctx);
    free(cfg.output_dir);
    if (cfg.hex_section) free(cfg.hex_section);

    if (!json_out)
        printf(CYAN "\nAnalysis finished.\n" RESET);

    return 0;
}
