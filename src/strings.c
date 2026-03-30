#include "strings.h"
#include <ctype.h>
#include <string.h>
#include "common.h"

static void json_escape_string(FILE *out, const char *str) {
    if (!out || !str) return;
    
    fputc('"', out);
    while (*str) {
        switch (*str) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\b': fputs("\\b", out); break;
            case '\f': fputs("\\f", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if (*str < 0x20) {
                    fprintf(out, "\\u%04x", *str);
                } else {
                    fputc(*str, out);
                }
                break;
        }
        str++;
    }
    fputc('"', out);
}

void print_strings_and_heuristics(FILE *f, FILE *json_out) {
    if (!f) return;
    
    unsigned char buf[4096];
    char current[256] = {0};
    int len = 0, count = 0;
    long original_pos = ftell(f);

    fseek(f, 0, SEEK_SET);
    size_t bytes;

    if (json_out) {
        // JSON mode: collect strings into an array
        fprintf(json_out, "  \"strings\": [\n");
        int first = 1;
        while ((bytes = fread(buf, 1, sizeof(buf), f)) > 0 && count < 100) {
            for (size_t i = 0; i < bytes; i++) {
                if (isprint(buf[i]) || buf[i] == '\t') {
                    if (len < 254) current[len++] = buf[i];
                } else {
                    if (len >= 6) {
                        current[len] = '\0';
                        count++;
                        if (!first) fprintf(json_out, ",\n");
                        first = 0;
                        fprintf(json_out, "    {\"index\": %d, \"string\": ", count);
                        json_escape_string(json_out, current);
                        
                        int susp = (strstr(current, "system") || strstr(current, "exec") ||
                                    strstr(current, "shell") || strstr(current, "strcpy") ||
                                    strstr(current, "popen") || strstr(current, "/bin/sh") ||
                                    strstr(current, "malloc") || strstr(current, "__stack_chk_fail"));
                        if (susp) fprintf(json_out, ", \"suspicious\": true");
                        fprintf(json_out, "}");
                    }
                    len = 0;
                }
            }
        }
        fprintf(json_out, "\n  ],\n");
    } else {
        // Console mode
        printf("=== Strings + Suspicious Patterns ===\n");
        printf("%-4s | String\n", "No.");
        printf("-----------------------------------\n");
        while ((bytes = fread(buf, 1, sizeof(buf), f)) > 0 && count < 100) {
            for (size_t i = 0; i < bytes; i++) {
                if (isprint(buf[i]) || buf[i] == '\t') {
                    if (len < 254) current[len++] = buf[i];
                } else {
                    if (len >= 6) {
                        current[len] = '\0';
                        count++;
                        int susp = (strstr(current, "system") || strstr(current, "exec") ||
                                    strstr(current, "shell") || strstr(current, "strcpy") ||
                                    strstr(current, "popen") || strstr(current, "/bin/sh") ||
                                    strstr(current, "malloc") || strstr(current, "__stack_chk_fail"));
                        if (susp)
                            printf(YELLOW "%-4d | %s" RESET "\n", count, current);
                        else
                            printf("%-4d | %s\n", count, current);
                    }
                    len = 0;
                }
            }
        }
        printf("\n");
    }
    
    // Restore file position
    fseek(f, original_pos, SEEK_SET);
}
