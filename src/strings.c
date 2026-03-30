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

typedef void (*string_callback_t)(int index, const char *str, int suspicious, void *userdata);

static void extract_strings(FILE *f, int max_strings, string_callback_t cb, void *userdata) {
    if (!f || !cb) return;
    unsigned char buf[BUFFER_SIZE];
    char current[MAX_STRING_LEN];
    int len = 0, count = 0;
    long original_pos = ftell(f);
    fseek(f, 0, SEEK_SET);
    size_t bytes;
    while ((bytes = fread(buf, 1, sizeof(buf), f)) > 0 && count < max_strings) {
        for (size_t i = 0; i < bytes; i++) {
            if (isprint(buf[i]) || buf[i] == '\t') {
                if (len < MAX_STRING_LEN - 1) current[len++] = buf[i];
            } else {
                if (len >= 6) {
                    current[len] = '\0';
                    count++;
                    int susp = (strstr(current, "system") || strstr(current, "exec") ||
                                strstr(current, "shell") || strstr(current, "strcpy") ||
                                strstr(current, "popen") || strstr(current, "/bin/sh") ||
                                strstr(current, "malloc") || strstr(current, "__stack_chk_fail"));
                    cb(count, current, susp, userdata);
                }
                len = 0;
            }
        }
    }
    fseek(f, original_pos, SEEK_SET);
}

static void json_callback(int idx, const char *str, int susp, void *userdata) {
    FILE *out = (FILE*)userdata;
    static int first = 1;
    if (!first) fprintf(out, ",\n");
    first = 0;
    fprintf(out, "    {\"index\": %d, \"string\": ", idx);
    json_escape_string(out, str);
    if (susp) fprintf(out, ", \"suspicious\": true");
    fprintf(out, "}");
}

static void console_callback(int idx, const char *str, int susp, void *userdata) {
    (void)userdata;
    if (susp)
        printf(YELLOW "%-4d | %s" RESET "\n", idx, str);
    else
        printf("%-4d | %s\n", idx, str);
}

void print_strings_and_heuristics(FILE *f, FILE *json_out) {
    if (!f) return;
    if (json_out) {
        fprintf(json_out, "  \"strings\": [\n");
        extract_strings(f, MAX_STRINGS, json_callback, json_out);
        fprintf(json_out, "\n  ],\n");
    } else {
        printf("=== Strings + Suspicious Patterns ===\n");
        printf("%-4s | String\n", "No.");
        printf("-----------------------------------\n");
        extract_strings(f, MAX_STRINGS, console_callback, NULL);
        printf("\n");
    }
}
