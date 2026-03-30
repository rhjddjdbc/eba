CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O2 -I./src/h
LDFLAGS = -lcapstone -lcrypto -lm
TARGET = eba
SOURCES = src/main.c src/cfg.c src/disassembly.c src/elf_context.c src/elf_parser.c \
          src/entropy.c src/relocations.c src/sha256.c src/strings.c \
          src/dependencies.c src/symbols.c src/program_headers.c src/hexview.c \
          src/section_entropy.c src/section_headers.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
