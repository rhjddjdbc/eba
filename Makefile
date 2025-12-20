CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS =
LIBS =

HASH_LIBS = -lcrypto
CAPSTONE_LIBS = -lcapstone
MATH_LIBS = -lm

BIN_DIR = bin
SOURCES = entropy_sections.c list_dtneeded.c hash_sha256.c disasm.c sections.c
TARGETS = $(BIN_DIR)/entropy_sections \
          $(BIN_DIR)/list_dtneeded \
          $(BIN_DIR)/hash_sha256 \
          $(BIN_DIR)/disasm \
          $(BIN_DIR)/sections

all: $(BIN_DIR) $(TARGETS)

$(BIN_DIR):
	mkdir -p $@

$(BIN_DIR)/entropy_sections: entropy_sections.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(MATH_LIBS)

$(BIN_DIR)/list_dtneeded: list_dtneeded.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BIN_DIR)/hash_sha256: hash_sha256.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(HASH_LIBS)

$(BIN_DIR)/disasm: disasm.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(CAPSTONE_LIBS)

$(BIN_DIR)/sections: sections.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean
