CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS =
LIBS =

HASH_LIBS = -lcrypto

BIN_DIR = bin

all: prepare_bin_dir entropy_sections list_dtneeded hash_sha256 disasm sections move_bins

prepare_bin_dir:
	mkdir -p $(BIN_DIR)

entropy_sections: entropy_sections.c
	$(CC) $(CFLAGS) -o $@ $^ -lm

list_dtneeded: list_dtneeded.c
	$(CC) $(CFLAGS) -o $@ $^

hash_sha256: hash_sha256.c
	$(CC) $(CFLAGS) -o $@ $^ $(HASH_LIBS)

disasm: disasm.c
	$(CC) $(CFLAGS) -o $@ $^ -lcapstone

sections: sections.c
	$(CC) $(CFLAGS) -o $@ $^

move_bins: entropy_sections list_dtneeded hash_sha256 disasm sections
	mv entropy_sections list_dtneeded hash_sha256 disasm sections $(BIN_DIR)/

clean:
	rm -rf $(BIN_DIR)
	rm -f entropy_sections list_dtneeded hash_sha256 disasm sections

.PHONY: all clean prepare_bin_dir move_bins
