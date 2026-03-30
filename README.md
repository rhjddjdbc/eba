# ELF Binary Analyzer

A comprehensive, all‑in‑one command‑line tool for analyzing ELF (Executable and Linkable Format) binaries. It extracts security‑relevant information, performs heuristic checks, and generates disassembly output – all with optional JSON export for further processing.

## Features

- **File Hashing:** SHA‑256 checksum of the whole file.
- **Entropy Analysis:** Global entropy and per‑section Shannon entropy.
- **Section Headers:** Full table with type, address, offset, and size.
- **Program Headers:** Detailed information about segments.
- **Strings & Heuristics:** Extracts printable strings and marks suspicious patterns (e.g., `malloc`, `system`, `strcpy`).
- **Relocations:** Lists all dynamic relocations (`.rela.dyn`).
- **Symbol Table:** Shows function and object symbols (first 100 by default).
- **Shared Library Dependencies:** Displays `DT_NEEDED` libraries.
- **Disassembly:** Full disassembly of selected sections (e.g., `.text`, `.plt`) using Capstone. Automatically splits output into per‑function files.
- **Section Hex Viewer:** Dumps any section in hex format.
- **JSON Output:** All analysis results can be saved as structured JSON for integration with other tools.
- **Configurable:** A `config.ini` file lets you enable/disable specific sections for disassembly.

## Build & Dependencies

### Prerequisites

- **GCC** (or any C99‑compatible compiler)
- **Capstone** (disassembly engine) – install via your package manager, e.g.  
  `sudo apt install libcapstone-dev` (Debian/Ubuntu)  
  `sudo dnf install capstone-devel` (Fedora)
- **OpenSSL** (for SHA‑256) – `libssl-dev` on Debian, `openssl-devel` on Fedora
- **GNU Make**

### Build

```bash
git clone https://github.com/yourusername/elf-analyzer.git
cd elf-analyzer
make
```

The executable `eba` will be placed in the current directory.

## Usage

```
./eba [options] <elf-file>
```

### Options

| Short | Long          | Description                               |
|-------|---------------|-------------------------------------------|
| `-h`  | `--help`      | Show help message                         |
| `-v`  | `--version`   | Show version information                  |
| `-s`  | `--strings`   | Extract strings and heuristics            |
| `-r`  | `--reloc`     | Show relocations                          |
| `-d`  | `--disasm`    | Disassemble sections (configurable)       |
| `-j`  | `--json`      | Write output as JSON (into timestamped dir) |
| `-o`  | `--output`    | Set output directory (default: `output`)  |
| `-e`  | `--deps`      | Show shared library dependencies          |
| `-y`  | `--symbols`   | Show symbol table (first 100)             |
| `-p`  | `--program`   | Show program headers                      |
| `-x`  | `--hexview`   | Hex‑dump a section (e.g., `.text`)        |
| `-E`  | `--sec-entropy`| Show entropy per section                  |
| `-H`  | `--sec-headers`| Show section headers table                |

### Examples

```bash
# Basic analysis (strings + relocations)
./eba --strings --reloc /bin/ls

# Full analysis with JSON export
./eba --strings --reloc --disasm --deps --symbols --program \
      --sec-entropy --sec-headers --json /bin/ls

# Only dependencies
./eba --deps /bin/ls

# Hex view of .text section
./eba --hexview .text /bin/ls
```

## Configuration

The file `config.ini` (placed in the working directory) controls which sections are disassembled. Example:

```ini
# Output directory for all analysis files
output_dir = output

# Disassembly options (true/false)
disasm_all = false
disasm_text = true
disasm_plt = true
disasm_init = true
disasm_fini = true
disasm_got = true
disasm_rodata = true
disasm_eh_frame = true
disasm_init_array = true
disasm_fini_array = true
```

## Output Structure

When `--json` is used, all output is stored under `output/<binary>_<timestamp>/`. The directory layout is:

```
output/
└── ls_2026-03-30_11-26-52/
    ├── json/
    │   └── analysis.json          # Complete JSON report
    ├── full_program.asm           # Concatenated disassembly of all sections
    ├── text.asm                   # Disassembly of .text section
    ├── plt.asm                    # Disassembly of .plt section
    ├── init.asm
    ├── fini.asm
    ├── text_func_0.asm            # Individual functions (detected by prologues)
    ├── text_func_1.asm
    └── ...
```

Without `--json`, results are printed to standard output.

## License

This project is released under the **GNU General Public License v3.0**. See the [LICENSE](LICENSE) file for details.
