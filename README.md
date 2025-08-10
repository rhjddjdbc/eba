# eba — ELF Binaries Analyser

## Overview

**eba** is a lightweight shell script tool designed to analyze ELF (Executable and Linkable Format) binaries on Linux systems. It provides detailed information about ELF headers, sections, symbols, strings, entropy, and disassembly. Additionally, it features an interactive section viewer with a colored hex dump output.

## Features

- Displays ELF header details using `readelf`.
- Lists sections with their flags.
- Shows first 10 printable strings inside the binary.
- Calculates the entropy of the binary to estimate randomness.
- Displays the first 40 entries of the symbol table.
- Lists suspicious function names (e.g., `malloc`, `system`, `strcpy`) found in strings.
- Shows first 40 lines of disassembly using `objdump`.
- Interactive viewer to display hex dumps of selected ELF sections with color-coded output.

## Dependencies

- `bash`
- `readelf` (from `binutils`)
- `objdump` (from `binutils`)
- `strings` (from `binutils`)
- `hexdump`
- `python3` (for entropy calculation)
- `dd`
- `less`

### Arch Linux

Install dependencies via pacman:

```bash
sudo pacman -S binutils python less coreutils
````

## Build

To compile the helper binaries (`disasm` and `elf_info`), simply run:

```bash
make
```

This will build the binaries inside the `bin/` directory.

## Usage

First, make the analysis script executable (if not already):

```bash
chmod +x analyze.sh
```

Then run the script with:

```bash
./analyze.sh -f <path_to_elf_binary>
```

Example:

```bash
./analyze.sh -f /bin/ls
```

## Interactive Section Viewer

After the initial analysis, the script prompts you to enter a section name to display its hex dump. Enter the section name (e.g., `.text`, `.data`) and press Enter. Type `q` to quit the viewer.

## Project Structure

```
.
├── analyze.sh        # Main analysis script
├── bin               # Compiled helper binaries (disassembler, elf info)
│   ├── disasm
│   └── elf_info
├── disasm.c          # C source for disassembler binary
├── elf_info.c        # C source for elf info binary
└── Makefile          # Build script
```

## License

eba is licensed under the **GNU General Public License v3.0** (GPL‑3.0). See the `LICENSE` file for details.
