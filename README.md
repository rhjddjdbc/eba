# eba — ELF Binaries Analyser

## Overview

**eba** is a lightweight shell script and C-based toolkit for analyzing ELF (Executable and Linkable Format) binaries on Linux. It provides comprehensive insights into ELF header information, section details, embedded strings, entropy analysis, symbol tables, disassembly, and more. The tool also includes an interactive hex viewer for ELF sections.

## Features

* Displays ELF header summary.
* Lists ELF sections with detailed information.
* Extracts and shows the first 10 printable strings.
* Calculates overall entropy of the binary.
* Calculates entropy for each section.
* Displays first 40 entries of the symbol table.
* Detects suspicious function names (e.g., malloc, system, strcpy) in strings.
* Shows disassembly of the first 20 instructions using Capstone.
* Lists shared library dependencies (DT\_NEEDED entries).
* Computes SHA256 hash of the binary.
* Interactive section viewer with colored hex dump output.

## Dependencies

* `bash`
* `readelf` (from binutils)
* `strings` (from binutils)
* `hexdump`
* `dd`
* `less`
* `python3` (used for entropy calculation in the script)
* `gcc` (for compiling helper C programs)
* `libcapstone` (for disassembly)
* `libcrypto` (OpenSSL, for SHA256 hashing)

### Installing on common distributions

* On Debian/Ubuntu:

```bash
sudo apt-get install build-essential binutils python3 libcapstone-dev libssl-dev less
```

* On Arch Linux:

```bash
sudo pacman -S base-devel binutils python less openssl capstone
```

## Building the tool

Run the following command to compile the helper binaries:

```bash
make
```

This will build the helper programs into the `bin/` directory.

## Usage

Make the main analysis script executable if not already:

```bash
chmod +x analyze.sh
```

Run the script with the ELF file to analyze:

```bash
./analyze.sh -f /path/to/elf_binary
```

The script outputs various analysis details and then enters an interactive mode where you can enter section names to view their hex dumps. Type `q` to quit the viewer.

## Project Structure

```
.
├── analyze.sh          # Main shell script to run the analysis
├── bin/                # Compiled helper binaries
│   ├── disasm          # Disassembler using Capstone
│   ├── entropy_sections # Entropy calculation per section
│   ├── hash_sha256     # SHA256 hash calculator
│   ├── list_dtneeded   # Lists shared library dependencies
│   └── sections        # Prints section headers
├── disasm.c            # Source code for disassembler
├── entropy_sections.c  # Source for entropy per section
├── hash_sha256.c       # Source for SHA256 hashing
├── list_dtneeded.c     # Source for shared library dependencies
├── sections.c          # Source for section headers
└── Makefile            # Build script
```

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See the `LICENSE` file for details.
