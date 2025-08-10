#!/bin/bash

# Example: ./analyze.sh -f /bin/ls
# Simple ELF analysis script with interactive section hexdump
# Includes colored output for section flags

if [[ "$1" != "-f" || -z "$2" ]]; then
  echo "Usage: $0 -f <filename>"
  exit 1
fi

filename="$2"

echo "Analyzing $filename..."

# --- File Info (simplified) ---
file "$filename"

echo
echo "=== [*] ELF Header ==="
readelf -h "$filename"

echo

# Define colors (ANSI codes)
GREEN='\033[0;32m'    # A - green
RED='\033[0;31m'      # W - red
BLUE='\033[0;34m'     # X - blue
YELLOW='\033[0;33m'   # M - yellow
ORANGE='\033[38;5;208m' # S - orange (256 colors)
RESET='\033[0m'

# Function to color flags
color_flags() {
  local flags="$1"
  local out=""

  # Remove whitespace
  flags="${flags// /}"

  for (( i=0; i<${#flags}; i++ )); do
    f="${flags:i:1}"
    case "$f" in
      A) out+="${GREEN}A${RESET}" ;;
      W) out+="${RED}W${RESET}" ;;
      X) out+="${BLUE}X${RESET}" ;;
      M) out+="${YELLOW}M${RESET}" ;;
      S) out+="${ORANGE}S${RESET}" ;;
      *) out+="$f" ;;
    esac
  done

  echo -e "$out"
}

echo "--- Sections ---"
readelf -W -S "$filename"

echo
echo "=== [*] Strings (first 10) ==="
strings "$filename" | head -10

echo
echo "=== [*] Entropy ==="
entropy=$(python3 -c "
import sys, math
from collections import Counter

with open('$filename', 'rb') as f:
    data = f.read()
c = Counter(data)
entropy = -sum(freq/len(data)*math.log2(freq/len(data)) for freq in c.values())
print(entropy)
")
echo "$entropy"

echo
echo "=== [*] Symbol Table (first 40 entries) ==="
readelf -s "$filename" | head -40

echo
echo "=== [*] Heuristics (suspicious strings) ==="
grep -E 'malloc|free|system|exec|shell|strcpy' <(strings "$filename") | sort -u

echo
echo "=== [*] Disassembly (first 40 lines) ==="
objdump -d "$filename" | head -40

# Function to display a section using hexdump
show_section() {
  local file=$1
  local section_name=$2

  local info
  info=$(readelf -S -W "$file" | grep -w " $section_name ")
  if [ -z "$info" ]; then
    printf '\e[31mSection %s not found.\e[0m\n' "$section_name"
    return 1
  fi

  local offset_hex size_hex offset size
  offset_hex=$(echo "$info" | awk '{print $5}')
  size_hex=$(echo "$info" | awk '{print $6}')

  if [[ -z "$offset_hex" || -z "$size_hex" ]]; then
    printf '\e[31mError: Offset or size could not be determined.\e[0m\n'
    return 1
  fi

  offset=$((0x$offset_hex))
  size=$((0x$size_hex))

  # Colors
  local cyan='\e[36m'
  local green='\e[32m'
  local reset='\e[0m'

  printf "${cyan}=== Section ${green}%s${cyan} (Offset: 0x%s, Size: 0x%s) ===${reset}\n" "$section_name" "$offset_hex" "$size_hex"

  # Hexdump with color and less -R
  dd if="$file" bs=1 skip=$offset count=$size 2>/dev/null | hexdump -C | less -R

  echo
}

# Interactive section viewer
echo "=== [*] Section Viewer ==="
echo "Type section name to view hexdump, or 'q' to quit:"

while true; do
  read -rp "> " section_name
  [[ "$section_name" == "q" ]] && { echo "Exiting Section Viewer."; break; }

  if [[ -z "$section_name" ]]; then
    echo "Please enter a section name or 'q' to quit."
    continue
  fi

  show_section "$filename" "$section_name"
done
