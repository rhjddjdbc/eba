all:
	mkdir -p bin
	gcc -o bin/elf_info elf_info.c
	gcc -o bin/disasm disasm.c -lcapstone
