#!/usr/bin/env python3
"""Read ELF identification and table metadata without executing the file."""

import argparse
from pathlib import Path
import stat
import struct
import sys


MAGIC = b"\x7fELF"
PN_XNUM = 0xFFFF
SHN_XINDEX = 0xFFFF
TYPE_NAMES = {0: "NONE", 1: "REL (relocatable)", 2: "EXEC (executable)", 3: "DYN (shared object or PIE)", 4: "CORE (core file)"}
MACHINE_NAMES = {
    2: "SPARC",
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
    258: "LoongArch",
}


class ElfError(ValueError):
    pass


def read_exact(stream, size, description):
    data = stream.read(size)
    if len(data) != size:
        raise ElfError(f"truncated {description}")
    return data


def inspect(path):
    source = Path(path)
    file_stat = source.stat()
    if not stat.S_ISREG(file_stat.st_mode):
        raise ElfError("input must be a regular file")

    with source.open("rb") as stream:
        ident = read_exact(stream, 16, "ELF identification")
        if ident[:4] != MAGIC:
            raise ElfError("invalid ELF magic")
        elf_class, data_encoding, ident_version = ident[4], ident[5], ident[6]
        if elf_class not in (1, 2) or data_encoding not in (1, 2) or ident_version != 1:
            raise ElfError("unsupported ELF class, byte order, or version")

        endian = "<" if data_encoding == 1 else ">"
        header_format = "HHIIIIIHHHHHH" if elf_class == 1 else "HHIQQQIHHHHHH"
        expected_header = 52 if elf_class == 1 else 64
        values = struct.unpack(endian + header_format, read_exact(stream, expected_header - 16, "ELF header"))
        (obj_type, machine, version, entry, phoff, shoff, flags, ehsize,
         phentsize, phnum, shentsize, shnum, shstrndx) = values
        if version != 1 or ehsize != expected_header:
            raise ElfError("unsupported ELF header size or version")
        ph_expected = 32 if elf_class == 1 else 56
        sh_expected = 40 if elf_class == 1 else 64

        extended_phnum = phnum == PN_XNUM
        extended_shnum = shnum == 0 and shoff != 0
        extended_shstrndx = shstrndx == SHN_XINDEX
        needs_section_zero = extended_phnum or extended_shnum or extended_shstrndx
        section_zero = None
        if needs_section_zero:
            if shoff == 0 or shentsize != sh_expected or shoff + shentsize > file_stat.st_size:
                raise ElfError("extended numbering requires a valid section header zero")
            stream.seek(shoff)
            section_format = "IIIIIIIIII" if elf_class == 1 else "IIQQQQIIQQ"
            section_zero = struct.unpack(endian + section_format, read_exact(stream, sh_expected, "section header zero"))

        if shnum == 0 and shoff != 0:
            shnum = section_zero[5]
            if shnum < 0xFF00:
                raise ElfError("extended section count is below the reserved range")
        if phnum == PN_XNUM:
            phnum = section_zero[7]
            if phnum < PN_XNUM:
                raise ElfError("extended program count is below PN_XNUM")
        if shstrndx == SHN_XINDEX:
            shstrndx = section_zero[6]
            if shstrndx < 0xFF00:
                raise ElfError("extended section-name index is below the reserved range")

        if phnum:
            if phoff == 0 or phentsize != ph_expected or phoff + phentsize * phnum > file_stat.st_size:
                raise ElfError("program header table is outside the file or has an invalid entry size")
        if shnum:
            if shoff == 0 or shentsize != sh_expected or shoff + shentsize * shnum > file_stat.st_size:
                raise ElfError("section header table is outside the file or has an invalid entry size")
            if shstrndx >= shnum and shstrndx != 0:
                raise ElfError("section-name table index is outside the section table")
        elif shoff != 0 or shstrndx != 0:
            raise ElfError("section table offset or name index is set but no entries are declared")

    return elf_class, "little-endian" if endian == "<" else "big-endian", obj_type, machine, entry, phnum, shnum, flags


def main():
    parser = argparse.ArgumentParser(description="Summarize an ELF header and table ranges without executing the file.")
    parser.add_argument("input", help="ELF object file")
    args = parser.parse_args()

    try:
        elf_class, byte_order, obj_type, machine, entry, phnum, shnum, flags = inspect(args.input)
    except ElfError as error:
        print(f"elf-glance: invalid or unsupported ELF: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"elf-glance: {error.strerror or 'unable to read input'}", file=sys.stderr)
        return 2

    print(f"Class: ELF{32 if elf_class == 1 else 64}")
    print(f"Byte order: {byte_order}")
    type_name = TYPE_NAMES.get(obj_type, f"0x{obj_type:04x}")
    machine_name = MACHINE_NAMES.get(machine, f"unknown ({machine})")
    print(f"Type: {type_name}")
    print(f"Machine: {machine_name}")
    print(f"Entry point: 0x{entry:x}")
    print(f"Program headers: {phnum}")
    print(f"Section headers: {shnum}")
    print(f"Machine flags: 0x{flags:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
