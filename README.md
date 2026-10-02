# elf-glance

Read ELF32 or ELF64 identification data and check that declared program and section header tables fit inside a regular file. The tool never executes the file and does not read program or section contents.

## Use

Requires Python 3.8+; no packages to install.

```sh
python elf_glance.py /usr/bin/python3
```

The report includes class, byte order, object type, machine, entry point, table counts, and machine flags. Extended ELF table numbering is supported. This is a header and table-bounds reader, not a complete ELF validator or malware scanner. Exit status is 0 for a supported header, 1 for malformed or unsupported ELF, and 2 for unreadable input.

## License

MIT
