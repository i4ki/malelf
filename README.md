malelf
======

Malelficus program to dissect and infect ELF binaries.

With malelf you can:
    * infect/backdoorize ELF binaries;
    * dissect ELF data structures;
    * Report ELF data structures in text or xml;
    * Disassembly sections;
    * Create payloads/shellcode to malwares;
    * Dynamic analysis (experimental)

The malelf tool is part of malelficus project and is under active
development. The libmalelf and malelf is far from complete but the
basic features are already working as expected.

*We are not responsible for any damage caused by using this tool. It was created with the sole purpose of research. It's a proof of concept that unix systems can also be the target of malware.*

Dependencies
=============

malelf depends solely of the libmalelf. If you haven't installed it in
your system, go to the github libmalelf page and install it.

    https://github.com/SecPlus/libmalelf


Building and Installing
========================

The tool is written in pure C, so the build process is very simple.

First, get the source:
    $ git clone https://github.com/SecPlus/malelf.git

Then build:

    $ ./configure --prefix=/usr
    $ make

Install (are you sure ? =P)
    $ sudo make install


Usage
=======

    $ malelf

    Tool to infect and/or analyse ELF binary.
    Usage: malelf <command> [-h] <options>
    Commands:
    dissect 	Show ELF binary info.
    disas   	Disassembly binary ELF in NASM compatible format.
    infect 	Infect the binary with a malware.
    shellcode 	create the virus shellcode in the proper format
    to use with the infect command.
    dynanalyse 	Dinamically analyse the ELF binary for malwares.

For each malelf command has a -h/--help option for more details of usage.
The dissect ELF header of /bin/bash use:

    $ malelf dissect -h
    This command display information about the ELF binary.
    Usage: malelf dissect <options>
    -h, --help    	Dissect Help
    -i, --input   	Binary File
    -e, --ehdr    	Display ELF Header
    -s, --shdr    	Display Section Header Table
    -p, --phdr    	Display Program Header Table
    -S, --stable  	Display Symbol Table
    -f, --format  	Output Format (XML or Stdout). Default is Stdout.
    -o, --output  	Output File.
    Example: malelf dissect -i /bin/ls -f xml -o /tmp/binary.xml

    $ malelf dissect -i /bin/bash --ehdr
    +-----------------------------------------------------------------------------+
    |                                  ELF Header                                 |
    +------------------------+------------------------------+---------------------+
    |   Structure Member     |         Description          |        Value        |
    +------------------------+------------------------------+---------------------+
    |        e_type          |         Object Type          |   Executable file   |
    |       e_version        |           Version            |          1          |
    |        e_entry         |         Entry Point          |     0x08064678      |
    |        e_phoff         |         PHT Offset           |     0x00000034      |
    |        e_shoff         |         SHT Offset           |     0x000e5864      |
    |       e_ehsize         |       ELF Header Size        |         52          |
    |      e_phentsize       |     Size of PHT entries      |         32          |
    |        e_phnum         |    Number of PHT entries     |          9          |
    |      e_shentsize       |  Size of one entry in SHT    |         40          |
    |        e_shnum         |     Number of sections       |         28          |
    |      e_shstrndx        |      SHT symbol index        |         27          |
    +------------------------+------------------------------+---------------------+
