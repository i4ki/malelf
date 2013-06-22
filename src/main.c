/*
 * The malelf tool was written in pure C and developed using malelf library
 * to analyze (static/dynamic) malwares and infect ELF binaries. Evil using
 * this tool is the responsibility of the programmer.
 *
 * Author: Tiago Natel de Moura <tiago4orion@gmail.com>
 *
 * Contributor: Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *              Paulo Leonardo Benatto <benatto@gmail.com>
 *
 * Copyright 2012, 2013 by Tiago Natel de Moura. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <string.h>

#include <malelf/error.h>

#include "dissect.h"
#include "shellcode.h"
#include "util.h"

#define DISSECT "dissect"
#define SHELLCODE "shellcode"

static void _malelf_help()
{
        HELP("\n");
        HELP("Tool to infect and/or analyse ELF binary.\n");
        HELP("Usage: malelf <command> [-h] <options> \n");
        HELP("Commands:\n");
        HELP("         dissect \tShow ELF binary info. \n");
        HELP("         reverse_elf \tReverse the ELF binary image in the C structs representation.\n");
        HELP("         disas   \tDisassembly binary ELF in NASM compatible format.\n");
        HELP("         entry_point \tEntry point command. \n");
        HELP("         infect \tInfect the binary with a malware.\n");
        HELP("         shellcode \tcreate the virus shellcode in the proper format\n\
                       \tto use with the infect command.\n");
        HELP("         copy     \tCopy ELF binary.\n");
        HELP("         database \tDatabase manager.\n");
        HELP("         analyse \tStatically analyse the ELF binary for malwares.\n");
        HELP("         dynanalyse \tDinamically analyse the ELF binary for malwares.\n");
        HELP("\n");
        exit(MALELF_SUCCESS);
}

int main(int argc, char **argv)
{
        MalelfDissect dissect;

        if (argc == 1) {
                _malelf_help();
                return -1;
        }

        if (strncmp(argv[1], DISSECT, sizeof(DISSECT)) == 0) {
                malelf_dissect_init(&dissect, argc, argv);
                malelf_dissect_finish(&dissect);
        } else if (strncmp(argv[1],
                           SHELLCODE,
                           sizeof (SHELLCODE)) == 0) {
                malelf_shellcode_init(argc, argv);
                malelf_shellcode_finish();

        } else {
                _malelf_help();
        }

        return 0;
}
