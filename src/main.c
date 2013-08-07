/*
 * The malelf tool was written in pure C and developed using malelf library
 * to analyse (static/dynamic) malwares and infect ELF binaries. Evil using
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
#include "disas.h"
#include "database.h"
#include "analyse.h"
#include "infect.h"
#include "dynamic_analysis.h"

#define DISSECT          "dissect"
#define SHELLCODE        "shellcode"
#define INFECT           "infect"
#define DYNAMIC_ANALYSIS "dynanalyse"
#define DISAS            "disas"
#define DATABASE         "database"
#define ANALYSE          "analyse"

static void _malelf_help()
{
        HELP("\n");
        HELP("Tool to infect and/or analyse ELF binary.\n");
        HELP("Usage: malelf <command> [-h] <options> \n");
        HELP("Commands:\n");
        HELP("         dissect \tShow ELF binary info. \n");
        HELP("         disas   \tDisassembly binary ELF in NASM compatible format.\n");
        HELP("         infect \tInfect the binary with a malware.\n");
        HELP("         shellcode \tcreate the virus shellcode in the proper format\n\
                       \tto use with the infect command.\n");
        HELP("         dynanalyse \tDinamically analyse the ELF binary for malwares.\n");
        HELP("         database \tStores ELF binary info in a database.\n");
        HELP("         analyse \tAnalyse ELF binary info in a database.\n");
        HELP("\n");
        exit(MALELF_SUCCESS);
}

int main(int argc, char **argv)
{
        MalelfDissect dissect;
        MalelfInfect infect;
        Disas disas;
        Database database;
        Analyse analyse;

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
        } else if (strncmp(argv[1], INFECT, sizeof(INFECT)) == 0) {
                malelf_infect_init(&infect, argc, argv);
                malelf_infect_finish(&infect);
        } else if (strncmp(argv[1], DYNAMIC_ANALYSIS, sizeof(DYNAMIC_ANALYSIS)) == 0) {
                malelf_dynanalyse_init(argc, argv);
                malelf_dynanalyse_finish();
        } else if (strncmp(argv[1], DISAS, sizeof(DISAS)) == 0) {
                disas_init(&disas, argc, argv);
                disas_finish(&disas);
        } else if (strncmp(argv[1], DATABASE, sizeof(DATABASE)) == 0) {
                database_init(&database, argc, argv);
                database_finish(&database);
        } else if (strncmp(argv[1], ANALYSE, sizeof(ANALYSE)) == 0) {
                analyse_init(&analyse, argc, argv);
                analyse_finish(&analyse);
        } else {
                _malelf_help();
        }

        return 0;
}
