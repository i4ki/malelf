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
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>

#include <assert.h>

/* Libmalelf */
#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/binary.h>

/* Malelf */
#include "util.h"
#include "shellcode.h"

static ShellcodeOptions sh_config;

void malelf_shellcode_help(void)
{
  HELP("\n");
  HELP("This command create the virus shellcode in the proper "
       "format for use with the infect command.");
  HELP("Usage: malelf shellcode <options>\n");
  HELP("         -h, --help    \tThis Help\n");
  HELP("         -i, --input   \tShellcode flat binary input\n");
  HELP("         -f, --format  \tOutput Format (C-string or malelf). Default is malelf.\n");
  HELP("         -o, --output  \tOutput Shellcode file.\n");
  HELP("Example: malelf shellcode -i ./malware.bin -f malelf -o ./malware_ready.bin\n");
  HELP("\n");
  exit(MALELF_SUCCESS);
}

_u32 _malelf_shellcode_set_output_format(char *format)
{
        _u32 error = MALELF_SUCCESS;

        if (NULL == format) {
                return MALELF_ERROR;
        }

        if (0 == strncmp(format, "malelf", 6)) {
                sh_config.format = SHELLCODE_FMT_DEFAULT;
        } else if (0 == strncmp(format, "c-string", 8)) {
                sh_config.format = SHELLCODE_FMT_CSTRING;
        } else {
                sh_config.format = SHELLCODE_FMT_UNKNOWN;
                error = MALELF_ERROR;
        }

        return error;
}

_u32 _malelf_shellcode(ShellcodeOptions *config)
{
        MalelfBinary input_shellcode;
        MalelfBinary output_shellcode;
        _u32 error;

        assert(config->ifname != NULL &&
               config->ofname != NULL &&
               config->format != SHELLCODE_FMT_UNKNOWN);

        malelf_binary_init(&input_shellcode);
        malelf_binary_init(&output_shellcode);

        input_shellcode.class = MALELF_FLATUNKNOWN;
        output_shellcode.class = MALELF_FLATUNKNOWN;

        error = malelf_binary_open(config->ifname, &input_shellcode);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return error;
        }

        return MALELF_SUCCESS;
}

static _u32 _malelf_shellcode_handle_options(int option)
{
        static _u8 error = MALELF_SUCCESS;

        switch (option) {
        case SHELLCODE_HELP:
                malelf_shellcode_help();
                break;
        case SHELLCODE_FORMAT:
                error = _malelf_shellcode_set_output_format(optarg);
                break;
        case SHELLCODE_BINARY:
                sh_config.ifname = optarg;
                break;
        case SHELLCODE_FILE:
                sh_config.ofname = optarg;
                break;
        case ':':
                printf("Unknown option character '%s'.\n", optarg);
                break;
        case SHELLCODE_UNKNOWN:
                malelf_shellcode_help();
                error = MALELF_ERROR;
                break;
        }

        if (sh_config.ifname == NULL ||
            sh_config.ofname == NULL ||
            sh_config.format == SHELLCODE_FMT_UNKNOWN) {
                error = MALELF_ERROR;
        }

        return error;
}


_u32 malelf_shellcode_init(int argc, char **argv)
{
        _i32 option = 0;
        _u32 error = MALELF_ERROR;
        int option_index = 0;
        static struct option long_options[] = {
                {"help", 0, 0, SHELLCODE_HELP},
                {"input", 1, 0, SHELLCODE_BINARY},
                {"format", 1, 0, SHELLCODE_FORMAT},
                {"output", 1, 0, SHELLCODE_FILE},
                {0, 0, 0, 0}
        };

        if (2 == argc) {
                malelf_shellcode_help();
                return MALELF_ERROR;
        }

        sh_config.ifname = NULL;
        sh_config.ofname = NULL;
        sh_config.format = SHELLCODE_FMT_UNKNOWN;

        while ((option = getopt_long (argc, argv, "ho:f:i:",
                                      long_options, &option_index)) != -1) {
                error = _malelf_shellcode_handle_options(option);
        }

        if (MALELF_SUCCESS == error ) {
                error = _malelf_shellcode(&sh_config);
        } else {
                printf("Invalid arguments...\n");
                malelf_shellcode_help();
        }

        return error;
}

_u32 malelf_shellcode_finish()
{
        printf("cleaning and exiting.\n");
        return MALELF_SUCCESS;
}
