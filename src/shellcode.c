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
#include <limits.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>

/* Libmalelf */
#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/debug.h>
#include <malelf/binary.h>

/* Malelf */
#include "util.h"
#include "shellcode.h"

static ShellcodeOptions sh_config;

int g_argc;
char **g_argv;

const char* malelf_shellcode_formats[] = {
        "binary",
        "c-string"
};

#define N_FORMATS 2

void _malelf_shellcode_list_formats()
{
        int i;

        HELP("Shellcode output formats available:\n");
        for (i = 0; i < N_FORMATS; i++) {
                HELP("\t%u - %s\n",
                     i,
                     malelf_shellcode_formats[i]);
        }
}

_u32 malelf_shellcode_verify_format(ShellcodeOptions *obj)
{
        char *endptr;
        long val;
        unsigned i;
        assert (NULL != obj->format);

        errno = 0;    /* To distinguish success/failure after call */
        val = strtol(obj->format, &endptr, 10);

        /* Check for various possible errors */

        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
            || (errno != 0 && val == 0)) {
                MALELF_PERROR(errno);
                return MALELF_ERROR;
        }

        if (endptr == obj->format) {
                MALELF_DEBUG_INFO("No digits were found in technique\n");
                /* parse string */
                for (i = 0;
                     i < N_FORMATS;
                     i++) {
                        if (strncmp(malelf_shellcode_formats[i],
                                    obj->format,
                                    strlen(malelf_shellcode_formats[i])) == 0) {
                                obj->iformat = i;
                                return MALELF_SUCCESS;
                        }
                }

                return MALELF_ERROR;
        }

        /* If we got here, strtol() successfully parsed a number */

        if (*endptr != '\0') {
                fprintf(stderr,
                        "Mixed digits and string in format. Use"
                        "(malelf shellcode -l) to show available formats"
                        "...\n");
                return MALELF_ERROR;
        }

        if (val >= 0 && val < N_FORMATS) {
                obj->iformat = (_u8) val;
        } else {
                fprintf(stderr,
                        "Format number out of range... Use "
                        "(malelf shellcode -l) to list available "
                        "formats.\n");
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

void malelf_shellcode_help(void)
{
        HELP("\n");
        HELP("This command create the virus shellcode in the proper "
             "format for use with the infect command.");
        HELP("Usage: %s shellcode <options>\n", *g_argv);
        HELP("         -h, --help    \tThis Help\n");
        HELP("         -i, --input   \tShellcode flat binary input\n");
        HELP("         -f, --format  \tOutput Format \n");
        HELP("                       \tDefault is '%s'\n",
             malelf_shellcode_formats[0]);
        HELP("         -l, --list    \tList output formats available\n");
        HELP("         -o, --output  \tOutput Shellcode file.\n");
        HELP("         -m, --magic-bytes\tMagic bytes to insert in ret address.\n");
        HELP("         -e, --return-entry-point\tEntry point to host.\n");
        HELP("Example: malelf shellcode -i ./malware.bin -f binary -o ./malware_ready.bin\n");
        HELP("\n");
        exit(MALELF_SUCCESS);
}

_u32 _malelf_shellcode_set_output_format(ShellcodeOptions *sh_config)
{
        _u32 error = MALELF_SUCCESS;

        error = malelf_shellcode_verify_format(sh_config);

        return error;
}

_u32 _malelf_shellcode_flat(ShellcodeOptions *config)
{
        MalelfBinary input_shellcode;
        MalelfBinary output_shellcode;
        _u32 error;
        _u32 magic_offset = 0;

        assert(config->ifname != NULL &&
               config->ofname != NULL &&
               config->iformat != -1);

        malelf_binary_init(&input_shellcode);
        malelf_binary_init(&output_shellcode);

        input_shellcode.class = MALELF_FLATUNKNOWN;
        output_shellcode.class = MALELF_FLATUNKNOWN;

        error = malelf_binary_open(&input_shellcode, config->ifname);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return error;
        }

        output_shellcode.fname = config->ofname;

        error = malelf_shellcode_create_flat(&output_shellcode,
                                             &input_shellcode,
                                             &magic_offset,
                                             0,
                                             config->magic_bytes.long_val);

        if (MALELF_SUCCESS != error) {
                MALELF_LOG_ERROR("Failed to create FLAT shellcode.");
                return error;
        }

        MALELF_LOG_SUCCESS("Shellcode generated successfully.\n");
        MALELF_LOG_SUCCESS("Output: %s\n", output_shellcode.fname);
        MALELF_LOG_SUCCESS("Infect binaries with: \n");
        MALELF_LOG_SUCCESS("\t\tmalelf infect -t 0 -m \"%s\" -f \"%u\" "
                           "-i <binary> -o "
                           "<output-binary>\n\n", output_shellcode.fname,
                           magic_offset);

        error = malelf_binary_write(&output_shellcode, output_shellcode.fname, 1);

        if (MALELF_SUCCESS != error) {
                MALELF_DEBUG_ERROR("Failed to write output file in '%s'.\n",
                                   output_shellcode.fname);
        }

        return error;
}

_u32 _malelf_shellcode_cstring(ShellcodeOptions *config)
{
        FILE *ofd = NULL;
        FILE *ifd = NULL;
        _u32 error;
        struct stat st_info;

        assert (NULL != config->ifname);

        if (NULL == config->ofname) {
                ofd = stdout;
        } else {
                ofd = fopen(config->ofname, "w+");
                if (NULL == ofd) {
                        return errno;
                }
        }

        ifd = fopen(config->ifname, "r");
        if (NULL == ifd) {
                goto cstring_error;
        }

        if (-1 == stat(config->ifname, &st_info)) {
                goto cstring_error;
        }

        error = malelf_shellcode_create_c(ofd,
                                          st_info.st_size,
                                          ifd,
                                          0);

        goto cstring_out;

cstring_error:
        error = errno;
cstring_out:
        fclose(ifd);
        fclose(ofd);
        return error;
}

_u32 _malelf_shellcode(ShellcodeOptions *config)
{
        assert (config->iformat < N_FORMATS);

        switch (config->iformat) {
        case SHELLCODE_FMT_BINARY:
                return _malelf_shellcode_flat(config);
                break;
        case SHELLCODE_FMT_CSTRING:
                return _malelf_shellcode_cstring(config);
                break;
        default:
                return _malelf_shellcode_flat(config);
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
                sh_config.format = optarg;
                error = _malelf_shellcode_set_output_format(&sh_config);
                break;
        case SHELLCODE_BINARY:
                sh_config.ifname = optarg;
                break;
        case SHELLCODE_FILE:
                sh_config.ofname = optarg;
                break;
        case SHELLCODE_MAGIC_BYTES:
                sh_config.magic_bytes.long_val = atoi(optarg);
                if (sh_config.magic_bytes.long_val <= 0 ||
                    sh_config.magic_bytes.long_val > 0xffffffff) {
                        malelf_error("magic bytes '%ld' is out of range "
                                     "(> 0 && < 99999999\n",
                                     sh_config.magic_bytes.long_val);
                        return MALELF_ERROR;
                }
                break;
        case SHELLCODE_ORIGINAL_ENTRY:
                sh_config.original_entry = atoi(optarg);
                break;
        case SHELLCODE_LIST:
                _malelf_shellcode_list_formats();
                exit(0);
        case ':':
                printf("Unknown option character '%s'.\n", optarg);
                break;
        case SHELLCODE_UNKNOWN:
                malelf_shellcode_help();
                error = MALELF_ERROR;
                break;
        }

        if (sh_config.iformat == -1) {
                return MALELF_ERROR;
        }

        if (sh_config.iformat == SHELLCODE_FMT_BINARY) {
                if (sh_config.ifname == NULL ||
                    sh_config.ofname == NULL) {
                        fprintf(stderr, "\n"
                                "Output format 'binary' requires"
                                " input (-i/--input) and output (-o/"
                                "--output) file.\n");
                        error = MALELF_ERROR;
                }
        } else if (sh_config.iformat == SHELLCODE_FMT_CSTRING) {
                if (sh_config.ifname == NULL) {
                        fprintf(stderr,
                                "Output format 'c-string' requires a "
                                "input (-i/--input) file.\n");
                        error = MALELF_ERROR;
                }
        } else {
                fprintf(stderr, "use -f <format> to select a output"
                        "format");
                error = MALELF_ERROR;
        }

        return error;
}


_u32 malelf_shellcode_init(int argc, char **argv)
{
        _i32 option = 0;
        _u32 error = MALELF_ERROR;
        int option_index = 0;

        g_argc = argc;
        g_argv = argv;

        static struct option long_options[] = {
                {"help", 0, 0, SHELLCODE_HELP},
                {"input", 1, 0, SHELLCODE_BINARY},
                {"format", 1, 0, SHELLCODE_FORMAT},
                {"list", 0, 0, SHELLCODE_LIST},
                {"output", 1, 0, SHELLCODE_FILE},
                {"magic-bytes", 1, 0, SHELLCODE_MAGIC_BYTES},
                {"original-entry", 1, 0, SHELLCODE_ORIGINAL_ENTRY},
                {0, 0, 0, 0}
        };

        if (2 == g_argc) {
                malelf_shellcode_help();
                return MALELF_ERROR;
        }

        sh_config.ifname = NULL;
        sh_config.ofname = NULL;
        sh_config.format = NULL;
        sh_config.iformat = -1;
        sh_config.magic_bytes.long_val = 0;

        while ((option = getopt_long (g_argc, g_argv, "hlo:f:i:e:m:",
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
        return MALELF_SUCCESS;
}
