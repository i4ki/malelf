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
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>

#include <malelf/defines.h>
#include <malelf/error.h>
#include <malelf/binary.h>

_u32 malelf_infect_verify_technique(MalelfInfect *obj)
{
        char *endptr;
        long val;
        assert (NULL != obj->technique);

        errno = 0;    /* To distinguish success/failure after call */
        val = strtol(str, &endptr, 10);

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
                     i < sizeof (malelf_techniques)/sizeof (_u8);
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

        if (val >= 0 && val < sizeof (malelf_techniques)/sizeof(_u8)) {
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
                break;
        case INFECT_OUTPUT:
                obj->ofname = optarg;
                break;
        case INFECT_MALWARE:
                obj->mfname = optarg;
                break;
        case INFECT_TECHNIQUE:
                obj->technique = optarg;
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

static _u32 _malelf_infect_options(MalelfInfect *obj,
                                   int argc,
                                   char **argv)
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
                {0, 0, 0, 0}
        };

        if (2 == argc) {
                malelf_infect_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (argc, argv, "hi:o:m:t:",
                                      long_options, &option_index)) != -1) {
                error = _malelf_infect_handle_options(obj, option);
        }

        if (MALELF_SUCCESS == error ) {
                error = _malelf_infect(obj);
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

        return _malelf_infect_options(obj, argc, argv);
}

_u32 malelf_infect_finish(MalelfInfect *infect)
{
        return MALELF_SUCCESS;
}

void malelf_infect_help(int argc, char **argv)
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
        HELP("                          \tUse %s infect -l to list ");
        HELP("techniques available.\n");
        HELP("Example: malelf infect -i /bin/ls -o myls -m evil.bin -t 'silvio-text-padding'\n");
        HELP("\n");
        exit(MALELF_SUCCESS);
}
