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
#include <getopt.h>
#include <unistd.h>
#include <string.h>

/* Libmalelf */
#include <malelf/report.h>
#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/table.h>

/* Malelf */
#include "dissect.h"
#include "util.h"

static MalelfReport report;
static MalelfBinary binary;

void malelf_dissect_help()
{
        HELP("\n");
        HELP("This command display information about the ELF binary.\n");
        HELP("Usage: malelf dissect [-h] -i <binary-file> -f <output-format> -o <output-file> [-e|-p|-s|-S]\n");
        HELP("         -h, --help    \tDissect Help\n");
        HELP("         -i, --binary  \tBinary File\n");
        HELP("         -e, --ehdr    \tDisplay ELF Header\n");
        HELP("         -s, --shdr    \tDisplay Section Header Table\n");
        HELP("         -p, --phdr    \tDisplay Program Header Table\n");
        HELP("         -S, --stable  \tDisplay Symbol Table\n");
        HELP("         -f, --format  \tOutput Format (XML or Stdout). Default is Stdout.\n");
        HELP("         -o, --file    \tOutput File.\n");
        HELP("Example: malelf dissect -i /bin/ls -f xml -o /tmp/binary.xml\n");
        HELP("\n");
        exit(MALELF_SUCCESS);
}

/* Set MalelfDissect the output type */
static _u32 _malelf_dissect_set_output_type(MalelfDissect *obj, char *type)
{
        if (NULL == type) {
                return MALELF_ERROR;
        }

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (0 == strncmp(type, "xml", 3)) {
                obj->output_type = MALELF_OUTPUT_XML;
        }

        if (0 == strncmp(type, "std", 3)) {
                obj->output_type = MALELF_OUTPUT_TEXT;
        }

        return MALELF_SUCCESS;
}

static _u32 _malelf_dissect_set_flag_ehdr(MalelfDissect *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        obj->flag_ehdr = 1;

        return MALELF_SUCCESS;
}

static _u32 _malelf_dissect_set_flag_phdr(MalelfDissect *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        obj->flag_phdr = 1;

        return MALELF_SUCCESS;
}

static _u32 _malelf_dissect_set_flag_shdr(MalelfDissect *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        obj->flag_shdr = 1;

        return MALELF_SUCCESS;
}

static _u32 _malelf_dissect_set_flag_stable(MalelfDissect *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        obj->flag_stable = 1;

        return MALELF_SUCCESS;
}

static _u32 _malelf_dissect_set_output_file(MalelfDissect *obj, char *fname)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == fname) {
                return MALELF_ERROR;
        }

        obj->fname = strdup(fname);
        if (NULL == obj->fname) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

static _u32 _malelf_dissect_set_binary_file(MalelfDissect *obj, char *fname)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == fname) {
                return MALELF_ERROR;
        }

        obj->binary = strdup(fname);
        malelf_binary_init(&binary);
    	if (MALELF_SUCCESS != malelf_binary_open(fname, &binary)) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

static _u32 _malelf_dissect_handle_options(MalelfDissect *obj, int option)
{
        static _u8 error = MALELF_SUCCESS;

        switch (option) {
        case DISSECT_HELP:
                malelf_dissect_help();
                break;
        case DISSECT_FORMAT:
                error |= _malelf_dissect_set_output_type(obj, optarg);
                break;
        case DISSECT_EHDR:
                error |= _malelf_dissect_set_flag_ehdr(obj);
                break;
        case DISSECT_PHDR:
                error |= _malelf_dissect_set_flag_phdr(obj);
                break;
        case DISSECT_SHDR:
                error |= _malelf_dissect_set_flag_shdr(obj);
                break;
        case DISSECT_STABLE:
                error |= _malelf_dissect_set_flag_stable(obj);
                break;
        case DISSECT_BINARY:
                error |= _malelf_dissect_set_binary_file(obj, optarg);
                break;
        case DISSECT_FILE:
                error |= _malelf_dissect_set_output_file(obj, optarg);
                break;
        case ':':
                printf("Unknown option character '%s'.\n", optarg);
                break;
        case DISSECT_UNKNOW:
                malelf_dissect_help();
                error |= 1;
                break;
        }

        return error;
}

static _u32 _malelf_dissect_table_ehdr()
{
        MalelfTable table;
        MalelfEhdr ehdr;

        char *headers[] = {"Structure Member", "Description", "Value", NULL};

        malelf_table_init(&table, 78, 11, 3);
        malelf_table_set_title(&table, "ELF Header");
        malelf_table_set_headers(&table, headers);

        malelf_binary_get_ehdr(&binary, &ehdr);

        /* 1 - Row */
        MalelfEhdrType me_type;
        malelf_ehdr_get_type(&ehdr, &me_type);
        malelf_table_add_value(&table, (void*)"e_type", MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)"Object Type", MALELF_TABLE_STR);
        malelf_table_add_value(&table, 
                               (void*)me_type.meaning, 
                               MALELF_TABLE_STR);

        /* 2 - Row */
        MalelfEhdrVersion me_version;
        malelf_ehdr_get_version(&ehdr, &me_version);
        malelf_table_add_value(&table, (void*)"e_version", MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)"Version", MALELF_TABLE_STR);
        malelf_table_add_value(&table, 
                               (void*)me_version.value, 
                               MALELF_TABLE_INT);

        /* 3 - Row */
        _u32 entry;
        malelf_ehdr_get_entry(&ehdr, &entry);
        malelf_table_add_value(&table, (void*)"e_entry", MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)"Entry Point", MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)entry, MALELF_TABLE_HEX);

        /* 4 - Row */
        _u32 phoff;
        malelf_ehdr_get_phoff(&ehdr, &phoff);
        malelf_table_add_value(&table, (void*)"e_phoff", MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)"PHT Offset", MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)phoff, MALELF_TABLE_HEX);

        /* 5 - Row */
        _u32 shoff;
        malelf_ehdr_get_shoff(&ehdr, &shoff);
        malelf_table_add_value(&table, (void*)"e_shoff", MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)"SHT Offset", MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)shoff, MALELF_TABLE_HEX);

        /* 6 - Row */
        _u32 ehsize;
        malelf_ehdr_get_ehsize(&ehdr, &ehsize);
        malelf_table_add_value(&table, (void*)"e_ehsize", MALELF_TABLE_STR);
        malelf_table_add_value(&table, 
                               (void*)"ELF Header Size", 
                               MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)ehsize, MALELF_TABLE_INT);

        /* 7 - Row */
        _u32 phentsize;
        malelf_ehdr_get_phentsize(&ehdr, &phentsize);
        malelf_table_add_value(&table, (void*)"e_phentsize", MALELF_TABLE_STR);
        malelf_table_add_value(&table, 
                               (void*)"Size of PHT entries", 
                               MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)phentsize, MALELF_TABLE_INT);

        /* 8 - Row */
        _u32 phnum;
        malelf_ehdr_get_phnum(&ehdr, &phnum);
        malelf_table_add_value(&table, (void*)"e_phnum", MALELF_TABLE_STR);
        malelf_table_add_value(&table, 
                               (void*)"Number of PHT entries", 
                               MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)phnum, MALELF_TABLE_INT);

        /* 9 - Row */
        _u32 shentsize;
        malelf_ehdr_get_shentsize(&ehdr, &shentsize);
        malelf_table_add_value(&table, (void*)"e_shentsize", MALELF_TABLE_STR);
        malelf_table_add_value(&table, 
                               (void*)"Size of one entry in SHT", 
                               MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)shentsize, MALELF_TABLE_INT);

        /* 10 - Row */
        _u32 shnum;
        malelf_ehdr_get_shnum(&ehdr, &shnum);
        malelf_table_add_value(&table, (void*)"e_shnum", MALELF_TABLE_STR);
        malelf_table_add_value(&table, 
                               (void*)"Number of sections", 
                               MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)shnum, MALELF_TABLE_INT);

        /* 11 - Row */
        _u32 shstrndx;
        malelf_ehdr_get_shstrndx(&ehdr, &shstrndx);
        malelf_table_add_value(&table, (void*)"e_shstrndx", MALELF_TABLE_STR);
        malelf_table_add_value(&table, 
                               (void*)"SHT symbol index", 
                               MALELF_TABLE_STR);
        malelf_table_add_value(&table, (void*)shstrndx, MALELF_TABLE_INT);




        malelf_table_print(&table);
        malelf_table_finish(&table);

        return MALELF_SUCCESS;
}

/* 
_u32 malelf_dissect_table_shdr()
_u32 malelf_dissect_table_phdr()
*/

static _u32 _malelf_dissect_report(MalelfDissect *obj, _u8 output_type)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (output_type == MALELF_OUTPUT_XML) {
                if (obj->flag_ehdr) {
                        malelf_report_ehdr(&report, &binary);
                }
                if (obj->flag_phdr) {
                        malelf_report_phdr(&report, &binary);
                }
                if (obj->flag_shdr) {
                        malelf_report_shdr(&report, &binary);
                }
                if ((!obj->flag_ehdr) &&
                    (!obj->flag_shdr) &&
                    (!obj->flag_phdr)) {
                        malelf_report_ehdr(&report, &binary);
                        malelf_report_phdr(&report, &binary);
                        malelf_report_shdr(&report, &binary);
                }
        } else {
                /*MalelfEhdr ehdr;
                malelf_binary_get_ehdr(&binary, &ehdr);
                malelf_table_ehdr(&ehdr);*/
                _malelf_dissect_table_ehdr();
                printf("Option -f std isn't implemented yet. Use -f xml -o file.xml\n");
        }
        return MALELF_SUCCESS;
}


static _u32 _malelf_dissect(MalelfDissect *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->binary) {
                HELP("[ERROR] No ELF binary file set to dissect.\n");
                malelf_dissect_help();
                return MALELF_ERROR;
        }

        if (MALELF_OUTPUT_XML == obj->output_type) {
            if (NULL == obj->fname) {
                HELP("[ERROR] No filename set to output.\n");
                malelf_dissect_help();
                return MALELF_ERROR;
            }
            malelf_report_open(&report, obj->fname, MALELF_OUTPUT_XML);
            _malelf_dissect_report(obj, MALELF_OUTPUT_XML);
        } else {
                _malelf_dissect_report(obj, MALELF_OUTPUT_TEXT);
                printf("Option -f std isn't implemented yet. Use -f xml -o file.xml\n");
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

static _u32 _malelf_dissect_options(MalelfDissect *obj, int argc, char **argv)
{
        _i32 option = 0;
        _u32 error = MALELF_ERROR;
        int option_index = 0;
        static struct option long_options[] = {
                {"help", 0, 0, DISSECT_HELP},
                {"binary", 1, 0, DISSECT_BINARY},
                {"format", 1, 0, DISSECT_FORMAT},
                {"file", 1, 0, DISSECT_FILE},
                {"phdr", 0, 0, DISSECT_PHDR},
                {"shdr", 0, 0, DISSECT_SHDR},
                {"ehdr", 0, 0, DISSECT_EHDR},
                {"symbol-table", 0, 0, DISSECT_STABLE},
                {0, 0, 0, 0}
        };

        while ((option = getopt_long (argc, argv, "ho:f:epsi:S",
                                      long_options, &option_index)) != -1) {
                error = _malelf_dissect_handle_options(obj, option);
        }

        if (MALELF_SUCCESS == error ) {
                error = _malelf_dissect(obj);
        }

        return error;
}

_u32 malelf_dissect_init(MalelfDissect *obj, int argc, char **argv)
{
        obj->binary = NULL;
        obj->fname = NULL;
        obj->output_type = MALELF_OUTPUT_TEXT;
        obj->flag_ehdr = 0;
        obj->flag_shdr = 0;
        obj->flag_phdr = 0;
        obj->flag_stable = 0;

        return _malelf_dissect_options(obj, argc, argv);
}


_u32 malelf_dissect_finish(MalelfDissect *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL != obj->fname) {
                free(obj->fname);
        }

        if (NULL != obj->binary) {
                free(obj->binary);
        }

        if (NULL != report.writer) {
                malelf_report_close(&report);
        }

        malelf_binary_close(&binary);

        return MALELF_SUCCESS;
}


