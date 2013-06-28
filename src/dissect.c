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
#include <elf.h>

/* Libmalelf */
#include <malelf/report.h>
#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/table.h>

/* Malelf */
#include "defines.h"
#include "dissect.h"
#include "util.h"

static MalelfReport report;
static MalelfBinary binary;

void malelf_dissect_help(void)
{
        HELP("\n");
        HELP("This command display information about the ELF binary.\n");
        HELP("Usage: malelf dissect <options>\n");
        HELP("         -h, --help    \tDissect Help\n");
        HELP("         -i, --input   \tBinary File\n");
        HELP("         -e, --ehdr    \tDisplay ELF Header\n");
        HELP("         -s, --shdr    \tDisplay Section Header Table\n");
        HELP("         -p, --phdr    \tDisplay Program Header Table\n");
        HELP("         -S, --stable  \tDisplay Symbol Table\n");
        HELP("         -f, --format  \tOutput Format (XML or Stdout). Default is Stdout.\n");
        HELP("         -o, --output  \tOutput File.\n");
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
        if (MALELF_SUCCESS != malelf_binary_open(&binary, fname)) {
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
        case DISSECT_UNKNOWN:
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
        _u32 value;
        _u32 error;

        char *headers[] = {"Structure Member", "Description", "Value", NULL};

        if (MALELF_SUCCESS != malelf_table_init(&table, 78, 11, 3)) {
                return MALELF_ERROR;
        }
        malelf_table_set_title(&table, "ELF Header");
        malelf_table_set_headers(&table, headers);

        MALELF_CHECK(malelf_binary_get_ehdr, &binary, &ehdr);

        /* 1 - Row */
        MalelfEhdrTable me_type;
        MALELF_CHECK(malelf_ehdr_get_type, &ehdr, &me_type);

        malelf_table_add_str_value(&table, "e_type");
        malelf_table_add_str_value(&table, "Object Type");
        malelf_table_add_str_value(&table, me_type.meaning);

        /* 2 - Row */
        MalelfEhdrTable me_version;
        MALELF_CHECK(malelf_ehdr_get_version, &ehdr, &me_version);
        malelf_table_add_str_value(&table, "e_version");
        malelf_table_add_str_value(&table, "Version");
        malelf_table_add_int_value(&table, me_version.value);

        /* 3 - Row */
        MALELF_CHECK(malelf_ehdr_get_entry, &ehdr, &value);
        malelf_table_add_str_value(&table, "e_entry");
        malelf_table_add_str_value(&table, "Entry Point");
        malelf_table_add_hex_value(&table, value);

        /* 4 - Row */
        MALELF_CHECK(malelf_ehdr_get_phoff, &ehdr, &value);
        malelf_table_add_str_value(&table, "e_phoff");
        malelf_table_add_str_value(&table, "PHT Offset");
        malelf_table_add_hex_value(&table, value);

        /* 5 - Row */
        MALELF_CHECK(malelf_ehdr_get_shoff, &ehdr, &value);
        malelf_table_add_str_value(&table, "e_shoff");
        malelf_table_add_str_value(&table, "SHT Offset");
        malelf_table_add_hex_value(&table, value);

        /* 6 - Row */
        MALELF_CHECK(malelf_ehdr_get_ehsize, &ehdr, &value);
        malelf_table_add_str_value(&table, "e_ehsize");
        malelf_table_add_str_value(&table, "ELF Header Size");
        malelf_table_add_int_value(&table, value);

        /* 7 - Row */
        MALELF_CHECK(malelf_ehdr_get_phentsize, &ehdr, &value);
        malelf_table_add_str_value(&table, "e_phentsize");
        malelf_table_add_str_value(&table, "Size of PHT entries");
        malelf_table_add_int_value(&table, value);

        /* 8 - Row */
        MALELF_CHECK(malelf_ehdr_get_phnum, &ehdr, &value);
        malelf_table_add_str_value(&table, "e_phnum");
        malelf_table_add_str_value(&table, "Number of PHT entries");
        malelf_table_add_int_value(&table, value);

        /* 9 - Row */
        MALELF_CHECK(malelf_ehdr_get_shentsize, &ehdr, &value);
        malelf_table_add_str_value(&table, "e_shentsize");
        malelf_table_add_str_value(&table, "Size of one entry in SHT");
        malelf_table_add_int_value(&table, value);

        /* 10 - Row */
        MALELF_CHECK(malelf_ehdr_get_shnum, &ehdr, &value);
        malelf_table_add_str_value(&table, "e_shnum");
        malelf_table_add_str_value(&table, "Number of sections");
        malelf_table_add_int_value(&table, value);

        /* 11 - Row */
        MALELF_CHECK(malelf_ehdr_get_shstrndx, &ehdr, &value);
        malelf_table_add_str_value(&table, "e_shstrndx");
        malelf_table_add_str_value(&table, "SHT symbol index");
        malelf_table_add_int_value(&table, value);

        malelf_table_print(&table);
        malelf_table_finish(&table);

        return MALELF_SUCCESS;
}

static _u32 _malelf_dissect_table_shdr()
{
        MalelfTable table;
        MalelfShdr shdr;
        MalelfEhdr ehdr;
        Elf32_Shdr *sections;
        _u32 shnum;
        unsigned int i;
        MalelfShdrType ms_type;
        _u32 shstrndx;
        char *sec_name = NULL;
        char *headers[] = {"N", "Addr", "Offset", "Type", "Name", NULL};
        _u32 error;

        if (MALELF_SUCCESS != malelf_table_init(&table, 75, 28, 5)) {
                return MALELF_ERROR;
        }
        malelf_table_set_title(&table, "Section Header Table (SHT)");
        malelf_table_set_headers(&table, headers);

        MALELF_CHECK(malelf_binary_get_ehdr, &binary, &ehdr);
        MALELF_CHECK(malelf_ehdr_get_shnum, &ehdr, &shnum);
        MALELF_CHECK(malelf_ehdr_get_shstrndx, &ehdr, &shstrndx);
        MALELF_CHECK(malelf_binary_get_shdr, &binary, &shdr);
        sections = shdr.uhdr.h32;

        for (i = 0; i < shnum; i++) {
                Elf32_Shdr *s = &sections[i];
                malelf_table_add_int_value(&table, i);
                malelf_table_add_hex_value(&table, s->sh_addr);
                malelf_table_add_int_value(&table, s->sh_offset);
                MALELF_CHECK(malelf_shdr_get_mstype, &shdr, &ms_type, i);
                malelf_table_add_str_value(&table, ms_type.name);
                if (s->sh_type != SHT_NULL && shstrndx != 0x00) {
                        error = malelf_binary_get_section_name(&binary,
                                                               i,
                                                               &sec_name);
                        if (MALELF_SUCCESS != error) {
                                MALELF_PERROR(error);
                                return error;
                        }

                        /* truncate the string to 19 chars */
                        if (strlen(sec_name) > 20) {
                                sec_name[20] = 0;
                        }

                        malelf_table_add_str_value(&table, sec_name);
                } else {
                        malelf_table_add_str_value(&table, " ");

                }
        }

        malelf_table_print(&table);
        malelf_table_finish(&table);

        return MALELF_SUCCESS;

}

static _u32 _malelf_dissect_table_phdr()
{
        MalelfTable table;
        MalelfPhdr phdr;
        MalelfEhdr ehdr;
        _u32 phnum;
        _u32 value;
        unsigned int i;
        _u32 error;

        char *headers[] = {"N", "Offset", NULL};

        if (MALELF_SUCCESS != malelf_table_init(&table, 60, 9, 2)) {
                return MALELF_ERROR;
        }
        malelf_table_set_title(&table, "Program Header Table (PHT)");
        malelf_table_set_headers(&table, headers);

        MALELF_CHECK(malelf_binary_get_phdr, &binary, &phdr);
        MALELF_CHECK(malelf_binary_get_ehdr, &binary, &ehdr);
        MALELF_CHECK(malelf_ehdr_get_phnum, &ehdr, &phnum);

        for (i = 0; i < phnum; i++) {
                malelf_table_add_int_value(&table, i);
                MALELF_CHECK(malelf_phdr_get_offset, &phdr, &value, i);
                malelf_table_add_hex_value(&table, value);
        }

        malelf_table_print(&table);
        malelf_table_finish(&table);

        return MALELF_SUCCESS;
}

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
                if (obj->flag_ehdr) {
                        _malelf_dissect_table_ehdr();
                }

                if (obj->flag_phdr) {
                        _malelf_dissect_table_phdr();
                }

                if (obj->flag_shdr) {
                        _malelf_dissect_table_shdr();
                }

                if ((!obj->flag_ehdr) &&
                    (!obj->flag_shdr) &&
                    (!obj->flag_phdr)) {
                        _malelf_dissect_table_ehdr();
                        _malelf_dissect_table_shdr();
                        _malelf_dissect_table_phdr();
                }
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
                {"input", 1, 0, DISSECT_BINARY},
                {"format", 1, 0, DISSECT_FORMAT},
                {"output", 1, 0, DISSECT_FILE},
                {"phdr", 0, 0, DISSECT_PHDR},
                {"shdr", 0, 0, DISSECT_SHDR},
                {"ehdr", 0, 0, DISSECT_EHDR},
                {"stable", 0, 0, DISSECT_STABLE},
                {0, 0, 0, 0}
        };

        if (2 == argc) {
                malelf_dissect_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (argc, argv, "ho:f:epsi:S",
                                      long_options, &option_index)) != -1) {
                error = _malelf_dissect_handle_options(obj, option);
        }

        if (MALELF_SUCCESS == error ) {
                error = _malelf_dissect(obj);
        } else {
                printf("Invalid arguments...\n");
                malelf_dissect_help();
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
