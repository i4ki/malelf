#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>

/*  Libmalelf */
#include <malelf/types.h>
#include <malelf/error.h>

/*  Malelf */
#include "defines.h"
#include "util.h"
#include "disas.h"


static _u32 _disas_set_binary_file(Disas *obj, char *fname)
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

        malelf_binary_init(&obj->bin);
        if (MALELF_SUCCESS != malelf_binary_open(&obj->bin, obj->fname)) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

static _u32 _disas_set_section(Disas *obj, char *section)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == section) {
                return MALELF_ERROR;
        }

        obj->section = strdup(section);
        if (NULL == obj->section) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}



static _u32 _disas_handle_options(Disas *obj, int option)
{
        static _u8 error = MALELF_SUCCESS;

        switch (option) {
        case DISAS_HELP:
                disas_help();
                break;
        case DISAS_SECTION:
                error |= _disas_set_section(obj, optarg);
                printf("Section: %s\n", optarg);
                break;
        case DISAS_BINARY:
                error |= _disas_set_binary_file(obj, optarg);
                printf("%s\n", optarg);
                break;
        case ':':
                printf("Unknown option character '%s'.\n", optarg);
                break;
        case DISAS_UNKNOWN:
                disas_help();
                error |= 1;
                break;
        }

        return error;
}



static _u32 _disas(Disas *obj)
{
        _u32 result;
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->fname) {
                HELP("[ERROR] No ELF binary file set to disas.\n");
                disas_help();
                return MALELF_ERROR;
        }

        malelf_disas_init(&obj->disas, &obj->bin);
        result = malelf_disas(&obj->disas, &obj->bin, obj->section);

        return result;
}

static _u32 _disas_options(Disas *obj, int argc, char **argv)
{
        _i32 option = 0;
        _u32 error = MALELF_ERROR;
        int option_index = 0;
        static struct option long_options[] = {
                {"help", 0, 0, DISAS_HELP},
                {"input", 1, 0, DISAS_BINARY},
                {"section", 1, 0, DISAS_SECTION},
                {0, 0, 0, 0}
        };

        if (2 == argc) {
                disas_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (argc, argv, "hs:i:",
                                      long_options, &option_index)) != -1) {
                error = _disas_handle_options(obj, option);
        }

        if (MALELF_SUCCESS == error ) {
                error = _disas(obj);
                if (MALELF_ESECTION_NOT_FOUND == error) {
                        printf("Section not found ...\n");
                }
        } else {
                printf("Invalid arguments...\n");
                disas_help();
        }

        return error;
}

void disas_help(void)
{
        HELP("\n");
        HELP("This command display information about the ELF binary.\n");
        HELP("Usage: malelf disas <options>\n");
        HELP("         -h, --help    \tDisas Help\n");
        HELP("         -i, --input   \tBinary File\n");
        HELP("         -s, --section \tSection Disassemble \n");
        HELP("Example: malelf disas -i /bin/ls -s .text\n");
        HELP("\n");
        exit(MALELF_SUCCESS);
}

_u32 disas_init(Disas *obj, int argc, char **argv)
{
        obj->fname = NULL;
        obj->section = NULL;

        return _disas_options(obj, argc, argv);
}

_u32 disas_finish(Disas *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL != obj->section) {
                free(obj->section);
        }

        if (NULL != obj->fname) {
                free(obj->fname);
        }

        malelf_binary_close(&obj->bin);

        return MALELF_SUCCESS;
}
