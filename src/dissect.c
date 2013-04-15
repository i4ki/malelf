#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>

/* Libmalelf */
#include <malelf/report.h>
#include <malelf/types.h>
#include <malelf/error.h>

/* Malelf */
#include "dissect.h"
#include "util.h"

#define HELP malelf_help

static MalelfReport report;
static MalelfBinary binary;

void malelf_dissect_help()
{
        HELP("\n");
        HELP("This command display information about the ELF binary.\n");
        HELP("Usage: malelf dissect [-h] -i <binary-file> -o <output-format> -f <output-file>\n");
        HELP("        -h\tDissect Help\n");
        HELP("        -i\tBinary File\n");
        HELP("        -e\tDisplay ELF Header\n");
        HELP("        -s\tDisplay Section Header Table\n");
        HELP("        -p\tDisplay Program Header Table\n");
        HELP("        -S\tDisplay Symbol Table\n");
        HELP("        -f\tOutput File.\n");
        HELP("        -o\tOutput Format (xml or std). Default is stdout.\n");
        HELP("Example: malelf dissect -i /bin/ls -o xml -f ./ls.xml\n");
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
        case DISSECT_UNKNOW:
                error |= 1;
                break;
        }
 
        return error;
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
                printf("TESTE\n");
        }
        return MALELF_SUCCESS;
}


static _u32 malelf_dissect(MalelfDissect *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->binary) {
                return MALELF_ERROR;
        }

        if (MALELF_OUTPUT_XML == obj->output_type) {
            malelf_report_open(&report, obj->fname, MALELF_OUTPUT_XML);
            _malelf_dissect_report(obj, MALELF_OUTPUT_XML);
            
        } else {
            printf("TESTE\n");
            //_malelf_dissect_report(obj, MALELT_OUTPUT_TEXT); 
        }

        return MALELF_SUCCESS;
}

static _u32 malelf_dissect_options(MalelfDissect *obj, int argc, char **argv)
{
        _i32 option;
        _u32 error = MALELF_SUCCESS;
     
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


        while ((option = getopt_long (argc, argv, "ho:f:epsi:S", long_options, &option_index)) != -1) {
                error = _malelf_dissect_handle_options(obj, option);
        }

        if (MALELF_SUCCESS == error ) {
                error = malelf_dissect(obj);        
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

        return malelf_dissect_options(obj, argc, argv);
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

        malelf_binary_close(&binary);
        malelf_report_close(&report);
        
        return MALELF_SUCCESS;
}

