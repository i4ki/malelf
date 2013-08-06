#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>


/*  Libmalelf */
#include <malelf/types.h>
#include <malelf/error.h>

/*  Malelf */
#include "defines.h"
#include "util.h"
#include "analyze.h"

static _u32 _analyze_set_binary_file(Analyze *obj, const char *filename)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == filename) {
                return MALELF_ERROR;
        }

        obj->filename = strdup(filename);
        if (NULL == obj->filename) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

static _u32 _analyze_set_database(Analyze *obj, const char *database)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == database) {
                return MALELF_ERROR;
        }

        obj->database = strdup(database);
        if (NULL == obj->database) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}



static _u32 _analyze_handle_options(Analyze *obj, int option)
{
        static _u8 error = MALELF_SUCCESS;

        switch (option) {
        case ANALYZE_HELP:
                analyze_help();
                break;
        case ANALYZE_INPUT:
                error |= _analyze_set_binary_file(obj, optarg);
                break;
        case ANALYZE_DATABASE:
                error |= _analyze_set_database(obj, optarg);
                break;
        case ':':
                printf("Unknown option character '%s'.\n", optarg);
                break;
        case ANALYZE_UNKNOWN:
                analyze_help();
                error |= 1;
                break;
        }

        return error;
}

static bool _analyze_search_section(Analyze *obj, const char *section) {
	char line[256] = {0};
	
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->fp) {
                return MALELF_ERROR;
        }

        if (NULL == section) {
                return MALELF_ERROR;
        }

        fseek(obj->fp, 0L, SEEK_SET);

        while (!feof(obj->fp)) {
                memset(line, '\0', 256);
                if (!fgets(line, 256, obj->fp)) {
                        break;
                }

                if (line[strlen(line) - 1] == '\n') {
                        line[strlen(line) - 1] = '\0';
                }
                
                if (strcmp(line, section) == 0) {
                        return true;
                }
        }

        return false;
}

static _u32 _analyze_binary_sections(Analyze *obj)
{
        MalelfBinary bin;
        int error;
        char *name = NULL;
        int i;


        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->filename) {
                return MALELF_ERROR;
        }

        if (NULL == obj->database) {
                return MALELF_ERROR;
        }

        obj->fp = fopen(obj->database, "r");
        if (NULL == obj->fp) {
                return MALELF_ERROR;
        }

        malelf_binary_init(&bin);
        error = malelf_binary_open(&bin, obj->filename);
        if (MALELF_SUCCESS != error) {
            return error;
        }

        for (i = 1; i < MALELF_ELF_FIELD(&bin.ehdr, e_shnum, error); i++) {
                error = malelf_binary_get_section_name(&bin, i, &name);
                if (MALELF_SUCCESS != error) {
                        return error;
                }

                if (false == _analyze_search_section(obj, name)) {
                        printf("Section %s NOT Found in database\n", name);
                }
        }
        malelf_binary_close(&bin);
        
        return MALELF_SUCCESS;
}


static _u32 _analyze(Analyze *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        return _analyze_binary_sections(obj);
}

static _u32 _analyze_options(Analyze *obj, int argc, char **argv)
{
        _i32 option = 0;
        _u32 error = MALELF_ERROR;
        int option_index = 0;
        static struct option long_options[] = {
                {"help", 0, 0, ANALYZE_HELP},
                {"input", 1, 0, ANALYZE_INPUT},
                {"section", 1, 0, ANALYZE_SECTION},
                {"database", 1, 0, ANALYZE_DATABASE},
                {0, 0, 0, 0}
        };

        if (2 == argc) {
                analyze_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (argc, argv, "hsd:i:",
                                      long_options, &option_index)) != -1) {
                error = _analyze_handle_options(obj, option);
        }

        if (MALELF_SUCCESS == error ) {
                error = _analyze(obj);
        } else {
                printf("Invalid arguments...\n");
                analyze_help();
        }

        return error;
}

void analyze_help(void)
{
        HELP("\n");
        HELP("This command analyze binary information.\n");
        HELP("Usage: malelf analyze <options>\n");
        HELP("         -h, --help     \tAnalyze Help\n");
        HELP("         -i, --input    \tBinary input file\n");
        HELP("         -d, --database \tDatabase\n");
        HELP("         -s, --section  \tAnalyze the binary sections\n");
        HELP("Example: malelf analyze -i /bin/ls -d db.txt -s\n");
        HELP("\n");
        exit(MALELF_SUCCESS);
}

_u32 analyze_init(Analyze *obj, int argc, char **argv)
{
        obj->database = NULL;
        obj->filename = NULL;
        obj->fp = NULL;

        return _analyze_options(obj, argc, argv);
}

_u32 analyze_finish(Analyze *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL != obj->database) {
                free(obj->database);
        }

        if (NULL != obj->filename) {
                free(obj->filename);
        }

        if (NULL != obj->fp) {
                fclose(obj->fp);
        }

        return MALELF_SUCCESS;
}
