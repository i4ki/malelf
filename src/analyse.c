#include <stdio.h>
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
#include "analyse.h"

char analyse_option;

static _u32 _analyse_list()
{
        printf("Available analyse options:\n");
        printf("\t-s/--sections\t\tAnalyse suspicious sections\n");

        return MALELF_SUCCESS;
}

static _u32 _analyse_set_binary_file(Analyse *obj, const char *filename)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == filename) {
                return MALELF_ERROR;
        }

        obj->filename = strdup(filename);
        if (NULL == obj->filename) {
                return MALELF_EALLOC;
        }

        return MALELF_SUCCESS;
}

static _u32 _analyse_set_database(Analyse *obj, const char *database)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == database) {
                return MALELF_ERROR;
        }

        obj->database = strdup(database);
        if (NULL == obj->database) {
                return MALELF_EALLOC;
        }

        return MALELF_SUCCESS;
}



static _u32 _analyse_handle_options(Analyse *obj, int option)
{
        static _u8 error = MALELF_SUCCESS;

        switch (option) {
        case ANALYSE_HELP:
                analyse_help();
                break;
        case ANALYSE_INPUT:
                error = _analyse_set_binary_file(obj, optarg);
                break;
        case ANALYSE_DATABASE:
                error = _analyse_set_database(obj, optarg);
                break;
        case ANALYSE_SECTION:
                analyse_option = ANALYSE_SECTION;
                break;
        case ANALYSE_ENTRY:
                analyse_option = ANALYSE_ENTRY;
                break;
        case ANALYSE_LIST:
                _analyse_list();
                exit(0);
                break;
        case ':':
                printf("Unknown option character '%s'.\n", optarg);
                break;
        case ANALYSE_UNKNOWN:
                analyse_help();
                error = MALELF_ERROR;
                break;
        }

        return error;
}

static _u8 _analyse_entry_suspect_offsets(Analyse *obj,
                                          _u32 off_init,
                                          _u32 size)
{
        char line[256] = {0};
        char *buf = NULL;
        int n = 0;

        if (NULL == obj || NULL == obj->fp) {
                return 0;
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

                buf = line;

                n = strcspn(buf, ",");
                buf[n] = 0;
                _u32 d_off_init = atoi(buf);

                buf += n + 1;
                n = strcspn(buf, ",");
                buf[n] = 0;

                _u32 d_size = atoi(buf);
                _u8 percent1 = (off_init * 100)/size;
                _u8 percent2 = (d_off_init * 100)/d_size;

/*                MALDEBUG ("%u%% vs %u%%\n", percent1, percent2);*/

                if (percent2 > percent1) {
/*                        printf("[+] SAFE: %u%% vs %u%%, d_init = %u, d_size = %u\n", percent1, percent2, d_off_init, d_size);*/
                        return 0;
                }
        }

        return 1;
}

static _u8 _analyse_search_section(Analyse *obj, const char *section) {
        char line[256] = {0};

        if (NULL == obj) {
                return 0;
        }

        if (NULL == obj->fp) {
                return 0;
        }

        if (NULL == section) {
                return 0;
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
                        return 1;
                }
        }

        return 0;
}

static _u32 _analyse_binary_sections(Analyse *obj)
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

                if (! _analyse_search_section(obj, name)) {
                        printf("Section %s NOT Found in database\n", name);
                }
        }

        malelf_binary_close(&bin);

        return MALELF_SUCCESS;
}

static _u32 _analyse_binary_entry(Analyse *obj)
{
        MalelfBinary bin;
        int error;
        int i;
        _u32 entry;

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

        entry = MALELF_ELF_FIELD(&bin.ehdr, e_entry, error);
        if (MALELF_SUCCESS != error) {
                malelf_binary_close(&bin);
                return error;
        }

        for (i = 1; i < MALELF_ELF_FIELD(&bin.ehdr, e_shnum, error); i++) {
                MalelfSection section;
                error = malelf_binary_get_section(&bin, i, &section);
                if (MALELF_SUCCESS != error) {
                        goto analyse_entry_exit;
                }

                if (entry >= section.addr &&
                    entry < (section.addr + section.size)) {
                        _u32 offset_init = entry - section.addr;
                        _u32 offset_end = section.size - offset_init;

                        if (offset_end <= offset_init) {
                                printf("[!] Suspect entry point:\n"
                                       "[!] \tEntry point is at the end of "
                                       "section '%s'\n", section.name);
                        }

                        if (_analyse_entry_suspect_offsets(obj,
                                                           offset_init,
                                                           section.size)) {
                                printf("[!] The entry point offset inside the "
                                       "TEXT segment is larger than the commonly"
                                       " generated by compilers.\n");
                        }
                }
        }

analyse_entry_exit:
        malelf_binary_close(&bin);

        return MALELF_SUCCESS;
}


static _u32 _analyse(Analyse *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        switch (analyse_option) {
        case ANALYSE_SECTION:
                return _analyse_binary_sections(obj);
                break;
        case ANALYSE_ENTRY:
                return _analyse_binary_entry(obj);
                break;
        default:
                fprintf(stderr, "Invalid analyse option. Use malelf analyse -l"
                        " to list available analyse options.\n");
        }

        return MALELF_ERROR;
}

static _u32 _analyse_options(Analyse *obj, int argc, char **argv)
{
        _i32 option = 0;
        _u32 error = MALELF_SUCCESS;
        int option_index = 0;
        static struct option long_options[] = {
                {"help", 0, 0, ANALYSE_HELP},
                {"input", 1, 0, ANALYSE_INPUT},
                {"section", 0, 0, ANALYSE_SECTION},
                {"entry", 0, 0, ANALYSE_ENTRY},
                {"database", 1, 0, ANALYSE_DATABASE},
                {"list", 0, 0, ANALYSE_LIST},
                {0, 0, 0, 0}
        };

        if (2 == argc) {
                analyse_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (argc, argv, "hlsed:i:",
                                      long_options, &option_index)) != -1) {
                error = _analyse_handle_options(obj, option);
        }

        if (NULL == obj->filename) {
                printf("Please, set input binary file (--input/-i).\n");
                error = MALELF_ERROR;
        }

        if (NULL == obj->database) {
                printf("Please, set the input database file (--database/-d)\n");
                error = MALELF_ERROR;
        }

        if (MALELF_SUCCESS == error ) {
                error = _analyse(obj);
        } else {
                printf("Invalid arguments...\n");
                analyse_help();
        }

        return error;
}

void analyse_help(void)
{
        HELP("\n");
        HELP("This command analyse binary information.\n");
        HELP("Usage: malelf analyse <options>\n");
        HELP("         -h, --help     \tAnalyse Help\n");
        HELP("         -i, --input    \tBinary input file\n");
        HELP("         -d, --database \tDatabase\n");
        HELP("         -l, --list     \tList available analyse options\n");
        HELP("         -s, --section  \tAnalyse the binary sections\n");
        HELP("         -e, --entry    \tAnalyse the entrypoint\n");
        HELP("Example: malelf analyse -i /bin/ls -d db.txt -s\n");
        HELP("\n");
        exit(MALELF_SUCCESS);
}

_u32 analyse_init(Analyse *obj, int argc, char **argv)
{
        obj->database = NULL;
        obj->filename = NULL;
        obj->fp = NULL;

        return _analyse_options(obj, argc, argv);
}

_u32 analyse_finish(Analyse *obj)
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
