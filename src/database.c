#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
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
#include "database.h"

char database_option = 0;

void _database_list()
{
        printf("Available database generator options:\n");
        printf("\t-s/--sections\t\tCreate a sections database\n");
        printf("\t-e/--entry\t\tCreate a entrypoint to sections map database\n");
}

_u32 _database_set_binary_directory(Database *obj, char *directory)
{
        char *new_dir = NULL;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == directory) {
                return MALELF_ERROR;
        }

        if (obj->directory) {
                free(obj->directory);
        }

        /* Fixing problem "/" in the end.
         * Example: /bin is diferent /bin/
         */
        if (directory[strlen(directory) - 1] != '/' ) {
            new_dir = malloc(strlen(directory) + 2);
            if (NULL == new_dir) {
                    return MALELF_EALLOC;
            }
            memset(new_dir, '\0', strlen(directory) + 2);

            strncpy(new_dir, directory, strlen(directory));
            strcat(new_dir, "/");

            obj->directory = strdup(new_dir);
            free(new_dir);
        } else {
            obj->directory = strdup(directory);
        }

        if (NULL == obj->directory) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

static _u32 _database_set_output(Database *obj, char *database)
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



static _u32 _database_handle_options(Database *obj, int option)
{
        static _u8 error = MALELF_SUCCESS;

        switch (option) {
        case DATABASE_HELP:
                database_help();
                break;
        case DATABASE_INPUT:
                error |= _database_set_binary_directory(obj, optarg);
                break;
        case DATABASE_OUTPUT:
                error |= _database_set_output(obj, optarg);
                break;
        case DATABASE_SECTION:
                database_option = DATABASE_SECTION;
                break;
        case DATABASE_ENTRY:
                database_option = DATABASE_ENTRY;
                break;
        case DATABASE_LIST:
                _database_list();
                exit(0);
                break;
        case ':':
                printf("Unknown option character '%s'.\n", optarg);
                break;
        case DATABASE_UNKNOWN:
                database_help();
                error |= 1;
                break;
        }

        return error;
}

static bool _database_search_line(Database *obj, const char *needle) {
        char line[256] = {0};

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->fp) {
                return MALELF_ERROR;
        }

        if (NULL == needle) {
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

                if (strcmp(line, needle) == 0) {
                        return true;
                }
        }

        return false;
}

static _u32 _database_save_section(Database *obj, const char *path_bin)
{
        MalelfBinary bin;
        int error;
        char *name = NULL;
        int i;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == path_bin) {
                return MALELF_ERROR;
        }

        malelf_binary_init(&bin);
        error = malelf_binary_open(&bin, (char*)path_bin);
        if (MALELF_SUCCESS != error) {
                malelf_binary_close(&bin);
                return error;
        }

        for (i = 1; i < MALELF_ELF_FIELD(&bin.ehdr, e_shnum, error); i++) {
                error = malelf_binary_get_section_name(&bin, i, &name);
                if (MALELF_SUCCESS != error) {
                        malelf_binary_close(&bin);
                        return error;
                }

                if (false == _database_search_line(obj, name)) {
                        fprintf(obj->fp, "%s\n", name);
                }
        }
        malelf_binary_close(&bin);

        return MALELF_SUCCESS;
}

static _u32 _database_save_entry_section(Database *obj, const char *path_bin)
{
        MalelfBinary bin;
        int error;
        int i;
        _u32 entry;
        _u32 type;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == path_bin) {
                return MALELF_ERROR;
        }

        malelf_binary_init(&bin);
        error = malelf_binary_open(&bin, (char*)path_bin);
        if (MALELF_SUCCESS != error) {
                goto save_entry_exit;
        }

        type = MALELF_ELF_FIELD(&bin.ehdr, e_type, error);
        if (MALELF_SUCCESS != error) {
                goto save_entry_exit;
        }

        if (type != ET_EXEC) {
                goto save_entry_exit;
        }

        entry = MALELF_ELF_FIELD(&bin.ehdr, e_entry, error);
        if (MALELF_SUCCESS != error) {
                goto save_entry_exit;
        }

        for (i = 1; i < MALELF_ELF_FIELD(&bin.ehdr, e_shnum, error); i++) {
                MalelfSection section;
                error = malelf_binary_get_section(&bin, i, &section);
                if (MALELF_SUCCESS != error) {
                        goto save_entry_exit;
                }

                if (entry >= section.addr && entry < (section.addr + section.size)) {
                        /* entry point is inside this section */
                        char linebuff[512];
                        snprintf(linebuff, 512,
                                 "%u,%u,%s",
                                 (entry - section.addr),
                                 (section.addr + section.size) - entry,
                                 section.name);
                        if (false == _database_search_line(obj,
                                                           linebuff)) {
                                fprintf(obj->fp, "%s\n", linebuff);
                        }
                }
        }

        error = MALELF_SUCCESS;
save_entry_exit:
        malelf_binary_close(&bin);

        return error;
}

static _u32 _database_load_binaries(Database *obj)
{
        DIR *dir = NULL;
        struct dirent *dp = NULL;
        unsigned int status = MALELF_SUCCESS;;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->directory) {
                return MALELF_ERROR;
        }

        if (NULL == obj->database) {
                obj->fp = stdout;
        } else {
                obj->fp = fopen(obj->database, "a+");
                if (NULL == obj->fp) {
                        return MALELF_ERROR;
                }
        }

        dir = opendir(obj->directory);
        if (NULL == dir) {
                return MALELF_ERROR;
        }

        while ((dp = readdir(dir))) {
                 if ((0 == strncmp(dp->d_name, ".", 1)) ||
                     (0 == strncmp(dp->d_name, "..", 2))) {
                         continue;
                 }
                 int pathlen = strlen(dp->d_name) + strlen(obj->directory) + 2;
                 char *path = malloc(pathlen);
                 memset(path, '\0', pathlen);
                 strncpy(path, obj->directory, strlen(obj->directory));
                 strncat(path, dp->d_name, strlen(dp->d_name));

                 if (database_option == DATABASE_SECTION) {
                         status = _database_save_section(obj, path);
                 } else if (database_option == DATABASE_ENTRY) {
                         status = _database_save_entry_section(obj, path);
                 }

                 if (MALELF_SUCCESS != status) {
                         free(path);
                         if (MALELF_ERROR == status) {
                                 return MALELF_ERROR;
                         } else {
                                 continue;
                         }
                         return status;
                 }
                 free(path);
        }
        closedir(dir);

        return MALELF_SUCCESS;
}


static _u32 _database(Database *obj)
{
        _u32 result;
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->directory) {
                HELP("[ERROR] No ELF binary file set to database.\n");
                database_help();
                return MALELF_ERROR;
        }

        struct stat sb;
        if (-1 == stat(obj->directory, &sb)) {
                return MALELF_ERROR;
        }

        if (!S_ISDIR(sb.st_mode) || S_ISLNK(sb.st_mode)) {
                printf ("Isn't Directory!\n");
                return MALELF_ERROR;
        }


        result = _database_load_binaries(obj);

        return result;
}

static _u32 _database_options(Database *obj, int argc, char **argv)
{
        _i32 option = 0;
        _u32 error = MALELF_ERROR;
        int option_index = 0;
        static struct option long_options[] = {
                {"help", 0, 0, DATABASE_HELP},
                {"input", 1, 0, DATABASE_INPUT},
                {"output", 1, 0, DATABASE_OUTPUT},
                {"sections", 0, 0, DATABASE_SECTION},
                {"entry", 0, 0, DATABASE_ENTRY},
                {"list", 0, 0, DATABASE_LIST},
                {0, 0, 0, 0}
        };

        if (2 == argc) {
                database_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (argc, argv, "hlseo:i:",
                                      long_options, &option_index)) != -1) {
                error = _database_handle_options(obj, option);
        }

        if (!database_option) {
                fprintf(stderr, "Invalid database option. "
                        "Use malelf database -l"
                        " to list available database options.\n");
                error = MALELF_ERROR;
        }

        if (MALELF_SUCCESS == error ) {
                error = _database(obj);
        } else {
                printf("Invalid arguments...\n");
                database_help();
        }

        return error;
}

void database_help()
{
        HELP("\n");
        HELP("This command stores information about the ELF binary in a database.\n");
        HELP("Usage: malelf database <options>\n");
        HELP("         -h, --help     \tDatabase Help\n");
        HELP("         -i, --input    \tBinary Directory\n");
        HELP("         -s, --sections \tStores Binary Sections\n");
        HELP("         -e, --entry    \tStore sections that commonly has the"
             " entry point.\n");
        HELP("         -o, --output   \tOutput Database\n");
        HELP("         -l, --list     \tList available database generator options.\n");
        HELP("Example: malelf database -i /bin --sections -o db.txt\n");
        HELP("\n");
        exit(MALELF_SUCCESS);
}

_u32 database_init(Database *obj, int argc, char **argv)
{
        obj->directory = NULL;
        obj->database = NULL;
        obj->fp = NULL;

        return _database_options(obj, argc, argv);
}

_u32 database_finish(Database *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL != obj->directory) {
                free(obj->directory);
        }

        if (NULL != obj->database) {
                free(obj->database);
        }

        if (NULL != obj->fp) {
                fclose(obj->fp);
        }

        return MALELF_SUCCESS;
}
