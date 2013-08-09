#include <stdio.h>
#include <stdlib.h>
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
#include "database.h"


static _u32 _database_set_binary_directory(Database *obj, char *directory)
{
        char *new_dir = NULL;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == directory) {
                return MALELF_ERROR;
        }

        /* Fixing problem "/" in the end.
         * Example: /bin is diferent /bin/
         */
        if (directory[strlen(directory) - 1] != '/' ) {
            new_dir = (char *) malloc(strlen(directory) + 2);
            if (NULL == new_dir) {
                    return MALELF_EALLOC;
            }
            memset(new_dir, '\0', strlen(directory) + 2);

            strncpy(new_dir, directory, strlen(directory));
            strncat(new_dir, "/", 1);
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

static bool _database_search_section(Database *obj, const char *section) {
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
            return error;
        }

        for (i = 1; i < MALELF_ELF_FIELD(&bin.ehdr, e_shnum, error); i++) {
                error = malelf_binary_get_section_name(&bin, i, &name);
                if (MALELF_SUCCESS != error) {
                        return error;
                }

                if (false == _database_search_section(obj, name)) {
                        fprintf(obj->fp, "%s\n", name);
                }
        }
        malelf_binary_close(&bin);

        return MALELF_SUCCESS;
}

static _u32 _database_load_binaries(Database *obj)
{
        DIR *dir = NULL;
	struct dirent *dp = NULL;
        unsigned int status;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->directory) {
                return MALELF_ERROR;
        }

        obj->fp = fopen(obj->database, "a+");
        if (NULL == obj->fp) {
                return MALELF_ERROR;
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

                 status = _database_save_section(obj, path);
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
                {0, 0, 0, 0}
        };

        if (2 == argc) {
                database_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (argc, argv, "hso:i:",
                                      long_options, &option_index)) != -1) {
                error = _database_handle_options(obj, option);
        }

        if (MALELF_SUCCESS == error ) {
                error = _database(obj);
        } else {
                printf("Invalid arguments...\n");
                database_help();
        }

        return error;
}

void database_help(void)
{
        HELP("\n");
        HELP("This command stores information about the ELF binary in a database.\n");
        HELP("Usage: malelf database <options>\n");
        HELP("         -h, --help     \tDatabase Help\n");
        HELP("         -i, --input    \tBinary Directory\n");
        HELP("         -s, --sections \tStores Binary Sections\n");
        HELP("         -o, --output   \tOutput Database\n");
        HELP("Example: malelf database -i /bin --sections .text -o db.txt\n");
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
