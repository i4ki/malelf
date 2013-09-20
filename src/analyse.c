#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>


/*  Libmalelf */
#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/table.h>

/*  Malelf */
#include "defines.h"
#include "util.h"
#include "analyse.h"

char analyse_option = 0;
const char *default_database_dir = "data/";

/* TODO:
   colocar na libmalelf
*/
#ifndef MALELF_EHDR_SIZEOF
#define MALELF_EHDR_SIZEOF(arch)                        \
        (arch == MALELF_ELF32 ?                         \
         sizeof(Elf32_Ehdr) :                           \
                (arch == MALELF_ELF64 ?                 \
                 sizeof(Elf64_Ehdr) :                   \
                 0))

#endif

#ifndef MALELF_PHDR_SIZEOF
#define MALELF_PHDR_SIZEOF(arch)                        \
        (arch == MALELF_ELF32 ?                         \
         sizeof(Elf32_Phdr) :                           \
         (arch == MALELF_ELF64 ?                        \
          sizeof(Elf64_Phdr) :                          \
          0))
#endif

#ifndef MALELF_SHDR_SIZEOF
#define MALELF_SHDR_SIZEOF(arch)                        \
        (arch == MALELF_ELF32 ?                         \
         sizeof(Elf32_Shdr) :                           \
         (arch == MALELF_ELF64 ?                        \
          sizeof(Elf64_Shdr) :                          \
          0))
#endif


static _u32 _analyse_list()
{
        printf("Available analyse options:\n");
        printf("\t-s/--sections\t\tAnalyse suspicious sections\n");
        printf("\t-e/--entry\t\tAnalyse suspicious entry point\n");
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

static _u32 _analyse_set_database_from_dir(Analyse *obj, const char *fname)
{
        _u8 has_slash = obj->db_dir[strlen(obj->db_dir) - 1] == '/';
        _u32 alloc_size = (strlen(obj->db_dir) +
                           strlen(fname) + 1);

        if (NULL != obj->database) {
                free(obj->database);
        }

        if (! has_slash) {
                alloc_size++;
        }

        obj->database = malloc(alloc_size);
        memset(obj->database, 0, alloc_size);
        strcpy(obj->database, obj->db_dir);
        if (! has_slash) {
                strcat(obj->database, "/");
        }

        strcat(obj->database, fname);

        return MALELF_SUCCESS;
}



static _u32 _analyse_handle_options(Analyse *obj, int option)
{
        static _u8 error = MALELF_SUCCESS;

        analyse_option = ANALYSE_ALL;

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
        case ANALYSE_ALL:
                analyse_option = ANALYSE_ALL;
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

        if (NULL == obj || NULL == obj->fp_eoffsets) {
                return 0;
        }

        fseek(obj->fp_eoffsets, 0L, SEEK_SET);

        while (!feof(obj->fp_eoffsets)) {
                memset(line, '\0', 256);
                if (!fgets(line, 256, obj->fp_eoffsets)) {
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

static _u32 _analyse_search_section(Analyse *obj,
                                    const char *section,
                                    _u8 *found) {
        char line[256] = {0};

        if (NULL == obj->fp_section) {
                return MALELF_ERROR;
        }

        if (NULL == section) {
                return MALELF_ERROR;
        }

        fseek(obj->fp_section, 0L, SEEK_SET);

        *found = 0;

        while (!feof(obj->fp_section)) {
                memset(line, '\0', 256);
                if (!fgets(line, 256, obj->fp_section)) {
                        break;
                }

                if (line[strlen(line) - 1] == '\n') {
                        line[strlen(line) - 1] = '\0';
                }

                if (strcmp(line, section) == 0) {
                        *found = 1;
                        return MALELF_SUCCESS;
                }
        }

        return MALELF_SUCCESS;
}

static _u32 _analyse_shoff_suspect(MalelfBinary *bin, _u32 value, _u8 *suspect)
{
        MalelfSection section;
        _u32 error = MALELF_SUCCESS;
        _u32 shnum = MALELF_ELF_FIELD(&bin->ehdr, e_shnum, error);

        *suspect = 0;

        error = malelf_binary_get_section(bin, shnum -1, &section);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        _u32 r = value - (section.offset + section.size);

        if (r > 10) {
                *suspect = 1;
        }

        return MALELF_SUCCESS;
}

static _u32 _analyse_binary_ehdr(Analyse *obj)
{
        MalelfBinary bin;
        MalelfEhdr ehdr;
        MalelfTable table;
        MalelfEhdrTable etbl;
        _u32 value;
        _u32 error = MALELF_SUCCESS;
        _u8 is_suspect = 0;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->filename) {
                return MALELF_ERROR;
        }

        malelf_binary_init(&bin);
        error = malelf_binary_open(&bin, obj->filename);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        if (MALELF_SUCCESS != malelf_table_init(&table, 78, 10, 3)) {
                return MALELF_ERROR;
        }

        char *headers[] = {"Field", "Value", "Status", NULL};
        malelf_table_set_title(&table, "EHDR");
        malelf_table_set_headers(&table, headers);

        MALELF_CHECK(malelf_binary_get_ehdr, &bin, &ehdr);

#define SET_STATUS(error) (error == MALELF_SUCCESS ? "NORMAL" : "SUSPECT")

        malelf_table_add_str_value(&table, "e_type");
        error = malelf_ehdr_get_type(&ehdr, &etbl);
        malelf_table_add_hex_value(&table, etbl.value);
        malelf_table_add_str_value(&table, SET_STATUS(error));

        malelf_table_add_str_value(&table, "e_version");
        error = malelf_ehdr_get_version(&ehdr, &etbl);
        malelf_table_add_hex_value(&table, etbl.value);
        malelf_table_add_str_value(&table, SET_STATUS(error));

        malelf_table_add_str_value(&table, "e_phoff");
        error = malelf_ehdr_get_phoff(&ehdr, &value);
        malelf_table_add_int_value(&table, value);

        _u32 ehdr_size = MALELF_EHDR_SIZEOF(bin.class);
        _u32 phdr_size = MALELF_PHDR_SIZEOF(bin.class);
        _u32 shdr_size = MALELF_SHDR_SIZEOF(bin.class);
        _u32 phnum;
        _u32 shnum;
        error = malelf_ehdr_get_phnum(&ehdr, &phnum);
        error = malelf_ehdr_get_shnum(&ehdr, &shnum);

        if (value != ehdr_size) {
                /* PHT SHOULD reside soon after EHDR */
                malelf_table_add_str_value(&table, "SUSPECT");
        } else {
                malelf_table_add_str_value(&table, "NORMAL");
        }

        error = malelf_ehdr_get_shoff(&ehdr, &value);

        malelf_table_add_str_value(&table, "e_shoff");
        malelf_table_add_hex_value(&table, value);

        error = _analyse_shoff_suspect(&bin, value, &is_suspect);

        if (is_suspect) {
                malelf_table_add_str_value(&table, "SUSPECT");
        } else {
                malelf_table_add_str_value(&table, "NORMAL");
        }

        error = malelf_ehdr_get_ehsize(&ehdr, &value);
        malelf_table_add_str_value(&table, "e_ehsize");
        malelf_table_add_int_value(&table, value);

        if (value != ehdr_size) {
                malelf_table_add_str_value(&table, "SUSPECT");
        } else {
                malelf_table_add_str_value(&table, "NORMAL");
        }

        error = malelf_ehdr_get_phentsize(&ehdr, &value);
        malelf_table_add_str_value(&table, "e_phentsize");
        malelf_table_add_int_value(&table, value);

        if (value != phdr_size) {
                malelf_table_add_str_value(&table, "SUSPECT");
        } else {
                malelf_table_add_str_value(&table, "NORMAL");
        }

        error = malelf_ehdr_get_phnum(&ehdr, &value);
        malelf_table_add_str_value(&table, "e_phnum");
        malelf_table_add_int_value(&table, value);

        if (value <= 0 || value < 2) {
                malelf_table_add_str_value(&table, "SUSPECT");
        } else {
                malelf_table_add_str_value(&table, "NORMAL");
        }

        error = malelf_ehdr_get_shentsize(&ehdr, &value);
        malelf_table_add_str_value(&table, "e_shentsize");
        malelf_table_add_int_value(&table, value);

        if (value != shdr_size) {
                malelf_table_add_str_value(&table, "SUSPECT");
        } else {
                malelf_table_add_str_value(&table, "NORMAL");
        }

        error = malelf_ehdr_get_shnum(&ehdr, &value);
        malelf_table_add_str_value(&table, "e_shnum");
        malelf_table_add_int_value(&table, value);

        if (0 == value) {
                malelf_table_add_str_value(&table, "SUSPECT");
        } else {
                malelf_table_add_str_value(&table, "NORMAL");
        }

        error = malelf_ehdr_get_shstrndx(&ehdr, &value);
        malelf_table_add_str_value(&table, "e_shstrndx");
        malelf_table_add_int_value(&table, value);

        if (value > (shnum - 1)) {
                malelf_table_add_str_value(&table, "SUSPECT");
        } else {
                malelf_table_add_str_value(&table, "NORMAL");
        }

        malelf_table_print(&table);
        malelf_table_finish(&table);
        malelf_binary_close(&bin);
        return error;
}

static _u32 _analyse_binary_sections(Analyse *obj)
{
        MalelfBinary bin;
        MalelfTable table;
        _u32 error = MALELF_SUCCESS;
        char *name = NULL;
        int i;
        char *current_db = DB_SECTION_NAME;


        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->filename) {
                return MALELF_ERROR;
        }

        if (NULL == obj->database && NULL == obj->db_dir) {
                return MALELF_ERROR;
        }

        if (ANALYSE_ALL == analyse_option && NULL != obj->database) {
                fprintf(stderr, "[-] Option --all and -d/--database are exclusive.\n");
                return MALELF_ERROR;
        }

        if (ANALYSE_ALL == analyse_option ||
            NULL == obj->database) {
                _analyse_set_database_from_dir(obj, current_db);
        }

        if (NULL != obj->fp_section) {
                fclose(obj->fp_section);
        }

        obj->fp_section = fopen(obj->database, "r");
        if (NULL == obj->fp_section) {
                fprintf(stderr, "Failed to open database '%s'.\n", obj->database);
                return errno;
        }

        malelf_binary_init(&bin);
        error = malelf_binary_open(&bin, obj->filename);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        int shnum = MALELF_ELF_FIELD(&bin.ehdr, e_shnum, error);

        if (shnum == 0) {
                printf("No section headers to analyse.\n");
                malelf_binary_close(&bin);
                if (obj->database) {
                        free(obj->database);
                        obj->database = NULL;
                }
                return MALELF_SUCCESS;
        }

        if (MALELF_SUCCESS != malelf_table_init(&table, 78, shnum - 1, 2)) {
                return MALELF_ERROR;
        }

        char *headers[] = {"Section", "Status", NULL};
        malelf_table_set_title(&table, "Sections");
        malelf_table_set_headers(&table, headers);

        for (i = 1; i < shnum; i++) {
                error = malelf_binary_get_section_name(&bin, i, &name);
                _u8 found = 0;
                if (MALELF_SUCCESS != error) {
                        goto analyse_section_exit;
                }

                if (!name || strlen(name) == 0) {
                        continue;
                }

                malelf_table_add_str_value(&table, name);

                error = _analyse_search_section(obj, name, &found);
                if (MALELF_SUCCESS != error) {
                        goto analyse_section_exit;
                }

                if (! found) {
                        malelf_table_add_str_value(&table, "SUSPECT");
                } else {
                        malelf_table_add_str_value(&table, "NORMAL");
                }
        }

analyse_section_exit:
        malelf_binary_close(&bin);
        if (obj->database) {
                free(obj->database);
                obj->database = NULL;
        }

        malelf_table_print(&table);
        malelf_table_finish(&table);

        return error;
}

static _u32 _analyse_binary_entry(Analyse *obj)
{
        MalelfTable table;
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

        if (NULL == obj->database && NULL == obj->db_dir) {
                return MALELF_ERROR;
        }

        if (ANALYSE_ALL == analyse_option && NULL != obj->database) {
                fprintf(stderr, "[-] Option -a/--all and -d/--database are exclusive.\n");
                return MALELF_ERROR;
        }

        if (ANALYSE_ALL == analyse_option ||
            NULL == obj->database) {
                _analyse_set_database_from_dir(obj, DB_ENTRY_SECTION_OFFSETS_NAME);
        }

        obj->fp_eoffsets = fopen(obj->database, "r");
        if (NULL == obj->fp_eoffsets) {
                fprintf(stderr, "Failed to open database '%s'.\n", obj->database);
                return errno;
        }

        _analyse_set_database_from_dir(obj, DB_ENTRY_SECTION_NAME);

        if (obj->fp_section) {
                fclose(obj->fp_section);
        }

        obj->fp_section = fopen(obj->database, "r");

        if (!obj->fp_section) {
                fprintf(stderr, "Failed to open database '%s'.\n", obj->database);
                return errno;
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

        char *headers[] = {"Information", "Value", "Status", NULL};

        if (MALELF_SUCCESS != malelf_table_init(&table, 78, 3, 3)) {
                return MALELF_ERROR;
        }
        malelf_table_set_title(&table, "Entry point analysis");
        malelf_table_set_headers(&table, headers);

        for (i = 1; i < MALELF_ELF_FIELD(&bin.ehdr, e_shnum, error); i++) {
                MalelfSection section;
                error = malelf_binary_get_section(&bin, i, &section);
                if (MALELF_SUCCESS != error) {
                        goto analyse_entry_exit;
                }

                if (entry >= section.addr &&
                    entry < (section.addr + section.size)) {
                        _u32 offset_init = entry - section.addr;
                        _u32 distance_from_end = section.size - offset_init;
                        _u8 found = 0;
                        /* verify the section where entry point is located */
                        error = _analyse_search_section(obj, section.name, &found);

                        if (MALELF_SUCCESS != error) {
                                goto analyse_entry_exit;
                        }

                        malelf_table_add_str_value(&table, "Entrypoint section");
                        malelf_table_add_str_value(&table, section.name);

                        if (! found) {
                                malelf_table_add_str_value(&table, "SUSPECT");
                        } else {
                                malelf_table_add_str_value(&table, "NORMAL");
                        }

                        malelf_table_add_str_value(&table,
                                                   "Entrypoint offset (heuristic)");
                        malelf_table_add_int_value(&table, offset_init);

                        if (distance_from_end <= offset_init) {
                                malelf_table_add_str_value(&table, "SUSPECT");
                        } else {
                                malelf_table_add_str_value(&table, "NORMAL");
                        }

                        malelf_table_add_str_value(&table,
                                                   "Entrypoint offset (database)");
                        malelf_table_add_int_value(&table, offset_init);

                        if (_analyse_entry_suspect_offsets(obj,
                                                           offset_init,
                                                           section.size)) {
                                malelf_table_add_str_value(&table, "SUSPECT");
                        } else {
                                malelf_table_add_str_value(&table, "NORMAL");
                        }

                        break;
                }
        }

analyse_entry_exit:
        malelf_table_print(&table);
        fflush(stdout);
        malelf_table_finish(&table);
        malelf_binary_close(&bin);
        if (obj->database) {
                free(obj->database);
                obj->database = NULL;
        }

        return MALELF_SUCCESS;
}

static _u32 _analyse_all(Analyse *obj)
{
        _u32 error;

        error = _analyse_binary_ehdr(obj);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        error = _analyse_binary_sections(obj);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        error = _analyse_binary_entry(obj);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        return error;
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
        case ANALYSE_ALL:
                return _analyse_all(obj);
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
                {"all", 0, 0, ANALYSE_ALL},
                {"section", 0, 0, ANALYSE_SECTION},
                {"entry", 0, 0, ANALYSE_ENTRY},
                {"database", 1, 0, ANALYSE_DATABASE},
                {"database-dir", 1, 0, ANALYSE_DATABASE_DIR},
                {"list", 0, 0, ANALYSE_LIST},
                {0, 0, 0, 0}
        };

        if (2 == argc) {
                analyse_help();
                return MALELF_ERROR;
        }

        while ((option = getopt_long (argc, argv, "hlsaedr:i:",
                                      long_options, &option_index)) != -1) {
                error = _analyse_handle_options(obj, option);
        }

        if (NULL == obj->filename) {
                printf("Please, set input binary file (--input/-i).\n");
                error = MALELF_ERROR;
        }

        if (NULL == obj->database) {
                obj->db_dir = strdup(default_database_dir);
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
        _u32 error;
        obj->database = NULL;
        obj->db_dir = NULL;
        obj->filename = NULL;
        obj->fp = NULL;
        obj->fp_section = NULL;
        obj->fp_eoffsets = NULL;

        error = _analyse_options(obj, argc, argv);

        return error;
}

_u32 analyse_finish(Analyse *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL != obj->database) {
                free(obj->database);
        }

        if (NULL != obj->db_dir) {
                free(obj->db_dir);
        }

        if (NULL != obj->filename) {
                free(obj->filename);
        }

        if (NULL != obj->fp) {
                fclose(obj->fp);
        }

        if (NULL != obj->fp_section) {
                fclose(obj->fp_section);
        }

        if (NULL != obj->fp_eoffsets) {
                fclose(obj->fp_eoffsets);
        }

        return MALELF_SUCCESS;
}
