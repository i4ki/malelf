/*
 * The malelf tool was written in pure C and developed using malelf library
 * to analyse (static/dynamic) malwares and infect ELF binaries. Evil using
 * this tool is the responsibility of the programmer.
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

#ifndef __ANALYSE_H__
#define __ANALYSE_H__

#include <malelf/binary.h>

/*
 * Analyse Options
 */
#define ANALYSE_HELP             'h'
#define ANALYSE_INPUT            'i'
#define ANALYSE_DATABASE         'd'
#define ANALYSE_DATABASE_DIR     'r'
#define ANALYSE_SECTION          's'
#define ANALYSE_ENTRY            'e'
#define ANALYSE_ALL              'a'
#define ANALYSE_LIST             'l'
#define ANALYSE_UNKNOWN          '?'

#define DB_SECTION_NAME "sections.db"
#define DB_ENTRY_SECTION_NAME "entry_sections.db"
#define DB_ENTRY_SECTION_OFFSETS_NAME "entry_off.db"

/* Store info about dissect */
typedef struct  {
        char *filename;
        char *database;    /* Binary (Input) Directory */
        char *db_dir;      /* database directory */
        FILE *fp;          /* FILE Pointer */
        FILE *fp_section;
        FILE *fp_eoffsets;
} Analyse;


_u32 analyse_init(Analyse *obj, int argc, char **argv);

_u32 analyse_finish(Analyse *obj);

void analyse_help();


#endif /* __ANALYSE_H__ */
