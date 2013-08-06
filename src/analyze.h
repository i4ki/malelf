/*
 * The malelf tool was written in pure C and developed using malelf library
 * to analyze (static/dynamic) malwares and infect ELF binaries. Evil using
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

#ifndef __ANALYZE_H__
#define __ANALYZE_H__

#include <malelf/binary.h>

/*
 * Analyze Options
 */
#define ANALYZE_HELP     'h'
#define ANALYZE_INPUT    'i'
#define ANALYZE_DATABASE 'd'
#define ANALYZE_SECTION  's'
#define ANALYZE_UNKNOWN  '?'

/* Store info about dissect */
typedef struct  {
        char *filename;
        char *database;   /* Binary (Input) Directory */
        FILE *fp;          /* FILE Pointer */
} Analyze;


_u32 analyze_init(Analyze *obj, int argc, char **argv);

_u32 analyze_finish(Analyze *obj);

void analyze_help();


#endif /* __ANALYZE_H__ */
