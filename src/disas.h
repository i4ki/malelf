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

#ifndef __DISAS_H__
#define __DISAS_H__

#include <malelf/disas.h>
#include <malelf/binary.h>

/*
 * Disas Options
 */
#define DISAS_HELP    'h'
#define DISAS_BINARY  'i'
#define DISAS_SECTION 's'
#define DISAS_UNKNOWN '?'

/* Store info about dissect */
typedef struct  {
        char *fname;                      /* Binary (Input) File */
        char *section;                    /* Section */
        MalelfBinary bin;
        MalelfDisas  disas;
} Disas;


_u32 disas_init(Disas *obj, int argc, char **argv);

_u32 disas_finish(Disas *obj);

void disas_help();


#endif /* __DISAS_H__ */
