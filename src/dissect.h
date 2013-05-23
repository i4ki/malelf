/*
 * The malelf tool was written in pure C and developed using malelf library
 * to analyze (static/dynamic) malwares and infect ELF binaries. Evil using
 * this tool is the responsibility of the programmer.
 *
 * Author: Tiago Natel de Moura <tiago4orion@gmail.com>
 *
 * Contributor: Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *              Paulo Leonardo Benatto <benatto@gmail.com>
 *
 * Copyright 2012, 2013 by Tiago Natel de Moura. All Rights Reserved.
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

#ifndef __DISSECT_H__
#define __DISSECT_H__

#include <malelf/report.h>

/*
 * Dissect Options
 */
#define DISSECT_FORMAT 'f'
#define DISSECT_HELP   'h'
#define DISSECT_EHDR   'e'
#define DISSECT_PHDR   'p'
#define DISSECT_SHDR   's'
#define DISSECT_BINARY 'i'
#define DISSECT_FILE   'o'
#define DISSECT_STABLE 'S'
#define DISSECT_UNKNOWN '?'

/* Store info about dissect */
typedef struct  {
        char *fname;                       /* Output File */
        char *binary;                      /* Binary (Input) File */
        MalelfOutputFormat output_type;    /* XML or Stdout */
        _u8  flag_ehdr;                    /* Flag Ehdr */
        _u8  flag_phdr;                    /* Flag Phdr */
        _u8  flag_shdr;                    /* Flag Shdr */
        _u8  flag_stable;                  /* Flag Symbol Table */
} MalelfDissect;


_u32 malelf_dissect_init(MalelfDissect *obj, int argc, char **argv);

_u32 malelf_dissect_finish(MalelfDissect *obj);

void malelf_dissect_help();


#endif /* __DISSECT_H__ */
