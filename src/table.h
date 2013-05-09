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

#ifndef __TABLE_H__
#define __TABLE_H__

#include <stdbool.h>

#define MAX_LENGTH 50

#define PIPE  '|'
#define EMPTY ' '
#define PLUS  '+'
#define LESS  '-'

/* MalelfLine
 * 
 * +-------------------------------------------------+ 
 * |  begin (+)        (+) partition (+)    end (+)  | 
 * |         +----------+-------------+----------+   |
 * |                      middle (-)                 |
 * +-------------------------------------------------+
 *
 */

typedef struct {
        char begin;
        char middle;
        char end;
        char partition;
        bool flag;
} MalelfLine;

typedef struct {
        unsigned int width;
        unsigned int nrows;
        unsigned int ncolumns;
        char *title;
        char **content;
        MalelfLine line;
} MalelfTable;

_u32 malelf_table_init(MalelfTable *obj, 
                       unsigned int width, 
                       unsigned int nrows, 
                       unsigned int ncolumns,
                       char *title,
                       char **content);

_u32 malelf_table_set_width(MalelfTable *obj, unsigned int width);

_u32 malelf_table_set_nrows(MalelfTable *obj, unsigned int nrows);

_u32 malelf_table_set_ncolumns(MalelfTable *obj, unsigned int ncolumns);

_u32 malelf_table_set_line_begin(MalelfTable *obj, char begin);

_u32 malelf_table_set_line_middle(MalelfTable *obj, char middle);

_u32 malelf_table_set_line_end(MalelfTable *obj, char end);

_u32 malelf_table_set_line_partition(MalelfTable *obj, char partition);

_u32 malelf_table_set_line_flag(MalelfTable *obj, bool flag);

/* OLD */
_u32 malelf_table_ehdr(MalelfTable *obj);


#endif /* __TABLE_H__ */
