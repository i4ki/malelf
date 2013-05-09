/* 
 * The malelf tool was written in pure C and developed using malelf library
 * to analyze (static/dynamic) malwares and infect ELF binaries. Evil using 
 * this tool is the responsibility of the programmer.
 *
 * Author: Paulo Leonardo Benatto <benatto@gmail.com>
 *
 * Contributor: Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *              Tiago Natel de Moura <tiago4orion@gmail.com>
 *
 * Copyright 2012, 2013 by Paulo Leonardo Benatto. All Rights Reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <malelf/ehdr.h>
#include <malelf/types.h>
#include <malelf/error.h>

#include "table.h"

static bool init = false;

_u32 malelf_table_init(MalelfTable *obj, 
                       unsigned int width, 
                       unsigned int nrows, 
                       unsigned int ncolumns,
                       char *title,
                       char **content,
                       char **headers)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        
        if (NULL == content) {
                return MALELF_ERROR;
        }

        if (width == 0) {
                fprintf(stdout, "Invalid WIDTH value!\n");
                return MALELF_ERROR;
        }
 
        if (nrows == 0) {
                fprintf(stdout, "Invalid Number of ROWS!\n");
                return MALELF_ERROR;
        } 

        if (ncolumns == 0) {
                fprintf(stdout, "Invalid Number of COLUMNS!\n");
                return MALELF_ERROR;
        } 

        if ((width % ncolumns) != 0) {
                fprintf(stdout, "WIDTH mod COLUMNS must be 0!\n");
                return MALELF_ERROR;
        }

        obj->width = width;
        obj->nrows = nrows;
        obj->ncolumns = ncolumns;
        obj->title = title;
        obj->content = content;
        obj->headers = headers;
        obj->line.flag = false;
        obj->line.end = PLUS;
        obj->line.begin = PLUS;
        obj->line.middle = LESS;
        obj->line.partition = PLUS;
        init = true;
 
        return MALELF_SUCCESS;
}

_u32 malelf_table_set_line_flag(MalelfTable *obj, bool flag)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->line.flag = flag;

        return MALELF_SUCCESS;
}


_u32 malelf_table_set_width(MalelfTable *obj, unsigned int width)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->width = width;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_nrows(MalelfTable *obj, unsigned int nrows)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->nrows = nrows;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_ncolumns(MalelfTable *obj, unsigned int ncolumns)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->ncolumns = ncolumns;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_line_begin(MalelfTable *obj, char begin)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->line.begin = begin;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_line_middle(MalelfTable *obj, char middle)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->line.middle = middle;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_line_end(MalelfTable *obj, char end)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->line.end = end;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_line_partition(MalelfTable *obj, char partition)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->line.partition = partition;

        return MALELF_SUCCESS;
}


static unsigned int _malelf_table_get_column_length(MalelfTable *obj, 
                                                    unsigned int *clength)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        *clength = obj->width/obj->ncolumns;
        
        return MALELF_SUCCESS;
}

static void _malelf_table_print_char(char character)
{
        fprintf(stdout, "%c", character);
}

static void _malelf_table_print_str(char *str)
{
        fprintf(stdout, "%s", str);
}

static void _malelf_table_new_line()
{
        fprintf(stdout, "\n");
}

static _u32 _malelf_table_print_line(MalelfTable *obj)
{
        unsigned int i;
        unsigned int col_length;
        unsigned int aux;
       
         _malelf_table_get_column_length(obj, &col_length);
        aux = col_length;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        _malelf_table_print_char(obj->line.begin);
        for (i = 1; i < obj->width; i++) {
                if ((aux == i) && (true == obj->line.flag)) {
                        _malelf_table_print_char(obj->line.partition);
                        aux = aux + col_length;
                } else {
                        _malelf_table_print_char(obj->line.middle);
                }
        }
        _malelf_table_print_char(obj->line.end);
        _malelf_table_new_line();
 
        return MALELF_SUCCESS;
}

static unsigned int _malelf_table_get_column_middle(unsigned int colx,
                                                    unsigned int coly,
                                                    char *str)
{
        return ((colx + coly)/2) - (strlen(str)/2);
}


static _u32 _malelf_table_print_title(MalelfTable *obj)
{
        unsigned int i;
        unsigned int middle;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->title) {
                return MALELF_ERROR;
        }

        middle = _malelf_table_get_column_middle(0, obj->width, obj->title);
        _malelf_table_print_line(obj);
        _malelf_table_print_char(PIPE);
        for (i = 1; i < obj->width; i++) {
                _malelf_table_print_char(EMPTY);
                if (middle == i) {
                        printf("%s", obj->title);
                        i = i + strlen(obj->title);
                }
        }
        _malelf_table_print_char(PIPE);
        _malelf_table_new_line();
        malelf_table_set_line_flag(obj, true);
        _malelf_table_print_line(obj);
       
        return MALELF_SUCCESS;
}

static _u32 _malelf_table_print_headers(MalelfTable *obj)
{
        unsigned int i;
        unsigned int col_length;
        unsigned int col_middle;
        unsigned int pos = 0;
        unsigned int col_begin = 0;
        unsigned int col_end = 0;
        static unsigned int count = 2;
        unsigned int partitions = 0;

        if (NULL == obj) {
                return MALELF_ERROR;  
        }

        _malelf_table_get_column_length(obj, &col_length);
        col_end = col_length;
        partitions = col_length;
        col_middle = _malelf_table_get_column_middle(col_begin, 
                                                     col_end, 
                                                     obj->headers[pos]);

        _malelf_table_print_char(PIPE);
        for (i = 1; i < obj->width; i++) {
                if (i == col_middle) {
                        _malelf_table_print_str(obj->headers[pos]);
                        i = i + strlen(obj->headers[pos]) - 1;
                        col_end = col_length * count;
                        col_begin = col_begin + col_length;
                        pos++;
                        if ((obj->ncolumns) > pos) {
                                col_middle = _malelf_table_get_column_middle(col_end, 
                                                                             col_begin, 
                                                                             obj->headers[pos]);
                        }
                        count++;
                        continue; 
                }
                if (i == partitions) {
                        _malelf_table_print_char(PIPE);
                        partitions = partitions + col_length;
                        continue;
                } 
                _malelf_table_print_char(EMPTY);
        }
        _malelf_table_print_char(PIPE);
        _malelf_table_new_line();
        _malelf_table_print_line(obj);

        return MALELF_SUCCESS;
} 


static _u32 _malelf_table_print_content(MalelfTable *obj)
{
        unsigned int i;
        unsigned int col_length;
        unsigned int col_middle;
        unsigned int pos = 0;
        unsigned int col_begin = 0;
        unsigned int col_end = 0;
        static unsigned int count = 2;
        unsigned int partitions = 0;

        
        if (NULL == obj) {
                return MALELF_ERROR;  
        }

        _malelf_table_get_column_length(obj, &col_length);
        col_end = col_length;
        partitions = col_length;
        col_middle = _malelf_table_get_column_middle(col_begin, col_end, obj->content[pos]);

        _malelf_table_print_char(PIPE);
        for (i = 1; i < obj->width; i++) {
                if (i == col_middle) {
                        _malelf_table_print_str(obj->content[pos]);
                        i = i + strlen(obj->content[pos]) - 1;
                        col_end = col_length * count;
                        col_begin = col_begin + col_length;
                        pos++;
                        if ((obj->nrows * obj->ncolumns) > pos) {
                                col_middle = _malelf_table_get_column_middle(col_end, col_begin, obj->content[pos]);
                         }
                         count++;
                         continue; 
                }
                if (i == partitions) {
                        _malelf_table_print_char(PIPE);
                        partitions = partitions + col_length;
                        continue;
                } 
                _malelf_table_print_char(EMPTY);
        }
        _malelf_table_print_char(PIPE);
        _malelf_table_new_line();
        count = 2;
        col_begin = 0;
        col_end = partitions = col_length;
        if ((obj->nrows * obj->ncolumns) > pos) {
                col_middle = _malelf_table_get_column_middle(col_end, col_begin, obj->content[pos]);
        }

        return MALELF_SUCCESS;
} 

_u32 malelf_table_print(MalelfTable *obj) 
{
        unsigned int j;

        if (false == init) {
                fprintf(stdout, "You must call malelf_table_init method.\n");
                return MALELF_ERROR;  
        }
        
        if (NULL != obj->title) {
                _malelf_table_print_title(obj);
        }

        if (NULL != obj->headers) {
                _malelf_table_print_headers(obj);
        }

        for (j = 0; j < obj->nrows; j++) {
                _malelf_table_print_content(obj);
        }

        _malelf_table_print_line(obj);

        return MALELF_SUCCESS;
}

_u32 malelf_table_ehdr(MalelfTable *obj)
{

        MalelfTable table;
        char *headers[] = {"Member", "Description", "Value"};

        char *content[] = {"Structure Member", "Description", "Value",
                           "Structure Member", "Description", "Value",
                           "Structure Member", "Description", "Value"};

        malelf_table_init(&table, 81, 3, 3, "ELF Header", content, headers);
        malelf_table_print(&table);

        return MALELF_SUCCESS; 
}

