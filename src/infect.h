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

#ifndef __INFECT_H__
#define __INFECT_H__

#include <malelf/types.h>

typedef struct {
        char *ofname;    /* Outpuf filename */
        char *ifname;    /* Input filename */
        char *mfname;    /* Malware filename */
        int ofd;         /* Output file descriptor */
        int ifd;         /* Input file descriptor */
        int mfd;         /* Malware file descriptor */
        char *technique; /* Technique to infect */
        _i8 itech;       /* Unsigned technique digit */
        _u32 offset_ret; /* Offset in shellcode to patch with host entrypoint */
        _u8 auto_shellcode;
} MalelfInfect;

/*
 * Infect Options
 */
#define INFECT_HELP          'h'
#define INFECT_OUTPUT        'o'
#define INFECT_INPUT         'i'
#define INFECT_MALWARE       'm'
#define INFECT_TECHNIQUE     't'
#define INFECT_LIST          'l'
#define INFECT_OFFSETRET     'f'
#define INFECT_AUTOSHELLCODE 'a'
#define INFECT_UNKNOWN       '?'

/* Infect techniques */
#define INFECT_TECH_CESARE 0
#define INFECT_TECH_NOP 1

extern _u32 malelf_infect_init(MalelfInfect *infect,
                        int argc,
                        char **argv);
extern _u32 malelf_infect_finish(MalelfInfect *infect);

#endif /* __INFECT_H__ */
