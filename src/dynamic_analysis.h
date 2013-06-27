#ifndef DYNAMIC_ANALYSIS_H
#define DYNAMIC_ANALYSIS_H

#include <malelf/binary.h>
#include <malelf/types.h>
#include <stdio.h>

_i32 dynamic_analyse_input(MalelfBinary *elf_obj, char** argv, FILE* fd);
_i32 auto_dynamic_analyse_input(MalelfBinary *elf_obj, char** argv, FILE* fd);
void malelf_dynanalyse_init(int argc, char **argv);
void malelf_dynanalyse_finish();

#endif
