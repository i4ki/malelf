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
#define DISSECT_UNKNOW '?'

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


#endif /* __DISSECT_H__ */
