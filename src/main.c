#include <stdio.h>
#include <string.h>
#include <malelf/report.h>

#include "dissect.h"

#define DISSECT "dissect"

int main(int argc, char **argv)
{
        MalelfDissect dissect;

        if (argc < 2) {
                return -1;
        }

        if (strncmp(argv[1], DISSECT, sizeof(DISSECT)) == 0) { 
                malelf_dissect_init(&dissect, argc, argv);
                malelf_dissect_finish(&dissect);
        }

        return 0;
}
