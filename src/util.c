#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>


void malelf_help(const char *format, ...)
{
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
}

