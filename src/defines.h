#ifndef __DEFINES_H__
#define __DEFINES_H__


#define MALELF_CHECK(func, ...)                                         \
        if (MALELF_SUCCESS != (error = func(__VA_ARGS__))) {            \
                MALELF_PERROR(error);                                   \
                return error;                                           \
        }

#endif
