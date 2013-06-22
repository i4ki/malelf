CFLAGS_LANGUAGE=	-std=c99 -pedantic \
			-D_XOPEN_SOURCE=700 \
			-fno-strict-aliasing \
			$(LIBXML2_CFLAGS)

CFLAGS_INCLUDES=
CFLAGS_WARNS=-Wall -Wextra -Werror

AM_CFLAGS=	-ggdb -O2 $(M32_CFLAGS) \
		$(CFLAGS_LANGUAGE) \
		$(CFLAGS_WARNS)

bin_PROGRAMS = malelf

malelf_SOURCES = 	main.c \
			dissect.c \
			shellcode.c \
			util.c

malelf_LDADD = -lmalelf $(LIBXML2_CFLAGS)
