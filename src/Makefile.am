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
			util.c \
			infect.c \
			disas.c \
			database.c \
			analyze.c \
			dynamic_analysis.c

malelf_LDADD = -lmalelf -ludis86 $(LIBXML2_CFLAGS)

man_MANS = malelf.1
