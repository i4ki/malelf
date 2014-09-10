#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([malelf], [1.0.0], [benatto@secplus.com.br])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([src/config.h])

AC_ARG_WITH([libmalelf-prefix],
	[AS_HELP_STRING([--with-libmalelf-prefix],
	  [Use this libmalelf prefix directory @<:@default=/usr/local@:>])],
        [with_libmalelf_prefix="$withval"],
	[with_libmalelf_prefix="/usr/local"])

with_libmalelf_includes="$with_libmalelf_prefix/include"
with_libmalelf_libpath="$with_libmalelf_prefix/lib"

extra_includes="$extra_includes:$with_libmalelf_prefix"
LIBMALELF_INCLUDES="$with_libmalelf_includes"
LIBMALELF_LIBPATH="$with_libmalelf_libpath"

AC_SUBST(LIBMALELF_INCLUDES)
AC_SUBST(LIBMALELF_LIBPATH)

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
#AC_CHECK_LIB([malelf], [malelf_binary_init])
PKG_CHECK_MODULES([LIBXML2], [libxml-2.0 >= 2.6.19])

AC_SUBST([LIBXML2_CFLAGS])
AC_SUBST([LIBXML2_LIBS])

# Checks for header files.
AC_CHECK_HEADERS([string.h unistd.h malelf/binary.h])

if test "x$ac_cv_header_malelf_binary_h" = "xno"; then
   AC_MSG_ERROR([libmalelf headers not found at $with_libmalelf_includes/malelf/binary.h
    Download and install libmalelf from https://github.com/SecPlus/libmalelf
    If the library is already installed, use --with-libmalelf-prefix=/dir])
fi


# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([     strdup     \
                     fopen      \
                     open       \
                     malloc     \
                     mmap])

AC_OUTPUT([Makefile src/Makefile doc/Makefile])
