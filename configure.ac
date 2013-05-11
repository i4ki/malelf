#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([malelf], [1.0], [benatto@secplus.com.br])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([malelf], [malelf_binary_init])
PKG_CHECK_MODULES([LIBXML2], [libxml-2.0 >= 2.6.19])

AC_SUBST([LIBXML2_CFLAGS])
AC_SUBST([LIBXML2_LIBS])

# Checks for header files.
AC_CHECK_HEADERS([string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([strdup])

AC_OUTPUT([Makefile src/Makefile])
