#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([iaesni],[1.2], [hladky DOT jiri AT gmail DOT com])

AC_CONFIG_AUX_DIR(./config)
# Note that this directory must *exactly* match what was specified via
# -I in ACLOCAL_AMFLAGS in the top-level Makefile.am.
AC_CONFIG_MACRO_DIR(./config)

AC_CONFIG_SRCDIR([include/iaes_asm_interface.h])
AC_CONFIG_HEADERS([config.h])


AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CHOST], ["$host"], [Canonical host])
AC_CANONICAL_BUILD
AC_DEFINE_UNQUOTED([CBUILD], ["$build"], [Canonical build])
AC_CANONICAL_TARGET
AC_DEFINE_UNQUOTED([CTARGET], ["$target"], [Canonical target])

# Init automake
AM_INIT_AUTOMAKE([1.10 dist-bzip2 subdir-objects foreign tar-ustar])

LT_INIT

INTEL_AES_NI_LT_VERSION="1:0:0"
AC_SUBST(INTEL_AES_NI_LT_VERSION)
INTEL_AES_NI_LIB_VERSION=1.2.0
AC_SUBST(INTEL_AES_LIB_VERSION)

case "$target" in
  i386-*-* | i486-*-* | i586-*-* | i686-*-* )
    bitness=32
    arch_type=X86
    AC_DEFINE(ARCH_X86,,[Architecture is x86])
    ;;
  x86_64-*-*)
    bitness=64
    arch_type=X86_64
    AC_DEFINE(ARCH_X86_64,,[Architecture is x86_64])
    ;;
  *)
  AC_MSG_ERROR([unsupported target 'target' system - only x86 and x86_64 is supported]) 
    ;;
esac

AM_CONDITIONAL(ARCH_X86, test "$arch_type" = "X86")
AM_CONDITIONAL(ARCH_X86_64, test "$arch_type" = "X86_64")

# Checks for programs.
# CFLAGS="$CFLAGS -O3 -Wall -Wextra -m${bitness}"
# CFLAGS="$CFLAGS -O3 -Wall -Wextra"

AC_PROG_CC

AC_PATH_PROG([YASM], [yasm])
if test -z "$YASM"; then
  AC_MSG_ERROR([could not find 'yasm'])
fi 


case "$host_os" in
  *bsd*|linux*|beos|irix*|solaris*)
    YASM_FLAGS="-D__linux__ -g dwarf2 -f elf${bitness}"
    ;;
  [[cC]][[yY]][[gG]][[wW]][[iI]][[nN]]*|mingw32*|mks*)
    YASM_FLAGS="-f win${bitness}"
    ;;
esac

AC_SUBST(YASM_FLAGS)

CCAS=${YASM}
CCASFLAGS=${YASM_FLAGS}

AM_PROG_AS

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Setup libtool
AM_ENABLE_SHARED
AM_DISABLE_STATIC
LT_LANG([C])

# Checks for library functions.
AC_CONFIG_FILES([Makefile
                 src/Makefile
                 include/Makefile])
AC_OUTPUT

AC_MSG_RESULT([
Build options:
  $PACKAGE $VERSION
  yasm $YASM
  YASM_FLAGS $YASM_FLAGS
  target $target
  architecture $arch_type
  CFLAGS ${CFLAGS}
])
