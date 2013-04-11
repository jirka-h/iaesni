VERSION=@VERSION@

AM_CFLAGS = -Wall -Wextra

ACLOCAL_AMFLAGS = -I ./config

lib_LTLIBRARIES = libiaesni.la

libiaesni_la_LIBADD =
libiaesni_la_CPPFLAGS = -I$(top_srcdir)/include
libiaesni_la_LDFLAGS = -version-number @INTEL_AES_NI_LT_VERSION@

COMMON_SOURCES = \
intel_aes.c

SOURCES_X86 = \
x86/do_rdtsc.s \
x86/iaesx86.s

SOURCES_X86_64 = \
x64/do_rdtsc.s \
x64/iaesx64.s 

YASM = @YASM@

if ARCH_X86
EXTRA_SOURCES = $(SOURCES_X86)
EXTRA_DIST = $(SOURCES_X86_64) strip_yasm_args.sh
endif

if ARCH_X86_64
EXTRA_SOURCES = $(SOURCES_X86_64)
EXTRA_DIST = $(SOURCES_X86) strip_yasm_args.sh
endif

# Sources
libiaesni_la_SOURCES = $(COMMON_SOURCES) $(EXTRA_SOURCES)

STRIP_YASM_ARGS = sh ./strip_yasm_args.sh
SUFFIXES = .s

.s.lo:
	$(LIBTOOL) --mode=compile --tag=ASM $(STRIP_YASM_ARGS) $(CCAS) $(CCASFLAGS) -o $@ $<

bin_PROGRAMS = aessample aes_cbc_elb
aessample_CPPFLAGS = -I$(top_srcdir)/include
aessample_LDADD = libiaesni.la
aessample_SOURCES = aessample.c

aes_cbc_elb_CPPFLAGS = -I$(top_srcdir)/include
aes_cbc_elb_LDADD = libiaesni.la
aes_cbc_elb_SOURCES = aes_cbc_elb.c


MAINTAINERCLEANFILES = Makefile.in



