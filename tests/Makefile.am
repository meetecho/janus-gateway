## Process this file with automake to produce Makefile.in

TESTS = check_duktape_extra_curl
check_PROGRAMS = check_duktape_extra_curl
check_duktape_extra_curl_SOURCES = $(top_builddir)/plugins/duktape-deps/duk_module_duktape.c \
                                   $(top_builddir)/plugins/duktape-deps/duk_console.c \
                                   $(top_builddir)/plugins/duktape-deps/duktape.c \
                                   $(top_builddir)/plugins/duktape-deps/dukcurl/dukcurl.c \
                                   $(top_builddir)/plugins/janus_duktape_extra_curl.c \
                                   check_duktape_extra_curl.c
check_duktape_extra_curl_CFLAGS = @CHECK_CFLAGS@
check_duktape_extra_curl_LDADD = @CHECK_LIBS@ @JANUS_LIBS@ @GLIB_LIBS@ @MHD_LIBS@ @LIBCURL_LIBS@ 
