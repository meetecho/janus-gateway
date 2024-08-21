ACLOCAL_AMFLAGS = -I m4

# FIXME: These should be enabled once the code is safe for them. That requires
# some fairly big refactoring though, which can wait.
# AM_CFLAGS += -Wshadow -Wstrict-aliasing=2

# FIXME: make docs work with distcheck
DISTCHECK_CONFIGURE_FLAGS = --disable-docs --enable-post-processing

EXTRA_DIST = $(NULL)
CLEANFILES = $(NULL)

confdir = $(sysconfdir)/janus
conf_DATA = conf/janus.jcfg.sample

plugindir = $(libdir)/janus/plugins
transportdir = $(libdir)/janus/transports
eventdir = $(libdir)/janus/events
loggerdir = $(libdir)/janus/loggers

SUBDIRS = src html
dist_html_DATA = README.md

demosdir = $(datadir)/janus/demos
demos_DATA = $(NULL)

jsmodulesdir = $(datadir)/janus/javascript
jsmodules_DATA = html/demos/janus.js

%.sample: %.sample.in
	$(MKDIR_P) $(@D)
	$(AM_V_GEN) sed -e "\
	    s|[@]confdir[@]|$(confdir)|;\
	    s|[@]plugindir[@]|$(plugindir)|;\
	    s|[@]transportdir[@]|$(transportdir)|;\
	    s|[@]eventdir[@]|$(eventdir)|;\
	    s|[@]loggerdir[@]|$(loggerdir)|;\
	    s|[@]recordingsdir[@]|$(recordingsdir)|;\
	    s|[@]demosdir[@]|$(demosdir)|;\
	    s|[@]streamdir[@]|$(streamdir)|; \
	    s|[@]luadir[@]|$(luadir)|; \
	    s|[@]duktapedir[@]|$(duktapedir)|" \
	$< > $@ || rm $@

EXTRA_DIST += conf/janus.jcfg.sample.in
CLEANFILES += conf/janus.jcfg.sample


##
# Fuzzers checking
##

check-fuzzers: FORCE
	CC=$(CC) SKIP_JANUS_BUILD=1 LIB_FUZZING_ENGINE=fuzzers/standalone.o ./fuzzers/build.sh
	./fuzzers/run.sh rtcp_fuzzer out/rtcp_fuzzer_seed_corpus
	./fuzzers/run.sh rtp_fuzzer out/rtp_fuzzer_seed_corpus
	./fuzzers/run.sh sdp_fuzzer out/sdp_fuzzer_seed_corpus

.PHONY: FORCE
FORCE:

##
# Docs
##

if ENABLE_DOCS
SUBDIRS += docs
endif

##
# JavaScript module flavours for janus.js
##

if ENABLE_JAVASCRIPT_ES_MODULE
jsmodules_DATA += npm/dist/janus.es.js
endif

if ENABLE_JAVASCRIPT_UMD_MODULE
jsmodules_DATA += npm/dist/janus.umd.js
endif

if ENABLE_JAVASCRIPT_IIFE_MODULE
jsmodules_DATA += npm/dist/janus.iife.js
endif

if ENABLE_JAVASCRIPT_COMMON_JS_MODULE
jsmodules_DATA += npm/dist/janus.cjs.js
endif

EXTRA_DIST += $(jsmodules_DATA)

if ENABLE_JAVASCRIPT_MODULES

node_modules/rollup/dist/bin/rollup: package.json
	$(NPM) install && touch node_modules/rollup/dist/bin/rollup

npm/dist/janus.%.js: html/demos/janus.js node_modules/rollup/dist/bin/rollup npm/rollup.config.mjs npm/module.js
	$(NPM) run rollup -- --o $@ --f $*

endif

##
# Configuration
##

configs:
	$(MKDIR_P) $(DESTDIR)$(confdir)
	$(foreach config,$(conf_DATA),cp "$(CURDIR)/$(config)" "$(DESTDIR)$(confdir)/$(notdir $(basename $(config) .sample))";)
	$(MAKE) -C src configs

##
# Extra cleanup
##

clean-local:
	-rm -f docs/doxygen_sqlite3.db
