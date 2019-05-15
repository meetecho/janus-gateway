ACLOCAL_AMFLAGS = -I m4

# FIXME: These should be enabled once the code is safe for them. That requires
# some fairly big refactoring though, which can wait.
# AM_CFLAGS += -Wshadow -Wstrict-aliasing=2

# FIXME: make docs work with distcheck
DISTCHECK_CONFIGURE_FLAGS = --disable-docs --enable-post-processing

EXTRA_DIST = $(NULL)
CLEANFILES = $(NULL)

bin_PROGRAMS = janus

headerdir = $(includedir)/janus
header_HEADERS = apierror.h config.h log.h debug.h mutex.h record.h \
	rtcp.h rtp.h rtpsrtp.h sdp-utils.h ip-utils.h utils.h refcount.h text2pcap.h

pluginsheaderdir = $(includedir)/janus/plugins
pluginsheader_HEADERS = plugins/plugin.h

transportsheaderdir = $(includedir)/janus/transports
transportsheader_HEADERS = transports/transport.h

eventsheaderdir = $(includedir)/janus/events
eventsheader_HEADERS = events/eventhandler.h

confdir = $(sysconfdir)/janus
conf_DATA = conf/janus.jcfg.sample

plugindir = $(libdir)/janus/plugins
plugin_LTLIBRARIES = $(NULL)

transportdir = $(libdir)/janus/transports
transport_LTLIBRARIES = $(NULL)

eventdir = $(libdir)/janus/events
event_LTLIBRARIES = $(NULL)

SUBDIRS = html
dist_html_DATA = README.md

streamdir = $(datadir)/janus/streams
stream_DATA = $(NULL)

recordingsdir = $(datadir)/janus/recordings
recordings_DATA = $(NULL)

luadir = $(datadir)/janus/lua
lua_DATA = $(NULL)

duktapedir = $(datadir)/janus/duktape
duktape_DATA = $(NULL)

demosdir = $(datadir)/janus/demos
demos_DATA = $(NULL)

jsmodulesdir = $(datadir)/janus/javascript
jsmodules_DATA = html/janus.js

%.sample: %.sample.in
	$(MKDIR_P) $(@D)
	$(AM_V_GEN) sed -e "\
	    s|[@]confdir[@]|$(confdir)|;\
	    s|[@]plugindir[@]|$(plugindir)|;\
	    s|[@]transportdir[@]|$(transportdir)|;\
	    s|[@]eventdir[@]|$(eventdir)|;\
	    s|[@]recordingsdir[@]|$(recordingsdir)|;\
	    s|[@]demosdir[@]|$(demosdir)|;\
	    s|[@]streamdir[@]|$(streamdir)|; \
	    s|[@]luadir[@]|$(luadir)|; \
	    s|[@]duktapedir[@]|$(duktapedir)|" \
	$< > $@ || rm $@

EXTRA_DIST += conf/janus.jcfg.sample.in
CLEANFILES += conf/janus.jcfg.sample

##
# Janus
##

janus_SOURCES = \
	apierror.c \
	apierror.h \
	auth.c \
	auth.h \
	cmdline.c \
	cmdline.h \
	config.c \
	config.h \
	debug.h \
	dtls.c \
	dtls.h \
	dtls-bio.c \
	dtls-bio.h \
	events.c \
	events.h \
	ice.c \
	ice.h \
	janus.c \
	janus.h \
	log.c \
	log.h \
	mutex.h \
	record.c \
	record.h \
	refcount.h \
	rtcp.c \
	rtcp.h \
	rtp.c \
	rtp.h \
	rtpsrtp.h \
	sctp.c \
	sctp.h \
	sdp.c \
	sdp.h \
	sdp-utils.c \
	sdp-utils.h \
	ip-utils.c \
	ip-utils.h \
	turnrest.c \
	turnrest.h \
	utils.c \
	utils.h \
	version.c \
	version.h \
	text2pcap.c \
	text2pcap.h \
	plugins/plugin.c \
	plugins/plugin.h \
	transports/transport.h \
	transports/transport.c \
	events/eventhandler.h \
	$(NULL)

janus_CFLAGS = \
	$(AM_CFLAGS) \
	$(JANUS_CFLAGS) \
	-DPLUGINDIR=\"$(plugindir)\" \
	-DTRANSPORTDIR=\"$(transportdir)\" \
	-DEVENTDIR=\"$(eventdir)\" \
	-DCONFDIR=\"$(confdir)\" \
	$(BORINGSSL_CFLAGS) \
	$(NULL)

janus_LDADD = \
	$(BORINGSSL_LIBS) \
	$(JANUS_LIBS) \
	$(JANUS_MANUAL_LIBS) \
	$(NULL)

dist_man1_MANS = janus.1

bin_PROGRAMS += janus-cfgconv

janus_cfgconv_SOURCES = \
	janus-cfgconv.c \
	config.c \
	log.c \
	utils.c \
	version.c \
	$(NULL)

janus_cfgconv_CFLAGS = \
	$(AM_CFLAGS) \
	$(JANUS_CFLAGS) \
	$(NULL)

janus_cfgconv_LDADD = \
	$(JANUS_LIBS) \
	$(JANUS_MANUAL_LIBS) \
	$(NULL)

dist_man1_MANS += janus-cfgconv.1

BUILT_SOURCES = cmdline.c cmdline.h version.c

cmdline.h: cmdline.c

cmdline.c: janus.c
	gengetopt --set-package="janus" --set-version="$(VERSION)" < janus.ggo

directory = .git
dir_target = $(directory)-$(wildcard $(directory))
dir_present = $(directory)-$(directory)
dir_absent = $(directory)-

if WITH_SOURCE_DATE_EPOCH
build_date = $(shell LC_ALL=C date --utc --date="@$(SOURCE_DATE_EPOCH)")
else
build_date = $(shell date)
endif

version.c: FORCE | $(dir_target)
	echo "$(build_date)" | awk 'BEGIN {} {print "const char *janus_build_git_time = \""$$0"\";"} END {} ' >> version.c
	echo "$(JANUS_VERSION)" | awk 'BEGIN {} {print "int janus_version = "$$0";"} END {} ' >> version.c
	echo "$(JANUS_VERSION_STRING)" | awk 'BEGIN {} {print "const char *janus_version_string = \""$$0"\";"} END {} ' >> version.c
	pkg-config --modversion nice | awk 'BEGIN {} {print "const char *libnice_version_string = \""$$0"\";"} END {} ' >> version.c

$(dir_present):
	`which git` rev-parse HEAD | awk 'BEGIN {print "#include \"version.h\""} {print "const char *janus_build_git_sha = \"" $$0"\";"} END {}' > version.c

$(dir_absent):
	echo "not-a-git-repo" | awk 'BEGIN {print "#include \"version.h\""} {print "const char *janus_build_git_sha = \"" $$0"\";"} END {}' > version.c

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

EXTRA_DIST += janus.ggo
CLEANFILES += cmdline.c cmdline.h version.c

##
# Transports
##

transports_cflags = \
	$(AM_CFLAGS) \
	$(TRANSPORTS_CFLAGS) \
	$(NULL)

transports_libadd = \
	$(TRANSPORTS_LIBS) \
	$(NULL)

if ENABLE_REST
transport_LTLIBRARIES += transports/libjanus_http.la
transports_libjanus_http_la_SOURCES = transports/janus_http.c
transports_libjanus_http_la_CFLAGS = $(transports_cflags) $(MHD_CFLAGS)
transports_libjanus_http_la_LDFLAGS = $(transports_ldflags) $(MHD_LDFLAGS) $(MHD_LIBS)
transports_libjanus_http_la_LIBADD = $(transports_libadd) $(MHD_LDFLAGS)
conf_DATA += conf/janus.transport.http.jcfg.sample
EXTRA_DIST += conf/janus.transport.http.jcfg.sample
endif

if ENABLE_WEBSOCKETS
transport_LTLIBRARIES += transports/libjanus_websockets.la
transports_libjanus_websockets_la_SOURCES = transports/janus_websockets.c
transports_libjanus_websockets_la_CFLAGS = $(transports_cflags)
transports_libjanus_websockets_la_LDFLAGS = $(transports_ldflags) $(WS_MANUAL_LIBS)
transports_libjanus_websockets_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.websockets.jcfg.sample
EXTRA_DIST += conf/janus.transport.websockets.jcfg.sample
endif

if ENABLE_RABBITMQ
transport_LTLIBRARIES += transports/libjanus_rabbitmq.la
transports_libjanus_rabbitmq_la_SOURCES = transports/janus_rabbitmq.c
transports_libjanus_rabbitmq_la_CFLAGS = $(transports_cflags)
transports_libjanus_rabbitmq_la_LDFLAGS = $(transports_ldflags) -lrabbitmq
transports_libjanus_rabbitmq_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.rabbitmq.jcfg.sample
EXTRA_DIST += conf/janus.transport.rabbitmq.jcfg.sample
endif

if ENABLE_MQTT
transport_LTLIBRARIES += transports/libjanus_mqtt.la
transports_libjanus_mqtt_la_SOURCES = transports/janus_mqtt.c
transports_libjanus_mqtt_la_CFLAGS = $(transports_cflags)
transports_libjanus_mqtt_la_LDFLAGS = $(transports_ldflags) -lpaho-mqtt3as
transports_libjanus_mqtt_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.mqtt.jcfg.sample
EXTRA_DIST += conf/janus.transport.mqtt.jcfg.sample
endif

if ENABLE_PFUNIX
transport_LTLIBRARIES += transports/libjanus_pfunix.la
transports_libjanus_pfunix_la_SOURCES = transports/janus_pfunix.c
transports_libjanus_pfunix_la_CFLAGS = $(transports_cflags)
transports_libjanus_pfunix_la_LDFLAGS = $(transports_ldflags) $(LIBSYSTEMD_LIBS)
transports_libjanus_pfunix_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.pfunix.jcfg.sample
EXTRA_DIST += conf/janus.transport.pfunix.jcfg.sample
endif

if ENABLE_NANOMSG
transport_LTLIBRARIES += transports/libjanus_nanomsg.la
transports_libjanus_nanomsg_la_SOURCES = transports/janus_nanomsg.c
transports_libjanus_nanomsg_la_CFLAGS = $(transports_cflags)
transports_libjanus_nanomsg_la_LDFLAGS = $(transports_ldflags) -lnanomsg
transports_libjanus_nanomsg_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.nanomsg.jcfg.sample
EXTRA_DIST += conf/janus.transport.nanomsg.jcfg.sample
endif

##
# Event handlers
##

events_cflags = \
	$(AM_CFLAGS) \
	$(EVENTS_CFLAGS) \
	$(NULL)

events_libadd = \
	$(EVENTS_LIBS) \
	$(NULL)

if ENABLE_SAMPLEEVH
event_LTLIBRARIES += events/libjanus_sampleevh.la
events_libjanus_sampleevh_la_SOURCES = events/janus_sampleevh.c
events_libjanus_sampleevh_la_CFLAGS = $(events_cflags)
events_libjanus_sampleevh_la_LDFLAGS = $(events_ldflags) -lcurl -lm
events_libjanus_sampleevh_la_LIBADD = $(events_libadd)
conf_DATA += conf/janus.eventhandler.sampleevh.jcfg.sample
EXTRA_DIST += conf/janus.eventhandler.sampleevh.jcfg.sample
endif

if ENABLE_RABBITMQEVH
event_LTLIBRARIES += events/libjanus_rabbitmqevh.la
events_libjanus_rabbitmqevh_la_SOURCES = events/janus_rabbitmqevh.c
events_libjanus_rabbitmqevh_la_CFLAGS = $(events_cflags)
events_libjanus_rabbitmqevh_la_LDFLAGS = $(events_ldflags) -lrabbitmq
events_libjanus_rabbitmqevh_la_LIBADD = $(events_libadd)
conf_DATA += conf/janus.eventhandler.rabbitmqevh.jcfg.sample
EXTRA_DIST += conf/janus.eventhandler.rabbitmqevh.jcfg.sample
endif

if ENABLE_MQTTEVH
event_LTLIBRARIES += events/libjanus_mqttevh.la
events_libjanus_mqttevh_la_SOURCES = events/janus_mqttevh.c
events_libjanus_mqttevh_la_CFLAGS = $(events_cflags)
events_libjanus_mqttevh_la_LDFLAGS = $(events_ldflags) -lpaho-mqtt3as
events_libjanus_mqttevh_la_LIBADD = $(events_libadd)
conf_DATA += conf/janus.eventhandler.mqttevh.jcfg.sample
EXTRA_DIST += conf/janus.eventhandler.mqttevh.jcfg.sample
endif

##
# Plugins
##

plugins_cflags = \
	$(AM_CFLAGS) \
	$(PLUGINS_CFLAGS) \
	$(NULL)

plugins_libadd = \
	$(PLUGINS_LIBS) \
	$(NULL)

if ENABLE_PLUGIN_AUDIOBRIDGE
plugin_LTLIBRARIES += plugins/libjanus_audiobridge.la
plugins_libjanus_audiobridge_la_SOURCES = plugins/janus_audiobridge.c
plugins_libjanus_audiobridge_la_CFLAGS = $(plugins_cflags) $(OPUS_CFLAGS)
plugins_libjanus_audiobridge_la_LDFLAGS = $(plugins_ldflags) $(OPUS_LDFLAGS) $(OPUS_LIBS)
plugins_libjanus_audiobridge_la_LIBADD = $(plugins_libadd) $(OPUS_LIBADD)
conf_DATA += conf/janus.plugin.audiobridge.jcfg.sample
EXTRA_DIST += conf/janus.plugin.audiobridge.jcfg.sample
endif

if ENABLE_PLUGIN_ECHOTEST
plugin_LTLIBRARIES += plugins/libjanus_echotest.la
plugins_libjanus_echotest_la_SOURCES = plugins/janus_echotest.c
plugins_libjanus_echotest_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_echotest_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_echotest_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.echotest.jcfg.sample
EXTRA_DIST += conf/janus.plugin.echotest.jcfg.sample
endif

if ENABLE_PLUGIN_RECORDPLAY
plugin_LTLIBRARIES += plugins/libjanus_recordplay.la
plugins_libjanus_recordplay_la_SOURCES = plugins/janus_recordplay.c
plugins_libjanus_recordplay_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_recordplay_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_recordplay_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.recordplay.jcfg.sample
recordings_DATA += \
	plugins/recordings/1234.nfo \
	plugins/recordings/rec-sample-audio.mjr \
	plugins/recordings/rec-sample-video.mjr
EXTRA_DIST += \
	conf/janus.plugin.recordplay.jcfg.sample.in \
	$(recordings_DATA)
CLEANFILES += conf/janus.plugin.recordplay.jcfg.sample
endif

if ENABLE_PLUGIN_SIP
plugin_LTLIBRARIES += plugins/libjanus_sip.la
plugins_libjanus_sip_la_SOURCES = plugins/janus_sip.c
plugins_libjanus_sip_la_CFLAGS = $(plugins_cflags) $(SOFIA_CFLAGS)
plugins_libjanus_sip_la_LDFLAGS = $(plugins_ldflags) $(SOFIA_LDFLAGS) $(SOFIA_LIBS)
plugins_libjanus_sip_la_LIBADD = $(plugins_libadd) $(SOFIA_LIBADD)
conf_DATA += conf/janus.plugin.sip.jcfg.sample
EXTRA_DIST += conf/janus.plugin.sip.jcfg.sample
endif

if ENABLE_PLUGIN_SIPRE
plugin_LTLIBRARIES += plugins/libjanus_sipre.la
plugins_libjanus_sipre_la_SOURCES = plugins/janus_sipre.c
plugins_libjanus_sipre_la_CFLAGS = $(plugins_cflags) $(LIBRE_CFLAGS)
plugins_libjanus_sipre_la_LDFLAGS = $(plugins_ldflags) $(LIBRE_LDFLAGS) $(LIBRE_LIBS)
plugins_libjanus_sipre_la_LIBADD = $(plugins_libadd) $(LIBRE_LIBADD)
conf_DATA += conf/janus.plugin.sipre.jcfg.sample
EXTRA_DIST += conf/janus.plugin.sipre.jcfg.sample
endif

if ENABLE_PLUGIN_NOSIP
plugin_LTLIBRARIES += plugins/libjanus_nosip.la
plugins_libjanus_nosip_la_SOURCES = plugins/janus_nosip.c
plugins_libjanus_nosip_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_nosip_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_nosip_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.nosip.jcfg.sample
EXTRA_DIST += conf/janus.plugin.nosip.jcfg.sample
endif

if ENABLE_PLUGIN_STREAMING
plugin_LTLIBRARIES += plugins/libjanus_streaming.la
plugins_libjanus_streaming_la_SOURCES = plugins/janus_streaming.c
plugins_libjanus_streaming_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_streaming_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_streaming_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.streaming.jcfg.sample
stream_DATA += \
	plugins/streams/music.mulaw \
	plugins/streams/radio.alaw \
	plugins/streams/test_gstreamer.sh \
	plugins/streams/test_gstreamer_1.sh
EXTRA_DIST += \
	conf/janus.plugin.streaming.jcfg.sample.in \
	$(stream_DATA)
CLEANFILES += conf/janus.plugin.streaming.jcfg.sample
endif

if ENABLE_PLUGIN_VIDEOCALL
plugin_LTLIBRARIES += plugins/libjanus_videocall.la
plugins_libjanus_videocall_la_SOURCES = plugins/janus_videocall.c
plugins_libjanus_videocall_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_videocall_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_videocall_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.videocall.jcfg.sample
EXTRA_DIST += conf/janus.plugin.videocall.jcfg.sample
endif

if ENABLE_PLUGIN_VIDEOROOM
plugin_LTLIBRARIES += plugins/libjanus_videoroom.la
plugins_libjanus_videoroom_la_SOURCES = plugins/janus_videoroom.c
plugins_libjanus_videoroom_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_videoroom_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_videoroom_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.videoroom.jcfg.sample
EXTRA_DIST += conf/janus.plugin.videoroom.jcfg.sample
endif

if ENABLE_PLUGIN_VOICEMAIL
plugin_LTLIBRARIES += plugins/libjanus_voicemail.la
plugins_libjanus_voicemail_la_SOURCES = plugins/janus_voicemail.c
plugins_libjanus_voicemail_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_voicemail_la_LDFLAGS = $(plugins_ldflags) -logg
plugins_libjanus_voicemail_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.voicemail.jcfg.sample
EXTRA_DIST += conf/janus.plugin.voicemail.jcfg.sample.in
CLEANFILES += conf/janus.plugin.voicemail.jcfg.sample
endif

if ENABLE_PLUGIN_TEXTROOM
plugin_LTLIBRARIES += plugins/libjanus_textroom.la
plugins_libjanus_textroom_la_SOURCES = plugins/janus_textroom.c
plugins_libjanus_textroom_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_textroom_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_textroom_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.textroom.jcfg.sample
EXTRA_DIST += conf/janus.plugin.textroom.jcfg.sample
endif

if ENABLE_PLUGIN_LUA
plugin_LTLIBRARIES += plugins/libjanus_lua.la
plugins_libjanus_lua_la_SOURCES = plugins/janus_lua.c plugins/janus_lua_data.h plugins/janus_lua_extra.c plugins/janus_lua_extra.h
plugins_libjanus_lua_la_CFLAGS = $(plugins_cflags) $(LUA_CFLAGS)
plugins_libjanus_lua_la_LDFLAGS = $(plugins_ldflags) $(LUA_LDFLAGS) $(LUA_LIBS)
plugins_libjanus_lua_la_LIBADD = $(plugins_libadd) $(LUA_LIBADD)
conf_DATA += conf/janus.plugin.lua.jcfg.sample
lua_DATA += \
	plugins/lua/echotest.lua \
	plugins/lua/videoroom.lua \
	plugins/lua/janus-logger.lua \
	plugins/lua/janus-sdp.lua
EXTRA_DIST += conf/janus.plugin.lua.jcfg.sample.in
endif

if ENABLE_PLUGIN_DUKTAPE
plugin_LTLIBRARIES += plugins/libjanus_duktape.la
plugins_libjanus_duktape_la_SOURCES = plugins/janus_duktape.c \
	plugins/janus_duktape_data.h plugins/janus_duktape_extra.c plugins/janus_duktape_extra.h \
	plugins/duktape-deps/duktape.c plugins/duktape-deps/duk_config.h plugins/duktape-deps/duktape.h \
	plugins/duktape-deps/duk_module_duktape.c plugins/duktape-deps/duk_module_duktape.h \
	plugins/duktape-deps/duk_console.c plugins/duktape-deps/duk_console.h
plugins_libjanus_duktape_la_CFLAGS = $(plugins_cflags) $(DUKTAPE_CFLAGS)
plugins_libjanus_duktape_la_LDFLAGS = $(plugins_ldflags) $(DUKTAPE_LDFLAGS) $(DUKTAPE_LIBS)
plugins_libjanus_duktape_la_LIBADD = $(plugins_libadd) $(DUKTAPE_LIBADD)
conf_DATA += conf/janus.plugin.duktape.jcfg.sample
duktape_DATA += \
	plugins/duktape/echotest.js \
	plugins/duktape/janus-sdp.js
EXTRA_DIST += conf/janus.plugin.duktape.jcfg.sample.in
endif


##
# Post-processing
##

if ENABLE_POST_PROCESSING
bin_PROGRAMS += janus-pp-rec

janus_pp_rec_SOURCES = \
	postprocessing/pp-g711.c \
	postprocessing/pp-g711.h \
	postprocessing/pp-g722.c \
	postprocessing/pp-g722.h \
	postprocessing/pp-h264.c \
	postprocessing/pp-h264.h \
	postprocessing/pp-opus.c \
	postprocessing/pp-opus.h \
	postprocessing/pp-opus-silence.h \
	postprocessing/pp-rtp.h \
	postprocessing/pp-srt.c \
	postprocessing/pp-srt.h \
	postprocessing/pp-webm.c \
	postprocessing/pp-webm.h \
	postprocessing/janus-pp-rec.c \
	log.c \
	version.c \
	$(NULL)

janus_pp_rec_CFLAGS = \
	$(AM_CFLAGS) \
	$(POST_PROCESSING_CFLAGS) \
	$(NULL)

janus_pp_rec_LDADD = \
	$(POST_PROCESSING_LIBS) \
	$(NULL)
endif
dist_man1_MANS += postprocessing/janus-pp-rec.1

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
jsmodules_DATA += npm/bundles/janus.es.js
endif

if ENABLE_JAVASCRIPT_UMD_MODULE
jsmodules_DATA += npm/bundles/janus.umd.js
endif

if ENABLE_JAVASCRIPT_IIFE_MODULE
jsmodules_DATA += npm/bundles/janus.iife.js
endif

if ENABLE_JAVASCRIPT_COMMON_JS_MODULE
jsmodules_DATA += npm/bundles/janus.cjs.js
endif

EXTRA_DIST += $(jsmodules_DATA)

if ENABLE_JAVASCRIPT_MODULES

npm/node_modules/rollup/bin/rollup: npm/package.json
	cd npm && $(NPM) install && touch node_modules/rollup/bin/rollup

npm/bundles/janus.%.js: html/janus.js npm/node_modules/rollup/bin/rollup npm/rollup.config.js npm/module.js
	cd npm && $(NPM) run rollup -- --o $(patsubst npm/%,%,$@) --f $*

endif

##
# Configuration
##

configs:
	$(MKDIR_P) $(DESTDIR)$(confdir)
	$(foreach config,$(conf_DATA),cp "$(CURDIR)/$(config)" "$(DESTDIR)$(confdir)/$(notdir $(basename $(config) .sample))";)

##
# Extra cleanup
##

clean-local:
	-rm -f docs/doxygen_sqlite3.db
