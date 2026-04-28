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

loggersheaderdir = $(includedir)/janus/loggers
loggersheader_HEADERS = loggers/logger.h

confdir = $(sysconfdir)/janus
conf_DATA = $(NULL)

demosdir = $(datadir)/janus/html

plugindir = $(libdir)/janus/plugins
plugin_LTLIBRARIES = $(NULL)

transportdir = $(libdir)/janus/transports
transport_LTLIBRARIES = $(NULL)

eventdir = $(libdir)/janus/events
event_LTLIBRARIES = $(NULL)

loggerdir = $(libdir)/janus/loggers
logger_LTLIBRARIES = $(NULL)

streamdir = $(datadir)/janus/streams
stream_DATA = $(NULL)

recordingsdir = $(datadir)/janus/recordings
recordings_DATA = $(NULL)

luadir = $(datadir)/janus/lua
lua_DATA = $(NULL)

duktapedir = $(datadir)/janus/duktape
duktape_DATA = $(NULL)

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

##
# Janus
##

janus_SOURCES = \
	apierror.c \
	apierror.h \
	auth.c \
	auth.h \
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
	options.c \
	options.h \
	record.c \
	record.h \
	refcount.h \
	rtcp.c \
	rtcp.h \
	rtp.c \
	rtp.h \
	rtpfwd.c \
	rtpfwd.h \
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
	loggers/logger.h \
	$(NULL)

janus_CFLAGS = \
	$(AM_CFLAGS) \
	$(JANUS_CFLAGS) \
	$(LIBSRTP_CFLAGS) \
	$(LIBCURL_CFLAGS) \
	-DPLUGINDIR=\"$(plugindir)\" \
	-DTRANSPORTDIR=\"$(transportdir)\" \
	-DEVENTDIR=\"$(eventdir)\" \
	-DLOGGERDIR=\"$(loggerdir)\" \
	-DCONFDIR=\"$(confdir)\" \
	$(BORINGSSL_CFLAGS) \
	$(NULL)

janus_LDADD = \
	$(BORINGSSL_LIBS) \
	$(JANUS_LIBS) \
	$(JANUS_MANUAL_LIBS) \
	$(LIBSRTP_LDFLAGS) $(LIBSRTP_LIBS) \
	$(LIBCURL_LDFLAGS) $(LIBCURL_LIBS) \
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

BUILT_SOURCES = version.c

directory = ../.git
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
	PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" "$(PKG_CONFIG)" --modversion nice | awk 'BEGIN {} {print "const char *libnice_version_string = \""$$0"\";"} END {} ' >> version.c

$(dir_present):
	`which git` rev-parse HEAD | awk 'BEGIN {print "#include \"version.h\""} {print "const char *janus_build_git_sha = \"" $$0"\";"} END {}' > version.c

$(dir_absent):
	echo "not-a-git-repo" | awk 'BEGIN {print "#include \"version.h\""} {print "const char *janus_build_git_sha = \"" $$0"\";"} END {}' > version.c

CLEANFILES += version.c

##
# Transports
##

transports_cflags = \
	$(AM_CFLAGS) \
	$(TRANSPORTS_CFLAGS) \
	$(NULL)

transports_ldflags = \
	-version-info $(JANUS_VERSION_SO) \
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
conf_DATA += ../conf/janus.transport.http.jcfg.sample
EXTRA_DIST += ../conf/janus.transport.http.jcfg.sample
endif

if ENABLE_WEBSOCKETS
transport_LTLIBRARIES += transports/libjanus_websockets.la
transports_libjanus_websockets_la_SOURCES = transports/janus_websockets.c
transports_libjanus_websockets_la_CFLAGS = $(transports_cflags)
transports_libjanus_websockets_la_LDFLAGS = $(transports_ldflags) $(WS_MANUAL_LIBS)
transports_libjanus_websockets_la_LIBADD = $(transports_libadd)
conf_DATA += ../conf/janus.transport.websockets.jcfg.sample
EXTRA_DIST += ../conf/janus.transport.websockets.jcfg.sample
endif

if ENABLE_RABBITMQ
transport_LTLIBRARIES += transports/libjanus_rabbitmq.la
transports_libjanus_rabbitmq_la_SOURCES = transports/janus_rabbitmq.c
transports_libjanus_rabbitmq_la_CFLAGS = $(transports_cflags)
transports_libjanus_rabbitmq_la_LDFLAGS = $(transports_ldflags) -lrabbitmq
transports_libjanus_rabbitmq_la_LIBADD = $(transports_libadd)
conf_DATA += ../conf/janus.transport.rabbitmq.jcfg.sample
EXTRA_DIST += ../conf/janus.transport.rabbitmq.jcfg.sample
endif

if ENABLE_MQTT
transport_LTLIBRARIES += transports/libjanus_mqtt.la
transports_libjanus_mqtt_la_SOURCES = transports/janus_mqtt.c
transports_libjanus_mqtt_la_CFLAGS = $(transports_cflags)
transports_libjanus_mqtt_la_LDFLAGS = $(transports_ldflags) -lpaho-mqtt3as
transports_libjanus_mqtt_la_LIBADD = $(transports_libadd)
conf_DATA += ../conf/janus.transport.mqtt.jcfg.sample
EXTRA_DIST += ../conf/janus.transport.mqtt.jcfg.sample
endif

if ENABLE_PFUNIX
transport_LTLIBRARIES += transports/libjanus_pfunix.la
transports_libjanus_pfunix_la_SOURCES = transports/janus_pfunix.c
transports_libjanus_pfunix_la_CFLAGS = $(transports_cflags)
transports_libjanus_pfunix_la_LDFLAGS = $(transports_ldflags) $(LIBSYSTEMD_LIBS)
transports_libjanus_pfunix_la_LIBADD = $(transports_libadd)
conf_DATA += ../conf/janus.transport.pfunix.jcfg.sample
EXTRA_DIST += ../conf/janus.transport.pfunix.jcfg.sample
endif

if ENABLE_NANOMSG
transport_LTLIBRARIES += transports/libjanus_nanomsg.la
transports_libjanus_nanomsg_la_SOURCES = transports/janus_nanomsg.c
transports_libjanus_nanomsg_la_CFLAGS = $(transports_cflags)
transports_libjanus_nanomsg_la_LDFLAGS = $(transports_ldflags) -lnanomsg
transports_libjanus_nanomsg_la_LIBADD = $(transports_libadd)
conf_DATA += ../conf/janus.transport.nanomsg.jcfg.sample
EXTRA_DIST += ../conf/janus.transport.nanomsg.jcfg.sample
endif

##
# Event handlers
##

events_cflags = \
	$(AM_CFLAGS) \
	$(EVENTS_CFLAGS) \
	$(NULL)

events_ldflags = \
	-version-info $(JANUS_VERSION_SO) \
	$(NULL)

events_libadd = \
	$(EVENTS_LIBS) \
	$(NULL)

if ENABLE_SAMPLEEVH
event_LTLIBRARIES += events/libjanus_sampleevh.la
events_libjanus_sampleevh_la_SOURCES = events/janus_sampleevh.c
events_libjanus_sampleevh_la_CFLAGS = $(events_cflags) $(LIBCURL_CFLAGS)
events_libjanus_sampleevh_la_LDFLAGS = $(events_ldflags) $(LIBCURL_LDFLAGS) $(LIBCURL_LIBS) -lm
events_libjanus_sampleevh_la_LIBADD = $(events_libadd) $(LIBCURL_LIBADD)
conf_DATA += ../conf/janus.eventhandler.sampleevh.jcfg.sample
EXTRA_DIST += ../conf/janus.eventhandler.sampleevh.jcfg.sample
endif

if ENABLE_WSEVH
event_LTLIBRARIES += events/libjanus_wsevh.la
events_libjanus_wsevh_la_SOURCES = events/janus_wsevh.c
events_libjanus_wsevh_la_CFLAGS = $(events_cflags)
events_libjanus_wsevh_la_LDFLAGS = $(events_ldflags) $(WS_MANUAL_LIBS)
events_libjanus_wsevh_la_LIBADD = $(events_libadd)
conf_DATA += ../conf/janus.eventhandler.wsevh.jcfg.sample
EXTRA_DIST += ../conf/janus.eventhandler.wsevh.jcfg.sample
endif

if ENABLE_RABBITMQEVH
event_LTLIBRARIES += events/libjanus_rabbitmqevh.la
events_libjanus_rabbitmqevh_la_SOURCES = events/janus_rabbitmqevh.c
events_libjanus_rabbitmqevh_la_CFLAGS = $(events_cflags)
events_libjanus_rabbitmqevh_la_LDFLAGS = $(events_ldflags) -lrabbitmq
events_libjanus_rabbitmqevh_la_LIBADD = $(events_libadd)
conf_DATA += ../conf/janus.eventhandler.rabbitmqevh.jcfg.sample
EXTRA_DIST += ../conf/janus.eventhandler.rabbitmqevh.jcfg.sample
endif

if ENABLE_MQTTEVH
event_LTLIBRARIES += events/libjanus_mqttevh.la
events_libjanus_mqttevh_la_SOURCES = events/janus_mqttevh.c
events_libjanus_mqttevh_la_CFLAGS = $(events_cflags)
events_libjanus_mqttevh_la_LDFLAGS = $(events_ldflags) -lpaho-mqtt3as
events_libjanus_mqttevh_la_LIBADD = $(events_libadd)
conf_DATA += ../conf/janus.eventhandler.mqttevh.jcfg.sample
EXTRA_DIST += ../conf/janus.eventhandler.mqttevh.jcfg.sample
endif

if ENABLE_NANOMSGEVH
event_LTLIBRARIES += events/libjanus_nanomsgevh.la
events_libjanus_nanomsgevh_la_SOURCES = events/janus_nanomsgevh.c
events_libjanus_nanomsgevh_la_CFLAGS = $(events_cflags)
events_libjanus_nanomsgevh_la_LDFLAGS = $(events_ldflags) -lnanomsg
events_libjanus_nanomsgevh_la_LIBADD = $(events_libadd)
conf_DATA += ../conf/janus.eventhandler.nanomsgevh.jcfg.sample
EXTRA_DIST += ../conf/janus.eventhandler.nanomsgevh.jcfg.sample
endif

if ENABLE_GELFEVH
event_LTLIBRARIES += events/libjanus_gelfevh.la
events_libjanus_gelfevh_la_SOURCES = events/janus_gelfevh.c
events_libjanus_gelfevh_la_CFLAGS = $(events_cflags)
events_libjanus_gelfevh_la_LDFLAGS = $(events_ldflags)
events_libjanus_gelfevh_la_LIBADD = $(events_libadd)
conf_DATA += ../conf/janus.eventhandler.gelfevh.jcfg.sample
EXTRA_DIST += ../conf/janus.eventhandler.gelfevh.jcfg.sample
endif

##
# Loggers
##

loggers_cflags = \
	$(AM_CFLAGS) \
	$(LOGGERS_CFLAGS) \
	$(NULL)

loggers_ldflags = \
	-version-info $(JANUS_VERSION_SO) \
	$(NULL)

loggers_libadd = \
	$(LOGGERS_LIBS) \
	$(NULL)

if ENABLE_JSONLOGGER
logger_LTLIBRARIES += loggers/libjanus_jsonlog.la
loggers_libjanus_jsonlog_la_SOURCES = loggers/janus_jsonlog.c
loggers_libjanus_jsonlog_la_CFLAGS = $(loggers_cflags)
loggers_libjanus_jsonlog_la_LDFLAGS = $(loggers_ldflags)
loggers_libjanus_jsonlog_la_LIBADD = $(loggers_libadd)
conf_DATA += ../conf/janus.logger.jsonlog.jcfg.sample
EXTRA_DIST += ../conf/janus.logger.jsonlog.jcfg.sample
endif

##
# Plugins
##

plugins_cflags = \
	$(AM_CFLAGS) \
	$(PLUGINS_CFLAGS) \
	$(NULL)

plugins_ldflags = \
	-version-info $(JANUS_VERSION_SO) \
	$(NULL)

plugins_libadd = \
	$(PLUGINS_LIBS) \
	$(NULL)

if ENABLE_PLUGIN_AUDIOBRIDGE
plugin_LTLIBRARIES += plugins/libjanus_audiobridge.la
plugins_libjanus_audiobridge_la_SOURCES = plugins/janus_audiobridge.c \
	plugins/audiobridge-deps/jitter.c plugins/audiobridge-deps/resample.c plugins/audiobridge-deps/arch.h \
	plugins/audiobridge-deps/os_support.h plugins/audiobridge-deps/speex/speex_jitter.h plugins/audiobridge-deps/speex/speex_resampler.h \
	plugins/audiobridge-deps/speex/speexdsp_types.h plugins/audiobridge-deps/speex/speexdsp_config_types.h
plugins_libjanus_audiobridge_la_CFLAGS = $(plugins_cflags) $(OPUS_CFLAGS) $(OGG_CFLAGS) $(RNNOISE_CFLAGS) $(LIBSRTP_CFLAGS)
plugins_libjanus_audiobridge_la_LDFLAGS = $(plugins_ldflags) $(OPUS_LDFLAGS) $(OPUS_LIBS) $(OGG_LDFLAGS) $(OGG_LIBS) $(RNNOISE_LDFLAGS) $(RNNOISE_LIBS)
plugins_libjanus_audiobridge_la_LIBADD = $(plugins_libadd) $(OPUS_LIBADD) $(OGG_LIBADD) $(RNNOISE_LIBADD)
conf_DATA += ../conf/janus.plugin.audiobridge.jcfg.sample
EXTRA_DIST += ../conf/janus.plugin.audiobridge.jcfg.sample
endif

if ENABLE_PLUGIN_ECHOTEST
plugin_LTLIBRARIES += plugins/libjanus_echotest.la
plugins_libjanus_echotest_la_SOURCES = plugins/janus_echotest.c
plugins_libjanus_echotest_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_echotest_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_echotest_la_LIBADD = $(plugins_libadd)
conf_DATA += ../conf/janus.plugin.echotest.jcfg.sample
EXTRA_DIST += ../conf/janus.plugin.echotest.jcfg.sample
endif

if ENABLE_PLUGIN_RECORDPLAY
plugin_LTLIBRARIES += plugins/libjanus_recordplay.la
plugins_libjanus_recordplay_la_SOURCES = plugins/janus_recordplay.c
plugins_libjanus_recordplay_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_recordplay_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_recordplay_la_LIBADD = $(plugins_libadd)
conf_DATA += ../conf/janus.plugin.recordplay.jcfg.sample
recordings_DATA += \
	plugins/recordings/1234.nfo \
	plugins/recordings/rec-sample-audio.mjr \
	plugins/recordings/rec-sample-video.mjr
EXTRA_DIST += \
	../conf/janus.plugin.recordplay.jcfg.sample.in \
	$(recordings_DATA)
CLEANFILES += ../conf/janus.plugin.recordplay.jcfg.sample
endif

if ENABLE_PLUGIN_SIP
plugin_LTLIBRARIES += plugins/libjanus_sip.la
plugins_libjanus_sip_la_SOURCES = plugins/janus_sip.c
plugins_libjanus_sip_la_CFLAGS = $(plugins_cflags) $(SOFIA_CFLAGS) $(LIBSRTP_CFLAGS)
plugins_libjanus_sip_la_LDFLAGS = $(plugins_ldflags) $(SOFIA_LDFLAGS) $(SOFIA_LIBS)
plugins_libjanus_sip_la_LIBADD = $(plugins_libadd) $(SOFIA_LIBADD)
conf_DATA += ../conf/janus.plugin.sip.jcfg.sample
EXTRA_DIST += ../conf/janus.plugin.sip.jcfg.sample
endif

if ENABLE_PLUGIN_NOSIP
plugin_LTLIBRARIES += plugins/libjanus_nosip.la
plugins_libjanus_nosip_la_SOURCES = plugins/janus_nosip.c
plugins_libjanus_nosip_la_CFLAGS = $(plugins_cflags) $(LIBSRTP_CFLAGS)
plugins_libjanus_nosip_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_nosip_la_LIBADD = $(plugins_libadd)
conf_DATA += ../conf/janus.plugin.nosip.jcfg.sample
EXTRA_DIST += ../conf/janus.plugin.nosip.jcfg.sample
endif

if ENABLE_PLUGIN_STREAMING
plugin_LTLIBRARIES += plugins/libjanus_streaming.la
plugins_libjanus_streaming_la_SOURCES = plugins/janus_streaming.c
plugins_libjanus_streaming_la_CFLAGS = $(plugins_cflags) $(LIBCURL_CFLAGS) $(OGG_CFLAGS) $(LIBSRTP_CFLAGS)
plugins_libjanus_streaming_la_LDFLAGS = $(plugins_ldflags) $(LIBCURL_LDFLAGS) $(LIBCURL_LIBS) $(OGG_LDFLAGS) $(OGG_LIBS)
plugins_libjanus_streaming_la_LIBADD = $(plugins_libadd) $(LIBCURL_LIBADD) $(OGG_LIBADD)
conf_DATA += ../conf/janus.plugin.streaming.jcfg.sample
stream_DATA += \
	plugins/streams/radio.alaw \
	plugins/streams/remembrance.opus \
	plugins/streams/test_gstreamer.sh \
	plugins/streams/test_gstreamer1.sh \
	plugins/streams/test_gstreamer_multistream.sh \
	plugins/streams/test_gstreamer1_multistream.sh
EXTRA_DIST += \
	../conf/janus.plugin.streaming.jcfg.sample.in \
	$(stream_DATA)
CLEANFILES += ../conf/janus.plugin.streaming.jcfg.sample
endif

if ENABLE_PLUGIN_VIDEOCALL
plugin_LTLIBRARIES += plugins/libjanus_videocall.la
plugins_libjanus_videocall_la_SOURCES = plugins/janus_videocall.c
plugins_libjanus_videocall_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_videocall_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_videocall_la_LIBADD = $(plugins_libadd)
conf_DATA += ../conf/janus.plugin.videocall.jcfg.sample
EXTRA_DIST += ../conf/janus.plugin.videocall.jcfg.sample
endif

if ENABLE_PLUGIN_VIDEOROOM
plugin_LTLIBRARIES += plugins/libjanus_videoroom.la
plugins_libjanus_videoroom_la_SOURCES = plugins/janus_videoroom.c
plugins_libjanus_videoroom_la_CFLAGS = $(plugins_cflags) $(LIBSRTP_CFLAGS)
plugins_libjanus_videoroom_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_videoroom_la_LIBADD = $(plugins_libadd)
conf_DATA += ../conf/janus.plugin.videoroom.jcfg.sample
EXTRA_DIST += ../conf/janus.plugin.videoroom.jcfg.sample
endif

if ENABLE_PLUGIN_TEXTROOM
plugin_LTLIBRARIES += plugins/libjanus_textroom.la
plugins_libjanus_textroom_la_SOURCES = plugins/janus_textroom.c
plugins_libjanus_textroom_la_CFLAGS = $(plugins_cflags) $(LIBCURL_CFLAGS)
plugins_libjanus_textroom_la_LDFLAGS = $(plugins_ldflags) $(LIBCURL_LDFLAGS) $(LIBCURL_LIBS)
plugins_libjanus_textroom_la_LIBADD = $(plugins_libadd)
conf_DATA += ../conf/janus.plugin.textroom.jcfg.sample
EXTRA_DIST += ../conf/janus.plugin.textroom.jcfg.sample
endif

if ENABLE_PLUGIN_LUA
plugin_LTLIBRARIES += plugins/libjanus_lua.la
plugins_libjanus_lua_la_SOURCES = plugins/janus_lua.c plugins/janus_lua_data.h plugins/janus_lua_extra.c plugins/janus_lua_extra.h
plugins_libjanus_lua_la_CFLAGS = $(plugins_cflags) $(LUA_CFLAGS)
plugins_libjanus_lua_la_LDFLAGS = $(plugins_ldflags) $(LUA_LDFLAGS) $(LUA_LIBS)
plugins_libjanus_lua_la_LIBADD = $(plugins_libadd) $(LUA_LIBADD)
conf_DATA += ../conf/janus.plugin.lua.jcfg.sample
lua_DATA += \
	plugins/lua/echotest.lua \
	plugins/lua/videoroom.lua \
	plugins/lua/janus-logger.lua \
	plugins/lua/janus-sdp.lua
EXTRA_DIST += ../conf/janus.plugin.lua.jcfg.sample.in
endif

if ENABLE_PLUGIN_DUKTAPE
plugin_LTLIBRARIES += plugins/libjanus_duktape.la
plugins_libjanus_duktape_la_SOURCES = plugins/janus_duktape.c \
	plugins/janus_duktape_data.h plugins/janus_duktape_extra.c plugins/janus_duktape_extra.h \
	plugins/duktape-deps/duk_module_duktape.c plugins/duktape-deps/duk_module_duktape.h \
	plugins/duktape-deps/duk_console.c plugins/duktape-deps/duk_console.h
plugins_libjanus_duktape_la_CFLAGS = $(plugins_cflags) $(DUKTAPE_CFLAGS)
plugins_libjanus_duktape_la_LDFLAGS = $(plugins_ldflags) $(DUKTAPE_LDFLAGS) $(DUKTAPE_LIBS)
plugins_libjanus_duktape_la_LIBADD = $(plugins_libadd) $(DUKTAPE_LIBADD)
conf_DATA += ../conf/janus.plugin.duktape.jcfg.sample
duktape_DATA += \
	plugins/duktape/echotest.js \
	plugins/duktape/janus-sdp.js
EXTRA_DIST += ../conf/janus.plugin.duktape.jcfg.sample.in
endif


##
# Post-processing
##

if ENABLE_POST_PROCESSING
bin_PROGRAMS += janus-pp-rec
bin_PROGRAMS += mjr2pcap
if ENABLE_PCAP2MJR
bin_PROGRAMS += pcap2mjr
endif

janus_pp_rec_SOURCES = \
	postprocessing/pp-g711.c \
	postprocessing/pp-g711.h \
	postprocessing/pp-g722.c \
	postprocessing/pp-g722.h \
	postprocessing/pp-l16.c \
	postprocessing/pp-l16.h \
	postprocessing/pp-h264.c \
	postprocessing/pp-h264.h \
	postprocessing/pp-av1.c \
	postprocessing/pp-av1.h \
	postprocessing/pp-avformat.c \
	postprocessing/pp-avformat.h \
	postprocessing/pp-h265.c \
	postprocessing/pp-h265.h \
	postprocessing/pp-opus.c \
	postprocessing/pp-opus.h \
	postprocessing/pp-opus-silence.h \
	postprocessing/pp-options.c \
	postprocessing/pp-options.h \
	postprocessing/pp-rtp.h \
	postprocessing/pp-srt.c \
	postprocessing/pp-srt.h \
	postprocessing/pp-binary.c \
	postprocessing/pp-binary.h \
	postprocessing/pp-webm.c \
	postprocessing/pp-webm.h \
	postprocessing/janus-pp-rec.c \
	log.c \
	utils.c \
	version.c \
	$(NULL)

janus_pp_rec_CFLAGS = \
	$(AM_CFLAGS) \
	-I$(top_builddir)/src/postprocessing \
	$(LIBCURL_CFLAGS) \
	$(POST_PROCESSING_CFLAGS) \
	$(BORINGSSL_CFLAGS) \
	$(NULL)

janus_pp_rec_LDADD = \
	$(BORINGSSL_LIBS) \
	$(POST_PROCESSING_LIBS) \
	$(LIBCURL_LDFLAGS) $(LIBCURL_LIBS) \
	$(NULL)

mjr2pcap_SOURCES = \
	postprocessing/pp-rtp.h \
	postprocessing/mjr2pcap.c \
	log.c \
	utils.c \
	version.c \
	$(NULL)

mjr2pcap_CFLAGS = \
	$(AM_CFLAGS) \
	$(POST_PROCESSING_CFLAGS) \
	$(BORINGSSL_CFLAGS) \
	$(NULL)

mjr2pcap_LDADD = \
	$(BORINGSSL_LIBS) \
	$(POST_PROCESSING_LIBS) \
	$(POST_PROCESSING_MANUAL_LIBS) \
	$(NULL)

if ENABLE_PCAP2MJR
pcap2mjr_SOURCES = \
	postprocessing/pp-rtp.h \
	postprocessing/pcap2mjr.c \
	log.c \
	utils.c \
	version.c \
	$(NULL)

pcap2mjr_CFLAGS = \
	$(AM_CFLAGS) \
	-I$(top_builddir)/src/postprocessing \
	$(POST_PROCESSING_CFLAGS) \
	$(PCAP_CFLAGS) \
	$(BORINGSSL_CFLAGS) \
	$(NULL)

pcap2mjr_LDADD = \
	$(BORINGSSL_LIBS) \
	$(POST_PROCESSING_LIBS) \
	$(POST_PROCESSING_MANUAL_LIBS) \
	$(PCAP_LIBS) \
	$(NULL)
endif

dist_man1_MANS += postprocessing/janus-pp-rec.1
dist_man1_MANS += postprocessing/mjr2pcap.1
if ENABLE_PCAP2MJR
dist_man1_MANS += postprocessing/pcap2mjr.1
endif

endif

.PHONY: FORCE
FORCE:

##
# Configuration
##

configs:
	$(MKDIR_P) $(DESTDIR)$(confdir)
	$(foreach config,$(conf_DATA),cp "$(CURDIR)/$(config)" "$(DESTDIR)$(confdir)/$(notdir $(basename $(config) .sample))";)
