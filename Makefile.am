ACLOCAL_AMFLAGS = -I m4

# FIXME: These flags should be produced in configure.ac using AX_APPEND_COMPILE_FLAGS
AM_CFLAGS = \
	-Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
	-Wunused -fstrict-aliasing -Wextra -Wformat=2 -Winit-self -Winline \
	-Wpacked -Wpointer-arith -Wmissing-format-attribute -Wmissing-noreturn \
	-Wnested-externs -Wstrict-prototypes -Wunsafe-loop-optimizations \
	-Wwrite-strings -Wno-missing-field-initializers -Wno-unused-parameter \
	-Wcast-align -Wformat-nonliteral -Wformat-security -Wswitch-default \
	-Wmissing-include-dirs -Wno-aggregate-return -Wunused-but-set-variable \
	-Warray-bounds -Wold-style-definition -Wsign-compare -Wlarger-than=65537
AM_CFLAGS += -Wno-undef  # sophiasip is not -Wundef--safe
AM_CFLAGS += -Wno-redundant-decls  # sophiasip also contains redundant declarations
AM_CFLAGS += -Wno-override-init  # we need this for JANUS_PLUGIN_INIT and JANUS_TRANSPORT_INIT
# FIXME: These should be enabled once the code is safe for them. That requires
# some fairly big refactoring though, which can wait.
# AM_CFLAGS += -Wshadow -Wstrict-aliasing=2

AM_CFLAGS += -fstack-protector-all -g -ggdb -pthread

if WINDOWS_OS
AM_CFLAGS += -Wno-sign-compare -Wno-format-nonliteral
else
AM_CFLAGS += -fPIC -rdynamic
endif

# FIXME: make docs work with distcheck
DISTCHECK_CONFIGURE_FLAGS = --disable-docs --enable-post-processing

EXTRA_DIST = $(NULL)
CLEANFILES = $(NULL)

bin_PROGRAMS = janus

headerdir = $(includedir)/janus
header_HEADERS = \
	plugins/plugin.h transports/transport.h apierror.h config.h debug.h dtls.h \
	janus.h ice.h mutex.h record.h rtcp.h rtp.h sctp.h sdp.h turnrest.h utils.h log.h os.h

confdir = $(sysconfdir)/janus
conf_DATA = conf/janus.cfg.sample

certdir = $(datadir)/janus/certs
cert_DATA = certs/mycert.key certs/mycert.pem

plugindir = $(libdir)/janus/plugins
plugin_LTLIBRARIES = $(NULL)

transportdir = $(libdir)/janus/transports
transport_LTLIBRARIES = $(NULL)

SUBDIRS = html
html_DATA = README.md

streamdir = $(datadir)/janus/streams
stream_DATA = $(NULL)

recordingsdir = $(datadir)/janus/recordings
recordings_DATA = $(NULL)

if WINDOWS_OS
INSTDIR = ../..
else
INSTDIR = $(NULL)
endif

%.sample: %.sample.in
	$(MKDIR_P) $(@D)
	$(AM_V_GEN) sed -e "\
	    s|[@]confdir[@]|$(INSTDIR)$(confdir)|;\
	    s|[@]certdir[@]|$(INSTDIR)$(certdir)|;\
	    s|[@]plugindir[@]|$(INSTDIR)$(plugindir)|;\
	    s|[@]transportdir[@]|$(INSTDIR)$(transportdir)|;\
	    s|[@]recordingsdir[@]|$(INSTDIR)$(recordingsdir)|;\
	    s|[@]streamdir[@]|$(INSTDIR)$(streamdir)|" \
	$< > $@ || rm $@

EXTRA_DIST += conf/janus.cfg.sample.in
CLEANFILES += conf/janus.cfg.sample

##
# Janus
##

janus_SOURCES = \
	janus.c cmdline.c $(NULL)

janus_CFLAGS = \
	$(AM_CFLAGS) \
	$(JANUS_CFLAGS) \
	-DPLUGINDIR=\"$(plugindir)\" \
	-DTRANSPORTDIR=\"$(transportdir)\" \
	-DCONFDIR=\"$(confdir)\" \
	$(BORINGSSL_CFLAGS) \
	$(NULL)

janus_LDADD = \
	$(BORINGSSL_LIBS) \
	$(JANUS_LIBS) \
	$(JANUS_MANUAL_LIBS) \
	-lsrtp \
	libjanus.la \
	$(NULL)

libjanusdir = $(libdir)

libjanus_LTLIBRARIES = libjanus.la

libjanus_la_SOURCES = \
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
	ice.c \
	ice.h \
	janus.c \
	janus.h \
	log.c \
	log.h \
	mutex.h \
	record.c \
	record.h \
	rtcp.c \
	rtcp.h \
	rtp.h \
	sctp.c \
	sctp.h \
	sdp.c \
	sdp.h \
	turnrest.c \
	turnrest.h \
	utils.c \
	utils.h \
	plugins/plugin.c \
	plugins/plugin.h \
	transports/transport.h \
	os.h \
	os.c \
	$(NULL)

libjanus_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(JANUS_CFLAGS) \
	-DPLUGINDIR=\"$(plugindir)\" \
	-DTRANSPORTDIR=\"$(transportdir)\" \
	-DCONFDIR=\"$(confdir)\" \
	$(BORINGSSL_CFLAGS) \
	$(NULL)

if WINDOWS_OS
libjanus_la_CFLAGS += \
	-DSHARED \
	$(NULL)
endif

libjanus_la_LIBADD = \
	$(BORINGSSL_LIBS) \
	$(JANUS_LIBS) \
	$(JANUS_MANUAL_LIBS) \
	-lsrtp \
	$(NULL)

if WINDOWS_OS
libjanus_la_LDFLAGS = \
	-no-undefined \
	$(NULL)
endif

BUILT_SOURCES = cmdline.c cmdline.h

cmdline.c: janus.ggo
	gengetopt --set-package="janus" --set-version="$(VERSION)" --output-dir=$(srcdir) --header-output-dir=$(srcdir) --src-output-dir=$(srcdir) < $^

EXTRA_DIST += janus.ggo
CLEANFILES += cmdline.c cmdline.h

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

if WINDOWS_OS
transports_libadd += \
	libjanus.la \
	$(NULL)

transports_ldflags = \
	-no-undefined \
	$(NULL)
endif

if ENABLE_REST
transport_LTLIBRARIES += transports/libjanus_http.la
transports_libjanus_http_la_SOURCES = transports/janus_http.c
transports_libjanus_http_la_CFLAGS = $(transports_cflags)
transports_libjanus_http_la_LDFLAGS = $(transports_ldflags) -lmicrohttpd
transports_libjanus_http_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.http.cfg.sample
EXTRA_DIST += conf/janus.transport.http.cfg.sample.in
CLEANFILES += conf/janus.transport.http.cfg.sample
endif

if ENABLE_WEBSOCKETS
transport_LTLIBRARIES += transports/libjanus_websockets.la
transports_libjanus_websockets_la_SOURCES = transports/janus_websockets.c
transports_libjanus_websockets_la_CFLAGS = $(transports_cflags)
transports_libjanus_websockets_la_LDFLAGS = $(transports_ldflags) $(WS_MANUAL_LIBS)
transports_libjanus_websockets_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.websockets.cfg.sample
EXTRA_DIST += conf/janus.transport.websockets.cfg.sample.in
CLEANFILES += conf/janus.transport.websockets.cfg.sample
endif

if ENABLE_RABBITMQ
transport_LTLIBRARIES += transports/libjanus_rabbitmq.la
transports_libjanus_rabbitmq_la_SOURCES = transports/janus_rabbitmq.c
transports_libjanus_rabbitmq_la_CFLAGS = $(transports_cflags)
transports_libjanus_rabbitmq_la_LDFLAGS = $(transports_ldflags) -lrabbitmq
transports_libjanus_rabbitmq_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.rabbitmq.cfg.sample
EXTRA_DIST += conf/janus.transport.rabbitmq.cfg.sample
endif

if ENABLE_MQTT
transport_LTLIBRARIES += transports/libjanus_mqtt.la
transports_libjanus_mqtt_la_SOURCES = transports/janus_mqtt.c
transports_libjanus_mqtt_la_CFLAGS = $(transports_cflags)
transports_libjanus_mqtt_la_LDFLAGS = $(transports_ldflags) -lpaho-mqtt3a
transports_libjanus_mqtt_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.mqtt.cfg.sample
EXTRA_DIST += conf/janus.transport.mqtt.cfg.sample
endif

if ENABLE_PFUNIX
transport_LTLIBRARIES += transports/libjanus_pfunix.la
transports_libjanus_pfunix_la_SOURCES = transports/janus_pfunix.c
transports_libjanus_pfunix_la_CFLAGS = $(transports_cflags)
transports_libjanus_pfunix_la_LDFLAGS = $(transports_ldflags)
transports_libjanus_pfunix_la_LIBADD = $(transports_libadd)
conf_DATA += conf/janus.transport.pfunix.cfg.sample
EXTRA_DIST += conf/janus.transport.pfunix.cfg.sample
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

if WINDOWS_OS
plugins_libadd += \
	libjanus.la \
	$(NULL)

plugins_ldflags = \
	-no-undefined \
	$(NULL)
endif

if ENABLE_PLUGIN_AUDIOBRIDGE
plugin_LTLIBRARIES += plugins/libjanus_audiobridge.la
plugins_libjanus_audiobridge_la_SOURCES = plugins/janus_audiobridge.c
plugins_libjanus_audiobridge_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_audiobridge_la_LDFLAGS = $(plugins_ldflags) -lopus
plugins_libjanus_audiobridge_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.audiobridge.cfg.sample
EXTRA_DIST += conf/janus.plugin.audiobridge.cfg.sample
endif

if ENABLE_PLUGIN_ECHOTEST
plugin_LTLIBRARIES += plugins/libjanus_echotest.la
plugins_libjanus_echotest_la_SOURCES = plugins/janus_echotest.c
plugins_libjanus_echotest_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_echotest_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_echotest_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.echotest.cfg.sample
EXTRA_DIST += conf/janus.plugin.echotest.cfg.sample
endif

if ENABLE_PLUGIN_RECORDPLAY
plugin_LTLIBRARIES += plugins/libjanus_recordplay.la
plugins_libjanus_recordplay_la_SOURCES = plugins/janus_recordplay.c
plugins_libjanus_recordplay_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_recordplay_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_recordplay_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.recordplay.cfg.sample
recordings_DATA += \
	plugins/recordings/1234.nfo \
	plugins/recordings/rec-sample-audio.mjr \
	plugins/recordings/rec-sample-video.mjr
EXTRA_DIST += \
	conf/janus.plugin.recordplay.cfg.sample.in \
	$(recordings_DATA)
CLEANFILES += conf/janus.plugin.recordplay.cfg.sample
endif

if ENABLE_PLUGIN_SIP
plugin_LTLIBRARIES += plugins/libjanus_sip.la
plugins_libjanus_sip_la_SOURCES = plugins/janus_sip.c
plugins_libjanus_sip_la_CFLAGS = $(plugins_cflags) $(PLUGIN_SIP_CFLAGS)
plugins_libjanus_sip_la_LDFLAGS = $(plugins_ldflags) $(PLUGIN_SIP_LDFLAGS)
plugins_libjanus_sip_la_LIBADD = $(plugins_libadd) $(PLUGIN_SIP_LIBADD)
conf_DATA += conf/janus.plugin.sip.cfg.sample
EXTRA_DIST += conf/janus.plugin.sip.cfg.sample
endif

if ENABLE_PLUGIN_STREAMING
plugin_LTLIBRARIES += plugins/libjanus_streaming.la
plugins_libjanus_streaming_la_SOURCES = plugins/janus_streaming.c
plugins_libjanus_streaming_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_streaming_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_streaming_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.streaming.cfg.sample
stream_DATA += \
	plugins/streams/music.mulaw \
	plugins/streams/radio.alaw \
	plugins/streams/test_gstreamer.sh \
	plugins/streams/test_gstreamer_1.sh
EXTRA_DIST += \
	conf/janus.plugin.streaming.cfg.sample.in \
	$(stream_DATA)
CLEANFILES += conf/janus.plugin.streaming.cfg.sample
endif

if ENABLE_PLUGIN_VIDEOCALL
plugin_LTLIBRARIES += plugins/libjanus_videocall.la
plugins_libjanus_videocall_la_SOURCES = plugins/janus_videocall.c
plugins_libjanus_videocall_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_videocall_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_videocall_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.videocall.cfg.sample
EXTRA_DIST += conf/janus.plugin.videocall.cfg.sample
endif

if ENABLE_PLUGIN_VIDEOROOM
plugin_LTLIBRARIES += plugins/libjanus_videoroom.la
plugins_libjanus_videoroom_la_SOURCES = plugins/janus_videoroom.c
plugins_libjanus_videoroom_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_videoroom_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_videoroom_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.videoroom.cfg.sample
EXTRA_DIST += conf/janus.plugin.videoroom.cfg.sample
endif

if ENABLE_PLUGIN_VOICEMAIL
plugin_LTLIBRARIES += plugins/libjanus_voicemail.la
plugins_libjanus_voicemail_la_SOURCES = plugins/janus_voicemail.c
plugins_libjanus_voicemail_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_voicemail_la_LDFLAGS = $(plugins_ldflags) -logg
plugins_libjanus_voicemail_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.voicemail.cfg.sample
EXTRA_DIST += conf/janus.plugin.voicemail.cfg.sample
endif

if ENABLE_PLUGIN_TEXTROOM
plugin_LTLIBRARIES += plugins/libjanus_textroom.la
plugins_libjanus_textroom_la_SOURCES = plugins/janus_textroom.c
plugins_libjanus_textroom_la_CFLAGS = $(plugins_cflags)
plugins_libjanus_textroom_la_LDFLAGS = $(plugins_ldflags)
plugins_libjanus_textroom_la_LIBADD = $(plugins_libadd)
conf_DATA += conf/janus.plugin.textroom.cfg.sample
EXTRA_DIST += conf/janus.plugin.textroom.cfg.sample
endif

##
# Post-processing
##

if ENABLE_POST_PROCESSING
bin_PROGRAMS += janus-pp-rec

janus_pp_rec_SOURCES = \
	postprocessing/pp-g711.c \
	postprocessing/pp-g711.h \
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
	$(NULL)

janus_pp_rec_CFLAGS = \
	$(AM_CFLAGS) \
	$(POST_PROCESSING_CFLAGS) \
	$(NULL)

janus_pp_rec_LDADD = \
	$(POST_PROCESSING_LIBS) \
	libjanus.la \
	$(NULL)
endif

##
# Docs
##

if ENABLE_DOCS
SUBDIRS += docs
endif

##
# Configuration
##

if WINDOWS_OS
install-data-hook:
	$(foreach plugin,$(plugin_LTLIBRARIES),mv "$(DESTDIR)$(libdir)/janus/bin/$(basename $(notdir $(plugin)))-0.dll" "$(DESTDIR)$(plugindir)" 2>/dev/null;)
	$(foreach transport,$(transport_LTLIBRARIES),mv "$(DESTDIR)$(libdir)/janus/bin/$(basename $(notdir $(transport)))-0.dll" "$(DESTDIR)$(transportdir)" 2>/dev/null;)
	rm -rf $(DESTDIR)$(plugindir)/../bin

uninstall-hook:
	rm -rf $(DESTDIR)$(libdir)/janus

endif

configs:
	$(MKDIR_P) $(DESTDIR)$(confdir)
	$(foreach config,$(conf_DATA),cp "$(DESTDIR)$(confdir)/$(notdir $(config))" "$(DESTDIR)$(confdir)/$(notdir $(basename $(config) .sample))";)

##
# Extra cleanup
##

clean-local:
	-rm -f docs/doxygen_sqlite3.db
