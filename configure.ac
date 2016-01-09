AC_INIT([Janus Gateway],[0.1.0],[https://github.com/meetecho/janus-gateway],[janus-gateway],[https://janus.conf.meetecho.com])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AC_ENABLE_SHARED(yes)
AC_ENABLE_STATIC(no)

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

AC_GNU_SOURCE

AC_PROG_CC

LT_PREREQ([2.2])
LT_INIT

case "$host_os" in
darwin*)
	LDFLAGS="$LDFLAGS -L/usr/local/lib -L/usr/local/opt/openssl/lib"
	AM_CONDITIONAL([DARWIN_OS], true)
	AM_CONDITIONAL([HAS_DTLS_WINDOW_SIZE], false)
;;
*)
	AM_CONDITIONAL([DARWIN_OS], false)
	AM_CONDITIONAL([HAS_DTLS_WINDOW_SIZE], true)
esac

glib_version=2.32
ssl_version=1.0.1

##
# Janus
##

AC_ARG_ENABLE([docs],
              [AS_HELP_STRING([--disable-docs],
                              [Disable building documentation])],
              [],
              [enable_docs=yes])

AC_ARG_ENABLE([rest],
              [AS_HELP_STRING([--disable-rest],
                              [Disable REST (HTTP/HTTPS) support])],
              [],
              [enable_rest=yes])

AC_ARG_ENABLE([websockets],
              [AS_HELP_STRING([--disable-websockets],
                              [Disable WebSockets support])],
              [],
              [enable_websockets=yes])

AC_ARG_ENABLE([data-channels],
              [AS_HELP_STRING([--disable-data-channels],
                              [Disable DataChannels])],
              [],
              [enable_data_channels=yes])

AC_ARG_ENABLE([rabbitmq],
              [AS_HELP_STRING([--disable-rabbitmq],
                              [Disable RabbitMQ integration])],
              [],
              [enable_rabbitmq=yes])

AC_ARG_ENABLE([boringssl],
              [AS_HELP_STRING([--enable-boringssl],
                              [Use BoringSSL instead of OpenSSL])],
              [],
              [enable_boringssl=no])

AC_ARG_ENABLE([turn-rest-api],
              [AS_HELP_STRING([--disable-turn-rest-api],
                              [Disable TURN REST API client (via libcurl)])],
              [],
              [enable_turn_rest_api=yes])

PKG_CHECK_MODULES([JANUS],
                  [
                    glib-2.0 >= $glib_version
                    nice
                    jansson
                    libssl >= $ssl_version
                    libcrypto
                    sofia-sip-ua
                  ])
AC_SUBST(JANUS_MANUAL_LIBS)

AS_IF([test "x$enable_boringssl" = "xyes"],
	  [echo "Trying to use BoringSSL instead of OpenSSL...";
	   CFLAGS="$CFLAGS -I/opt/boringssl/include";
	   BORINGSSL_CFLAGS=" -I/opt/boringssl/include";
       AC_SUBST(BORINGSSL_CFLAGS)
	   BORINGSSL_LIBS=" -L/opt/boringssl/lib";
       AC_SUBST(BORINGSSL_LIBS)
	   AC_CHECK_HEADERS([openssl/opensslfeatures.h],
	                    [],
	                    [AC_MSG_ERROR([BoringSSL headers not found in /opt/boringssl, use --disable-boringssl if you want to use OpenSSL instead])])
      ])
AM_CONDITIONAL([ENABLE_BORINGSSL], [test "x$enable_boringssl" = "xyes"])

AC_CHECK_LIB([nice],
             [nice_agent_set_port_range],
             [AC_DEFINE(HAVE_PORTRANGE)],
             [AC_MSG_NOTICE([libnice version does not have nice_agent_set_port_range])]
             )

AC_CHECK_LIB([nice],
             [nice_address_equal_no_port],
             [AC_DEFINE(HAVE_LIBNICE_TCP)],
             [AC_MSG_NOTICE([libnice version does not support TCP candidates])]
             )

AC_CHECK_LIB([dl],
             [dlopen],
             [JANUS_MANUAL_LIBS+=" -ldl"],
             [AC_MSG_ERROR([libdl not found.])])

AC_CHECK_LIB([srtp],
             [srtp_init],
             [JANUS_MANUAL_LIBS+=" -lsrtp"],
             [AC_MSG_ERROR([libsrtp not found.])])

AC_CHECK_LIB([usrsctp],
             [usrsctp_finish],
             [
               AS_IF([test "x$enable_data_channels" = "xyes"],
               [
                  AC_DEFINE(HAVE_SCTP)
                  JANUS_MANUAL_LIBS+=" -lusrsctp"
               ])
             ],
             [
               AS_IF([test "x$enable_data_channels" = "xyes"],
                     [AC_MSG_ERROR([libusrsctp not found. See README.md for installation instructions or use --disable-data-channels])])
             ])
AM_CONDITIONAL([ENABLE_SCTP], [test "x$enable_data_channels" = "xyes"])

PKG_CHECK_MODULES([LIBCURL],
                  [libcurl],
                  [
                    AS_IF(
                      [test "x$enable_turn_rest_api" = "xyes"],
                      [
                        AC_DEFINE(HAVE_LIBCURL)
                        JANUS_MANUAL_LIBS+=" -lcurl"
                        enable_turn_rest_api=yes
                      ],
                      [
                        enable_turn_rest_api=no
                      ])
                  ],
                  [
                    AC_MSG_NOTICE(libcurl not found. The TURN REST API client will not be built.)
                    enable_turn_rest_api=no
                  ])
AM_CONDITIONAL([ENABLE_TURN_REST_API], [test "x$enable_turn_rest_api" = "xyes"])

AC_CHECK_PROG([DOXYGEN],
              [doxygen],
              [doxygen])
AC_CHECK_PROG([DOT],
              [dot],
              [dot])
AS_IF([test -z "$DOXYGEN" -o -z "$DOT"],
      [
        AS_IF([test "x$enable_docs" = "xyes"],
              [AC_MSG_ERROR([doxygen or dot not found. See README.md for installation instructions or use --disable-docs])])
      ])
AM_CONDITIONAL([ENABLE_DOCS], [test "x$enable_docs" = "xyes"])

AC_CHECK_PROG([GENGETOPT_CHECK],
              [gengetopt],
              [yes])
if test x"$GENGETOPT_CHECK" != x"yes" ; then
    AC_MSG_ERROR([Please install gengetopt before installing.])
fi


##
# Transports
##

PKG_CHECK_MODULES([TRANSPORTS],
                  [
                    glib-2.0 >= $glib_version
                    jansson
                  ])

PKG_CHECK_MODULES([MHD],
                  [libmicrohttpd],
                  [],
                  [
                    AC_MSG_ERROR([libmicrohttpd not found. See README.md for installation instructions or use --disable-rest])
                  ])
AM_CONDITIONAL([ENABLE_REST], [test "x$enable_rest" = "xyes"])

AC_CHECK_LIB([websockets_shared],
             [lws_get_internal_extensions],
             [
               AS_IF([test "x$enable_websockets" = "xyes"],
               [
                  AC_DEFINE(HAVE_WEBSOCKETS)
                  WS_MANUAL_LIBS="-lwebsockets_shared"
               ])
             ],
             [
				AC_CHECK_LIB([websockets],
							 [lws_get_internal_extensions],
							 [
							   AS_IF([test "x$enable_websockets" = "xyes"],
							   [
								  AC_DEFINE(HAVE_WEBSOCKETS)
								  WS_MANUAL_LIBS="-lwebsockets"
							   ])
							 ],
							 [
							   AS_IF([test "x$enable_websockets" = "xyes"],
									 [AC_MSG_ERROR([libwebsockets not found. See README.md for installation instructions or use --disable-websockets])])
							 ])
             ])
AM_CONDITIONAL([ENABLE_WEBSOCKETS], [test "x$enable_websockets" = "xyes"])
AC_SUBST(WS_MANUAL_LIBS)

AC_CHECK_LIB([rabbitmq],
             [amqp_error_string2],
             [
               AS_IF([test "x$enable_rabbitmq" = "xyes"],
               [
                  AC_DEFINE(HAVE_RABBITMQ)
               ])
             ],
             [
               AS_IF([test "x$enable_rabbitmq" = "xyes"],
                     [AC_MSG_ERROR([rabbitmq-c not found. See README.md for installation instructions or use --disable-rabbitmq])])
             ])
AM_CONDITIONAL([ENABLE_RABBITMQ], [test "x$enable_rabbitmq" = "xyes"])


##
# Plugins
##

PKG_CHECK_MODULES([PLUGINS],
                  [
                    glib-2.0 >= $glib_version
                    sofia-sip-ua
                    jansson
                  ])

AC_ARG_ENABLE([plugin-audiobridge],
              [AS_HELP_STRING([--disable-plugin-audiobridge],
                              [Disable audiobridge plugin])],
              [],
              [enable_plugin_audiobridge=yes])

AC_ARG_ENABLE([plugin-echotest],
              [AS_HELP_STRING([--disable-plugin-echotest],
                              [Disable echotest plugin])],
              [],
              [enable_plugin_echotest=yes])

AC_ARG_ENABLE([plugin-recordplay],
              [AS_HELP_STRING([--disable-plugin-recordplay],
                              [Disable record&play plugin])],
              [],
              [enable_plugin_recordplay=yes])

AC_ARG_ENABLE([plugin-sip],
              [AS_HELP_STRING([--disable-plugin-sip],
                              [Disable sip plugin])],
              [],
              [enable_plugin_sip=yes])

AC_ARG_ENABLE([plugin-streaming],
              [AS_HELP_STRING([--disable-plugin-streaming],
                              [Disable streaming plugin])],
              [],
              [enable_plugin_streaming=yes])

AC_ARG_ENABLE([plugin-videocall],
              [AS_HELP_STRING([--disable-plugin-videocall],
                              [Disable videocall plugin])],
              [],
              [enable_plugin_videocall=yes])

AC_ARG_ENABLE([plugin-videoroom],
              [AS_HELP_STRING([--disable-plugin-videoroom],
                              [Disable videoroom plugin])],
              [],
              [enable_plugin_videoroom=yes])

AC_ARG_ENABLE([plugin-voicemail],
              [AS_HELP_STRING([--disable-plugin-voicemail],
                              [Disable voicemail plugin])],
              [],
              [enable_plugin_voicemail=yes])

PKG_CHECK_MODULES([OPUS],
                  [opus],
                  [],
                  [
                    AC_MSG_NOTICE(libopus not found. The audiobridge plugin will not be built.)
                    enable_plugin_audiobridge=no
                  ])

PKG_CHECK_MODULES([OGG],
                  [ogg],
                  [],
                  [
                    AC_MSG_NOTICE(libogg not found. The voicemail plugin will not be built.)
                    enable_plugin_voicemail=no
                  ])

AM_CONDITIONAL([ENABLE_PLUGIN_AUDIOBRIDGE], [test "x$enable_plugin_audiobridge" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_ECHOTEST], [test "x$enable_plugin_echotest" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_RECORDPLAY], [test "x$enable_plugin_recordplay" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_SIP], [test "x$enable_plugin_sip" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_STREAMING], [test "x$enable_plugin_streaming" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_VIDEOCALL], [test "x$enable_plugin_videocall" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_VIDEOROOM], [test "x$enable_plugin_videoroom" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_VOICEMAIL], [test "x$enable_plugin_voicemail" = "xyes"])

##
# Post-processing
##

AC_ARG_ENABLE([post-processing],
              [AS_HELP_STRING([--enable-post-processing],
                              [Enable building post-processing utility])],
              [],
              [enable_post_processing=no])

AS_IF([test "x$enable_post_processing" = "xyes"],
      [PKG_CHECK_MODULES([POST_PROCESSING],
                         [
                           glib-2.0,
                           jansson,
                           libavutil,
                           libavcodec,
                           libavformat,
                           ogg
                         ])
      ])

AM_CONDITIONAL([ENABLE_POST_PROCESSING], [test "x$enable_post_processing" = "xyes"])

AC_CONFIG_FILES([
  Makefile
  html/Makefile
  docs/Makefile
])

JANUS_MANUAL_LIBS+=" -pthread"

AC_OUTPUT

##
# Summary
##
echo

AM_COND_IF([ENABLE_SCTP],
	[echo "DataChannels support:      yes"],
	[echo "DataChannels support:      no"])
AM_COND_IF([ENABLE_BORINGSSL],
	[echo "BoringSSL (no OpenSSL):    yes"],
	[echo "BoringSSL (no OpenSSL):    no"])
AM_COND_IF([ENABLE_POST_PROCESSING],
	[echo "Recordings post-processor: yes"],
	[echo "Recordings post-processor: no"])
AM_COND_IF([ENABLE_TURN_REST_API],
	[echo "TURN REST API client:      yes"],
	[echo "TURN REST API client:      no"])
AM_COND_IF([ENABLE_DOCS],
	[echo "Doxygen documentation:     yes"],
	[echo "Doxygen documentation:     no"])
echo "Transports:"
AM_COND_IF([ENABLE_REST],
	[echo "    REST (HTTP/HTTPS):     yes"],
	[echo "    REST (HTTP/HTTPS):     no"])
AM_COND_IF([ENABLE_WEBSOCKETS],
	[echo "    WebSockets:            yes"],
	[echo "    WebSockets:            no"])
AM_COND_IF([ENABLE_RABBITMQ],
	[echo "    RabbitMQ:              yes"],
	[echo "    RabbitMQ:              no"])
echo "Plugins:"
AM_COND_IF([ENABLE_PLUGIN_ECHOTEST],
	[echo "    Echo Test:             yes"],
	[echo "    Echo Test:             no"])
AM_COND_IF([ENABLE_PLUGIN_STREAMING],
	[echo "    Streaming:             yes"],
	[echo "    Streaming:             no"])
AM_COND_IF([ENABLE_PLUGIN_VIDEOCALL],
	[echo "    Video Call:            yes"],
	[echo "    Video Call:            no"])
AM_COND_IF([ENABLE_PLUGIN_SIP],
	[echo "    SIP Gateway:           yes"],
	[echo "    SIP Gateway:           no"])
AM_COND_IF([ENABLE_PLUGIN_AUDIOBRIDGE],
	[echo "    Audio Bridge:          yes"],
	[echo "    Audio Bridge:          no"])
AM_COND_IF([ENABLE_PLUGIN_VIDEOROOM],
	[echo "    Video Room:            yes"],
	[echo "    Video Room:            no"])
AM_COND_IF([ENABLE_PLUGIN_VOICEMAIL],
	[echo "    Voice Mail:            yes"],
	[echo "    Voice Mail:            no"])
AM_COND_IF([ENABLE_PLUGIN_RECORDPLAY],
	[echo "    Record&Play:           yes"],
	[echo "    Record&Play:           no"])

echo
echo "If this configuration is ok for you, do a 'make' to start building Janus. A 'make install' will install Janus and its plugins to the specified prefix. Finally, a 'make configs' will install some sample configuration files too (something you'll only want to do the first time, though)."
echo
