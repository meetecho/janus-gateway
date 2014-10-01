AC_INIT([Janus Gateway],[0.0.6],[https://github.com/meetecho/janus-gateway],[janus-gateway],[https://janus.conf.meetecho.com])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

AC_GNU_SOURCE

AC_PROG_CC

LT_PREREQ([2.2])
LT_INIT

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

PKG_CHECK_MODULES([JANUS],
                  [
                    glib-2.0 >= glib_version
                    nice
                    libmicrohttpd
                    jansson
                    libssl >= ssl_version
                    libcrypto
                    sofia-sip-ua
                    ini_config
                  ])

AC_SUBST(JANUS_MANUAL_LIBS)

AC_CHECK_LIB([nice],
             [nice_agent_set_port_range],
             [AC_DEFINE(HAVE_PORTRANGE)],
             [AC_MSG_NOTICE([libnice does not have nice_agent_set_port_range])]
             )

AC_CHECK_LIB([dl],
             [dlopen],
             [JANUS_MANUAL_LIBS+=" -ldl"],
             [AC_MSG_ERROR([libdl not found.])])

AC_CHECK_LIB([srtp],
             [srtp_init],
             [JANUS_MANUAL_LIBS+=" -lsrtp"],
             [AC_MSG_ERROR([libsrtp not found.])])

AC_CHECK_LIB([websock],
             [libwebsock_init],
             [
               AC_DEFINE(HAVE_WEBSOCKETS)
               JANUS_MANUAL_LIBS+=" -lwebsock"
             ],
             [
               AS_IF([test "x$enable_websockets" = "xyes"],
                     [AC_MSG_ERROR([libwebsocket not found. See README.md for installation instructions or use --disable-websockets])])
             ])

AC_CHECK_LIB([usrsctp],
             [usrsctp_finish],
             [
               AC_DEFINE(HAVE_SCTP)
               JANUS_MANUAL_LIBS+=" -lusrsctp"
             ],
             [
               AS_IF([test "x$enable_data_channels" = "xyes"],
                     [AC_MSG_ERROR([libusrsctp not found. See README.md for installation instructions or use --disable-data-channels])])
             ])

AC_CHECK_LIB([rabbitmq],
             [amqp_error_string2],
             [
               AC_DEFINE(HAVE_RABBITMQ)
               JANUS_MANUAL_LIBS+=" -lrabbitmq"
             ],
             [
               AS_IF([test "x$enable_rabbitmq" = "xyes"],
                     [AC_MSG_ERROR([rabbitmq-c not found. See README.md for installation instructions or use --disable-rabbitmq])])
             ])

AC_CHECK_PROG([DOXYGEN],
              [doxygen],
              [doxygen])
AC_CHECK_PROG([DOT],
              [dot],
              [dot])
AS_IF([test -z "$DOXYGEN" -o -z "$DOT"],
      [
        AS_IF([test "x$enable_docs" = "xyes"],
              [AC_MSG_ERROR([doxygen or dot not found. Docs cannot be built.])])
      ])
AM_CONDITIONAL([ENABLE_DOCS], [test "x$enable_docs" = "xyes"])

##
# Plugins
##

PKG_CHECK_MODULES([PLUGINS],
                  [
                    glib-2.0 >= glib_version
                    sofia-sip-ua
                    jansson
                    ini_config
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

AC_OUTPUT
