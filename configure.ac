AC_INIT([Janus WebRTC Server],[0.7.3],[https://github.com/meetecho/janus-gateway],[janus-gateway],[https://janus.conf.meetecho.com])
AC_LANG(C)
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AC_ENABLE_SHARED(yes)
AC_ENABLE_STATIC(no)

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

#AC_GNU_SOURCE has been deprecated (https://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/Obsolete-Macros.html)
AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC

LT_PREREQ([2.2])
LT_INIT

# Common CFLAGS
CFLAGS="$CFLAGS \
	-fPIC \
	-fstack-protector-all \
	-fstrict-aliasing \
	-ggdb3 \
	-pthread \
	-Wall \
	-Warray-bounds \
	-Wextra \
	-Wformat-nonliteral \
	-Wformat-security \
	-Wformat=2 \
	-Winit-self \
	-Winline \
	-Wlarger-than=65537 \
	-Wmissing-declarations \
	-Wmissing-format-attribute \
	-Wmissing-include-dirs \
	-Wmissing-noreturn \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wno-aggregate-return \
	-Wno-missing-field-initializers \
	-Wno-redundant-decls \
	-Wno-undef \
	-Wno-unused-parameter \
	-Wold-style-definition \
	-Wpacked \
	-Wpointer-arith \
	-Wsign-compare \
	-Wstrict-prototypes \
	-Wswitch-default \
	-Wunused \
	-Wwrite-strings"

case "$CC" in
clang*)
	# Specific clang flags
	CFLAGS="$CFLAGS \
		-Wno-cast-align \
		-Wno-initializer-overrides"
;;
*)
	# Specific gcc flags
	CFLAGS="$CFLAGS \
		-Wcast-align \
		-Wno-override-init \
		-Wunsafe-loop-optimizations \
		-Wunused-but-set-variable"
esac

JANUS_VERSION=73
AC_SUBST(JANUS_VERSION)
JANUS_VERSION_STRING="0.7.3"
AC_SUBST(JANUS_VERSION_STRING)

case "$host_os" in
darwin*)
	CFLAGS="$CFLAGS -I/usr/local/opt/openssl/include -I/usr/local/include"
	# add rdynamic to LDFLAGS
	LDFLAGS="$LDFLAGS -Wl,-export_dynamic"
	LDFLAGS="$LDFLAGS -L/usr/local/lib -L/usr/local/opt/openssl/lib -L/opt/local/lib -L/usr/local/libsrtp/lib"
	AM_CONDITIONAL([DARWIN_OS], true)
;;
*)
	LDFLAGS="$LDFLAGS -Wl,--export-dynamic"
	AM_CONDITIONAL([DARWIN_OS], false)
	AC_DEFINE(HAS_DTLS_WINDOW_SIZE, 1)
esac

glib_version=2.34
ssl_version=1.0.1
jansson_version=2.5

##
# Janus
##

AC_ARG_ENABLE([docs],
              [AS_HELP_STRING([--enable-docs],
                              [Enable building documentation])],
              [],
              [enable_docs=no])

AC_ARG_ENABLE([data-channels],
              [AS_HELP_STRING([--disable-data-channels],
                              [Disable DataChannels])],
              [],
              [enable_data_channels=maybe])

AC_ARG_ENABLE([boringssl],
              [AS_HELP_STRING([--enable-boringssl],
                              [Use BoringSSL instead of OpenSSL])],
              [
                case "${enableval}" in
                  yes) boringssl_dir=/opt/boringssl ;;
                  no)  boringssl_dir= ;;
                  *) boringssl_dir=${enableval} ;;
                esac
              ],
              [boringssl_dir=])

AC_ARG_ENABLE([libsrtp2],
              [AS_HELP_STRING([--enable-libsrtp2],
                              [Use libsrtp 2.0.x instead of libsrtp 1.5.x])],
              [],
              [enable_libsrtp2=maybe])

AC_ARG_ENABLE([dtls-settimeout],
              [AS_HELP_STRING([--enable-dtls-settimeout],
                              [Use DTLSv1_set_initial_timeout_duration (only available in recent BoringSSL versions)])],
              [],
              [enable_dtls_settimeout=no])

AC_ARG_ENABLE([pthread-mutex],
              [AS_HELP_STRING([--enable-pthread-mutex],
                              [Use pthread_mutex instead of GMutex (see #1397)])],
              [],
              [enable_pthread_mutex=no])

AC_ARG_ENABLE([turn-rest-api],
              [AS_HELP_STRING([--disable-turn-rest-api],
                              [Disable TURN REST API client (via libcurl)])],
              [],
              [enable_turn_rest_api=maybe])

AC_ARG_ENABLE([all-plugins],
              [AS_HELP_STRING([--disable-all-plugins],
                              [Disable building all plugins (except those manually enabled)])],
              [
               AS_IF([test "x$enable_plugin_audiobridge" != "xyes"],
                     [enable_plugin_audiobridge=no])
               AS_IF([test "x$enable_plugin_duktape" != "xyes"],
                     [enable_plugin_duktape=no])
               AS_IF([test "x$enable_plugin_echotest" != "xyes"],
                     [enable_plugin_echotest=no])
               AS_IF([test "x$enable_plugin_lua" != "xyes"],
                     [enable_plugin_lua=no])
               AS_IF([test "x$enable_plugin_recordplay" != "xyes"],
                     [enable_plugin_recordplay=no])
               AS_IF([test "x$enable_plugin_sip" != "xyes"],
                     [enable_plugin_sip=no])
               AS_IF([test "x$enable_plugin_sipre" != "xyes"],
                     [enable_plugin_sipre=no])
               AS_IF([test "x$enable_plugin_nosip" != "xyes"],
                     [enable_plugin_nosip=no])
               AS_IF([test "x$enable_plugin_streaming" != "xyes"],
                     [enable_plugin_streaming=no])
               AS_IF([test "x$enable_plugin_textroom" != "xyes"],
                     [enable_plugin_textroom=no])
               AS_IF([test "x$enable_plugin_videocall" != "xyes"],
                     [enable_plugin_videocall=no])
               AS_IF([test "x$enable_plugin_videoroom" != "xyes"],
                     [enable_plugin_videoroom=no])
               AS_IF([test "x$enable_plugin_voicemail" != "xyes"],
                     [enable_plugin_voicemail=no])
              ],
              [])

AC_ARG_ENABLE([all-transports],
              [AS_HELP_STRING([--disable-all-transports],
                              [Disable building all transports (except those manually enabled)])],
              [
               AS_IF([test "x$enable_rest" != "xyes"],
                     [enable_rest=no])
               AS_IF([test "x$enable_websockets" != "xyes"],
                     [enable_websockets=no])
               AS_IF([test "x$enable_rabbitmq" != "xyes"],
                     [enable_rabbitmq=no])
               AS_IF([test "x$enable_mqtt" != "xyes"],
                     [enable_mqtt=no])
               AS_IF([test "x$enable_unix_sockets" != "xyes"],
                     [enable_unix_sockets=no])
               AS_IF([test "x$enable_nanomsg" != "xyes"],
                     [enable_nanomsg=no])
              ],
              [])

AC_ARG_ENABLE([all-handlers],
              [AS_HELP_STRING([--disable-all-handlers],
                              [Disable building all event handlers (except those manually enabled)])],
              [
               AS_IF([test "x$enable_sample_event_handler" != "xyes"],
                     [enable_sample_event_handler=no])
               AS_IF([test "x$enable_rabbitmq_event_handler" != "xyes"],
                     [enable_rabbitmq_event_handler=no])
               AS_IF([test "x$enable_mqtt_event_handler" != "xyes"],
                     [enable_mqtt_event_handler=no])
              ],
              [])

AC_ARG_ENABLE([all-js-modules],
              [AS_HELP_STRING([--enable-all-js-modules],
                              [Build all the JavaScript modules (instead of manually enabling them one by one)])],
              [
               enable_javascript_es_module=yes
               enable_javascript_umd_module=yes
               enable_javascript_iife_module=yes
               enable_javascript_common_js_module=yes
              ],
              [])

AC_ARG_ENABLE([rest],
              [AS_HELP_STRING([--disable-rest],
                              [Disable REST (HTTP/HTTPS) support])],
              [AS_IF([test "x$enable_rest" != "xyes"],
                     [enable_rest=no])],
              [enable_rest=maybe])

AC_ARG_ENABLE([websockets],
              [AS_HELP_STRING([--disable-websockets],
                              [Disable WebSockets support])],
              [AS_IF([test "x$enable_websockets" != "xyes"],
                     [enable_websockets=no])],
              [enable_websockets=maybe])

AC_ARG_ENABLE([rabbitmq],
              [AS_HELP_STRING([--disable-rabbitmq],
                              [Disable RabbitMQ integration])],
              [AS_IF([test "x$enable_rabbitmq" != "xyes"],
                     [enable_rabbitmq=no])],
              [enable_rabbitmq=maybe])

AC_ARG_ENABLE([mqtt],
              [AS_HELP_STRING([--disable-mqtt],
                              [Disable MQTT integration])],
              [AS_IF([test "x$enable_mqtt" != "xyes"],
                     [enable_mqtt=no])],
              [enable_mqtt=maybe])

AC_ARG_ENABLE([unix-sockets],
              [AS_HELP_STRING([--disable-unix-sockets],
                              [Disable Unix Sockets integration])],
              [AS_IF([test "x$enable_unix_sockets" != "xyes"],
                     [enable_unix_sockets=no])],
              [enable_unix_sockets=maybe])

AC_ARG_ENABLE([nanomsg],
              [AS_HELP_STRING([--disable-nanomsg],
                              [Disable Nanomsg integration])],
              [AS_IF([test "x$enable_nanomsg" != "xyes"],
                     [enable_nanomsg=no])],
              [enable_nanomsg=maybe])

AC_ARG_ENABLE([sample-event-handler],
              [AS_HELP_STRING([--disable-sample-event-handler],
                              [Disable sample event handler (HTTP POST) ])],
              [AS_IF([test "x$enable_sample_event_handler" != "xyes"],
                     [enable_sample_event_handler=no])],
              [enable_sample_event_handler=maybe])

AC_ARG_ENABLE([rabbitmq-event-handler],
              [AS_HELP_STRING([--disable-rabbitmq-event-handler],
                              [Disable RabbitMQ event handler ])],
              [AS_IF([test "x$enable_rabbitmq_event_handler" != "xyes"],
                     [enable_rabbitmq_event_handler=no])],
              [enable_rabbitmq_event_handler=maybe])

AC_ARG_ENABLE([mqtt-event-handler],
              [AS_HELP_STRING([--disable-mqtt-event-handler],
                              [Disable MQTT event handler ])],
              [AS_IF([test "x$enable_mqtt_event_handler" != "xyes"],
                     [enable_mqtt_event_handler=no])],
              [enable_mqtt_event_handler=maybe])

AC_ARG_ENABLE([systemd-sockets],
              [AS_HELP_STRING([--enable-systemd-sockets],
                              [Enable Systemd Unix Sockets management])],
              [],
              [enable_systemd_sockets=no])

PKG_CHECK_MODULES([JANUS],
                  [
                    glib-2.0 >= $glib_version
					libconfig
                    nice
                    jansson >= $jansson_version
                    libssl >= $ssl_version
                    libcrypto
                  ])
JANUS_MANUAL_LIBS="${JANUS_MANUAL_LIBS} -lm"
AC_SUBST(JANUS_MANUAL_LIBS)

AS_IF([test "x${boringssl_dir}" != "x"],
	  [echo "Trying to use BoringSSL instead of OpenSSL...";
	   AC_MSG_NOTICE([BoringSSL directory is ${boringssl_dir}])
	   CFLAGS="$CFLAGS -I${boringssl_dir}/include";
	   BORINGSSL_CFLAGS=" -I${boringssl_dir}/include";
       AC_SUBST(BORINGSSL_CFLAGS)
	   BORINGSSL_LIBS=" -L${boringssl_dir}/lib";
       AC_SUBST(BORINGSSL_LIBS)
	   AC_CHECK_HEADERS([${boringssl_dir}/include/openssl/opensslconf.h],
	                    [AC_DEFINE(HAVE_BORINGSSL)],
	                    [AC_MSG_ERROR([BoringSSL headers not found in ${boringssl_dir}, use --disable-boringssl if you want to use OpenSSL instead])])
      ])
AM_CONDITIONAL([ENABLE_BORINGSSL], [test "x${boringssl_dir}" != "x"])

AS_IF([test "x$enable_dtls_settimeout" = "xyes"],
      [
      AC_DEFINE(HAVE_DTLS_SETTIMEOUT)
      AC_MSG_NOTICE([Assuming DTLSv1_set_initial_timeout_duration is available])
      ])
AM_CONDITIONAL([ENABLE_DTLS_SETTIMEOUT], [test "x$enable_dtls_settimeout" = "xyes"])

AS_IF([test "x$enable_pthread_mutex" = "xyes"],
      [
      AC_DEFINE(USE_PTHREAD_MUTEX)
      AC_MSG_NOTICE([Will use pthread_mutex instead of GMutex])
      ])
AM_CONDITIONAL([ENABLE_PTHREAD_MUTEX], [test "x$enable_pthread_mutex" = "xyes"])

AC_SEARCH_LIBS([tls_config_set_ca_mem],[tls],
             [AM_CONDITIONAL([LIBRESSL_DETECTED], true)],
             [AM_CONDITIONAL([LIBRESSL_DETECTED], false)]
             )

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
             [JANUS_MANUAL_LIBS="${JANUS_MANUAL_LIBS} -ldl"],
             [AC_MSG_ERROR([libdl not found.])])

AM_CONDITIONAL([ENABLE_LIBSRTP_2], false)
AS_IF([test "x$enable_libsrtp2" != "xno"],
      [AC_CHECK_LIB([srtp2],
                    [srtp_init],
                    [
                      AC_CHECK_HEADER([srtp2/srtp.h],
                                      [
                                        AC_DEFINE(HAVE_SRTP_2)
                                        JANUS_MANUAL_LIBS="${JANUS_MANUAL_LIBS} -lsrtp2"
                                        enable_libsrtp2=yes
                                        AM_CONDITIONAL([ENABLE_LIBSRTP_2], true)
                                        AC_CHECK_LIB([srtp2],
                                                     [srtp_crypto_policy_set_aes_gcm_256_16_auth],
                                                     [AC_DEFINE(HAVE_SRTP_AESGCM)],
                                                     [AC_MSG_NOTICE([libsrtp2 does not have support for AES-GCM profiles])])
                                      ],
                                      [
                                        AS_IF([test "x$enable_libsrtp2" = "xyes"],
                                              [AC_MSG_ERROR([libsrtp2 headers not found. See README.md for installation instructions or use --disable-libsrtp-2 to try and autodetect libsrtp 1.5.x instead])])
                                      ])
                    ],
                    [
                      AS_IF([test "x$enable_libsrtp2" = "xyes"],
                            [AC_MSG_ERROR([libsrtp2 not found. See README.md for installation instructions or use --disable-libsrtp-2 to try and autodetect libsrtp 1.5.x instead])])
                    ])
      ])
AM_COND_IF([ENABLE_LIBSRTP_2],
           [],
           [AC_CHECK_LIB([srtp],
                         [srtp_init],
                         [
                           AC_CHECK_HEADER([srtp/srtp.h],
                                           [
                                             JANUS_MANUAL_LIBS="${JANUS_MANUAL_LIBS} -lsrtp"
                                             enable_libsrtp2=no
                                             PKG_CHECK_MODULES([SRTP15X],
                                                               [
                                                                 libsrtp >= 1.5.0
                                                               ])
                                             AC_CHECK_LIB([srtp],
                                                          [crypto_policy_set_aes_gcm_256_16_auth],
                                                          [AC_DEFINE(HAVE_SRTP_AESGCM)],
                                                          [AC_MSG_NOTICE([libsrtp does not have support for AES-GCM profiles])])
                                           ],
                                           [AC_MSG_ERROR([libsrtp and libsrtp2 headers not found. See README.md for installation instructions])])
                         ],
                         [AC_MSG_ERROR([libsrtp and libsrtp2 not found. See README.md for installation instructions])])
           ])

AC_CHECK_LIB([usrsctp],
             [usrsctp_finish],
             [
               AS_IF([test "x$enable_data_channels" != "xno"],
               [
                  AC_DEFINE(HAVE_SCTP)
                  JANUS_MANUAL_LIBS="${JANUS_MANUAL_LIBS} -lusrsctp"
                  enable_data_channels=yes
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
                    AC_DEFINE(HAVE_LIBCURL)
                    JANUS_MANUAL_LIBS="${JANUS_MANUAL_LIBS} -lcurl"
                    AS_IF(
                      [test "x$enable_turn_rest_api" != "xno"],
                      [
                        AC_DEFINE(HAVE_TURNRESTAPI)
                        enable_turn_rest_api=yes
                      ])
                    AS_IF([test "x$enable_sample_event_handler" != "xno"],
                      [
                        AC_DEFINE(HAVE_SAMPLEEVH)
                        enable_sample_event_handler=yes
                      ])
                  ],
                  [
                    AS_IF([test "x$enable_turn_rest_api" = "xyes"],
                          [AC_MSG_ERROR([libcurl not found. See README.md for installation instructions or use --disable-turn-rest-api])])
                    AS_IF([test "x$enable_sample_event_handler" = "xyes"],
                          [AC_MSG_ERROR([libcurl not found. See README.md for installation instructions or use --disable-sample-event-handler])])
                  ])
AM_CONDITIONAL([ENABLE_TURN_REST_API], [test "x$enable_turn_rest_api" = "xyes"])
AM_CONDITIONAL([ENABLE_SAMPLEEVH], [test "x$enable_sample_event_handler" = "xyes"])

AC_CHECK_PROG([DOXYGEN],
              [doxygen],
              [doxygen])
AC_CHECK_PROG([DOT],
              [dot],
              [dot])
AS_IF([test -z "$DOXYGEN" -o -z "$DOT"],
      [
        AS_IF([test "x$enable_docs" = "xyes"],
              [AC_MSG_ERROR([doxygen or dot not found. See README.md for installation instructions or remove --enable-docs])])
      ])
AM_CONDITIONAL([ENABLE_DOCS], [test "x$enable_docs" = "xyes"])
if test "x$enable_docs" = "xyes"; then
	doxygen_version=$($DOXYGEN --version)
	AS_VERSION_COMPARE([$doxygen_version], [1.8.11],
					   [],
					   [],
					   [AC_MSG_ERROR([Doxygen $doxygen_version too new: versions higher than 1.8.11 are known to render poorly.])]
					  )
fi

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
                    jansson >= $jansson_version
                  ])

PKG_CHECK_MODULES([MHD],
                  [libmicrohttpd],
                  [
                    AS_IF([test "x$enable_rest" = "xmaybe"],
                          [enable_rest=yes])
                  ],
                  [
                    AS_IF([test "x$enable_rest" = "xyes"],
                          [AC_MSG_ERROR([libmicrohttpd not found. See README.md for installation instructions or use --disable-rest])])
                  ])
AC_SUBST([MHD_CFLAGS])
AC_SUBST([MHD_LIBS])
AM_CONDITIONAL([ENABLE_REST], [test "x$enable_rest" = "xyes"])

AC_CHECK_LIB([websockets],
			 [lws_create_vhost],
			 [
			   AS_IF([test "x$enable_websockets" != "xno"],
			   [
				  AC_DEFINE(HAVE_WEBSOCKETS)
				  WS_MANUAL_LIBS="-lwebsockets"
				  enable_websockets=yes
				  AC_CHECK_LIB([websockets],
							   [lws_get_peer_simple],
							   [AC_DEFINE(HAVE_LIBWEBSOCKETS_PEER_SIMPLE)]
							  )
			   ])
			 ],
			 [
			   AS_IF([test "x$enable_websockets" = "xyes"],
					 [AC_MSG_ERROR([libwebsockets not found. See README.md for installation instructions or use --disable-websockets])])
			 ])
AM_CONDITIONAL([ENABLE_WEBSOCKETS], [test "x$enable_websockets" = "xyes"])
AC_SUBST(WS_MANUAL_LIBS)

AC_CHECK_LIB([rabbitmq],
             [amqp_error_string2],
             [
               AS_IF([test "x$enable_rabbitmq" != "xno"],
               [
                  AC_DEFINE(HAVE_RABBITMQ)
                  enable_rabbitmq=yes
               ])
               AS_IF([test "x$enable_rabbitmq_event_handler" != "xno"],
               [
                 AC_DEFINE(HAVE_RABBITMQEVH)
                 enable_rabbitmq_event_handler=yes
               ])
             ],
             [
               AS_IF([test "x$enable_rabbitmq" = "xyes"],
                     [AC_MSG_ERROR([rabbitmq-c not found. See README.md for installation instructions or use --disable-rabbitmq])])
               AS_IF([test "x$enable_rabbitmq_event_handler" = "xyes"],
                     [AC_MSG_ERROR([rabbitmq-c not found. See README.md for installation instructions or use --disable-rabbitmq-event-handler])])
             ])
AC_CHECK_LIB([paho-mqtt3a],
             [MQTTAsync_create],
             [
               AS_IF([test "x$enable_mqtt" != "xno"],
               [
                  AC_DEFINE(HAVE_MQTT)
                  enable_mqtt=yes
               ])
               AS_IF([test "x$enable_mqtt_event_handler" != "xno"],
               [
                 AC_DEFINE(HAVE_MQTTEVH)
                 enable_mqtt_event_handler=yes
               ])
             ],
             [
               AS_IF([test "x$enable_mqtt" = "xyes"],
                     [AC_MSG_ERROR([paho c client not found. See README.md for installation instructions or use --disable-mqtt])])
               AS_IF([test "x$enable_mqtt_event_handler" = "xyes"],
                     [AC_MSG_ERROR([paho c not found. See README.md for installation instructions or use --disable-mqtt-event-handler])])
             ])
AC_CHECK_LIB([nanomsg],
             [nn_socket],
             [
               AS_IF([test "x$enable_nanomsg" != "xno"],
               [
                  AC_DEFINE(HAVE_NANOMSG)
                  enable_nanomsg=yes
               ])
             ],
             [
               AS_IF([test "x$enable_nanomsg" = "xyes"],
                     [AC_MSG_ERROR([nanomsg not found. See README.md for installation instructions or use --disable-nanomsg])])
             ])
AM_CONDITIONAL([ENABLE_RABBITMQ], [test "x$enable_rabbitmq" = "xyes"])
AM_CONDITIONAL([ENABLE_RABBITMQEVH], [test "x$enable_rabbitmq_event_handler" = "xyes"])
AM_CONDITIONAL([ENABLE_MQTT], [test "x$enable_mqtt" = "xyes"])
AM_CONDITIONAL([ENABLE_MQTTEVH], [test "x$enable_mqtt_event_handler" = "xyes"])
AM_CONDITIONAL([ENABLE_NANOMSG], [test "x$enable_nanomsg" = "xyes"])

AC_TRY_COMPILE([
               #include <stdlib.h>
               #include <sys/socket.h>
               #include <sys/un.h>
               void test() {
                 int pfd = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
                 if(pfd < 0)
                   exit(1);
               }],
               [],
               [
                 AS_IF([test "x$enable_unix_sockets" != "xno"],
                 [
                    AC_DEFINE(HAVE_PFUNIX)
                    enable_unix_sockets=yes
                 ])
               ],
               [
                 AS_IF([test "x$enable_unix_sockets" = "xyes"],
                       [AC_MSG_ERROR([SOCK_SEQPACKET not defined in your OS. Use --disable-unix-sockets])])
               ])
AM_CONDITIONAL([ENABLE_PFUNIX], [test "x$enable_unix_sockets" = "xyes"])

AS_IF([test "x$enable_systemd_sockets" = "xyes"],
      [PKG_CHECK_MODULES([LIBSYSTEMD],
                          [libsystemd],
                          [
                            AC_DEFINE(HAVE_LIBSYSTEMD)
                          ],
                          [AC_MSG_ERROR([libsystemd not found. systemd unix domain socket service not supported])])
      ])


##
# Plugins
##

PKG_CHECK_MODULES([PLUGINS],
                  [
                    glib-2.0 >= $glib_version
                    jansson >= $jansson_version
                  ])

AC_ARG_ENABLE([plugin-audiobridge],
              [AS_HELP_STRING([--disable-plugin-audiobridge],
                              [Disable audiobridge plugin])],
              [AS_IF([test "x$enable_plugin_audiobridge" != "xyes"],
                     [enable_plugin_audiobridge=no])],
              [enable_plugin_audiobridge=maybe])

AC_ARG_ENABLE([plugin-duktape],
              [AS_HELP_STRING([--enable-plugin-duktape],
                              [Enable duktape plugin])],
              [AS_IF([test "x$enable_plugin_duktape" != "xyes"],
                     [enable_plugin_duktape=no])],
              [enable_plugin_duktape=no])

AC_ARG_ENABLE([plugin-echotest],
              [AS_HELP_STRING([--disable-plugin-echotest],
                              [Disable echotest plugin])],
              [AS_IF([test "x$enable_plugin_echotest" != "xyes"],
                     [enable_plugin_echotest=no])],
              [enable_plugin_echotest=yes])

AC_ARG_ENABLE([plugin-lua],
              [AS_HELP_STRING([--enable-plugin-lua],
                              [Enable lua plugin])],
              [AS_IF([test "x$enable_plugin_lua" != "xyes"],
                     [enable_plugin_lua=no])],
              [enable_plugin_lua=no])

AC_ARG_ENABLE([plugin-recordplay],
              [AS_HELP_STRING([--disable-plugin-recordplay],
                              [Disable record&play plugin])],
              [AS_IF([test "x$enable_plugin_recordplay" != "xyes"],
                     [enable_plugin_recordplay=no])],
              [enable_plugin_recordplay=yes])

AC_ARG_ENABLE([plugin-sip],
              [AS_HELP_STRING([--disable-plugin-sip],
                              [Disable sip plugin])],
              [AS_IF([test "x$enable_plugin_sip" != "xyes"],
                     [enable_plugin_sip=no])],
              [enable_plugin_sip=maybe])

AC_ARG_ENABLE([plugin-sipre],
              [AS_HELP_STRING([--disable-plugin-sipre],
                              [Disable sipre plugin])],
              [AS_IF([test "x$enable_plugin_sipre" != "xyes"],
                     [enable_plugin_sipre=no])],
              [enable_plugin_sipre=maybe])

AC_ARG_ENABLE([plugin-nosip],
              [AS_HELP_STRING([--disable-plugin-nosip],
                              [Disable nosip plugin])],
              [AS_IF([test "x$enable_plugin_nosip" != "xyes"],
                     [enable_plugin_nosip=no])],
              [enable_plugin_nosip=yes])

AC_ARG_ENABLE([plugin-streaming],
              [AS_HELP_STRING([--disable-plugin-streaming],
                              [Disable streaming plugin])],
              [AS_IF([test "x$enable_plugin_streaming" != "xyes"],
                     [enable_plugin_streaming=no])],
              [enable_plugin_streaming=yes])

AC_ARG_ENABLE([plugin-textroom],
              [AS_HELP_STRING([--disable-plugin-textroom],
                              [Disable textroom plugin])],
              [AS_IF([test "x$enable_plugin_textroom" != "xyes"],
                     [enable_plugin_textroom=no])],
              [enable_plugin_textroom=yes])

AC_ARG_ENABLE([plugin-videocall],
              [AS_HELP_STRING([--disable-plugin-videocall],
                              [Disable videocall plugin])],
              [AS_IF([test "x$enable_plugin_videocall" != "xyes"],
                     [enable_plugin_videocall=no])],
              [enable_plugin_videocall=yes])

AC_ARG_ENABLE([plugin-videoroom],
              [AS_HELP_STRING([--disable-plugin-videoroom],
                              [Disable videoroom plugin])],
              [AS_IF([test "x$enable_plugin_videoroom" != "xyes"],
                     [enable_plugin_videoroom=no])],
              [enable_plugin_videoroom=yes])

AC_ARG_ENABLE([plugin-voicemail],
              [AS_HELP_STRING([--disable-plugin-voicemail],
                              [Disable voicemail plugin])],
              [AS_IF([test "x$enable_plugin_voicemail" != "xyes"],
                     [enable_plugin_voicemail=no])],
              [enable_plugin_voicemail=maybe])

PKG_CHECK_MODULES([SOFIA],
                  [sofia-sip-ua],
                  [
                    AS_IF([test "x$enable_plugin_sip" = "xmaybe"],
                          [enable_plugin_sip=yes])
                  ],
                  [
                    AS_IF([test "x$enable_plugin_sip" = "xyes"],
                          [AC_MSG_ERROR([sofia-sip-ua not found. See README.md for installation instructions or use --disable-plugin-sip])])
                  ])
AC_SUBST([SOFIA_CFLAGS])
AC_SUBST([SOFIA_LIBS])

PKG_CHECK_MODULES([LIBRE],
                  [libre >= 0.5.7],
                  [
                    AS_IF([test "x$enable_plugin_sipre" = "xmaybe"],
                          [
                           enable_plugin_sipre=yes
                           AC_DEFINE(HAVE_LIBRE_SIPREGNEWAPI)
                           AC_CHECK_LIB([re],
                                        [sip_set_trace],
                                        [AC_DEFINE(HAVE_LIBRE_SIPTRACE)],
                                        [AC_MSG_NOTICE([libre version does not have sip_set_trace])]
                                       )
                          ])
                  ],
                  [PKG_CHECK_MODULES([LIBRE],
                                     [libre],
                                     [
                                      AS_IF([test "x$enable_plugin_sipre" = "xmaybe"],
                                            [
                                             enable_plugin_sipre=yes
                                             AC_CHECK_LIB([re],
                                                          [sip_set_trace],
                                                          [AC_DEFINE(HAVE_LIBRE_SIPTRACE)],
                                                          [AC_MSG_NOTICE([libre version does not have sip_set_trace])]
                                                         )
                                            ])
                                     ],
                                     [
                                      AS_IF([test "x$enable_plugin_sipre" = "xyes"],
                                            [AC_MSG_ERROR([libre not found. See README.md for installation instructions or use --disable-plugin-sip])])
                                     ])
                  ])
AC_SUBST([SOFIA_CFLAGS])
AC_SUBST([SOFIA_LIBS])

PKG_CHECK_MODULES([OPUS],
                  [opus],
                  [
                    AS_IF([test "x$enable_plugin_audiobridge" = "xmaybe"],
                          [enable_plugin_audiobridge=yes])
                  ],
                  [
                    AS_IF([test "x$enable_plugin_audiobridge" = "xyes"],
                          [AC_MSG_ERROR([libopus not found. See README.md for installation instructions or use --disable-plugin-audiobridge])])
                  ])
AC_SUBST([OPUS_CFLAGS])
AC_SUBST([OPUS_LIBS])

PKG_CHECK_MODULES([OGG],
                  [ogg],
                  [
                    AS_IF([test "x$enable_plugin_voicemail" = "xmaybe"],
                          [enable_plugin_voicemail=yes])
                  ],
                  [
                    AS_IF([test "x$enable_plugin_voicemail" = "xyes"],
                          [AC_MSG_ERROR([libogg not found. See README.md for installation instructions or use --disable-plugin-voicemail])])
                  ])
AC_SUBST([OGG_CFLAGS])
AC_SUBST([OGG_LIBS])

PKG_CHECK_MODULES([LUA],
                  [lua],
                  [
                    AS_IF([test "x$enable_plugin_lua" = "xmaybe"],
                          [enable_plugin_lua=yes])
                  ],
                  [PKG_CHECK_MODULES([LUA],
                                     [lua5.3],
                                     [
                                       AS_IF([test "x$enable_plugin_lua" = "xmaybe"],
                                             [enable_plugin_lua=yes])
                                     ],
                                     [
                                       AS_IF([test "x$enable_plugin_lua" = "xyes"],
                                             [AC_MSG_ERROR([lua-libs not found. See README.md for installation instructions or use --disable-plugin-lua])])
                                     ])
                  ])
AC_SUBST([LUA_CFLAGS])
AC_SUBST([LUA_LIBS])

AM_CONDITIONAL([ENABLE_PLUGIN_AUDIOBRIDGE], [test "x$enable_plugin_audiobridge" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_DUKTAPE], [test "x$enable_plugin_duktape" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_ECHOTEST], [test "x$enable_plugin_echotest" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_LUA], [test "x$enable_plugin_lua" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_RECORDPLAY], [test "x$enable_plugin_recordplay" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_SIP], [test "x$enable_plugin_sip" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_SIPRE], [test "x$enable_plugin_sipre" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_NOSIP], [test "x$enable_plugin_nosip" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_STREAMING], [test "x$enable_plugin_streaming" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_VIDEOCALL], [test "x$enable_plugin_videocall" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_VIDEOROOM], [test "x$enable_plugin_videoroom" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_VOICEMAIL], [test "x$enable_plugin_voicemail" = "xyes"])
AM_CONDITIONAL([ENABLE_PLUGIN_TEXTROOM], [test "x$enable_plugin_textroom" = "xyes"])


##
# Event handlers
##

PKG_CHECK_MODULES([EVENTS],
                  [
                    glib-2.0 >= $glib_version
                    jansson >= $jansson_version
                  ])


##
# JavaScript modules
##

AC_ARG_ENABLE([javascript-es-module],
              [AS_HELP_STRING([--enable-javascript-es-module],
                              [Generate an ECMAScript style module from janus.js])],
              [AS_IF([test "x$enable_javascript_es_module" = "xyes"],
                     [enable_javascript_es_module=yes])],
              [enable_javascript_es_module=no])
AM_CONDITIONAL([ENABLE_JAVASCRIPT_ES_MODULE], [test "x$enable_javascript_es_module" = "xyes" ])

AC_ARG_ENABLE([javascript-umd-module],
              [AS_HELP_STRING([--enable-javascript-umd-module],
                              [Generate an UMD style module from janus.js])],
              [AS_IF([test "x$enable_javascript_umd_module" = "xyes"],
                     [enable_javascript_umd_module=yes])],
              [enable_javascript_umd_module=no])
AM_CONDITIONAL([ENABLE_JAVASCRIPT_UMD_MODULE], [test "x$enable_javascript_umd_module" = "xyes" ])

AC_ARG_ENABLE([javascript-iife-module],
              [AS_HELP_STRING([--enable-javascript-iife-module],
                              [Generate an IIFE style wrapper around janus.js])],
              [AS_IF([test "x$enable_javascript_iife_module" = "xyes"],
                     [enable_javascript_iife_module=yes])],
              [enable_javascript_iife_module=no])
AM_CONDITIONAL([ENABLE_JAVASCRIPT_IIFE_MODULE], [test "x$enable_javascript_iife_module" = "xyes" ])

AC_ARG_ENABLE([javascript-common-js-module],
              [AS_HELP_STRING([--enable-javascript-common-js-module],
                              [Generate an CommonJS style module from janus.js])],
              [AS_IF([test "x$enable_javascript_common_js_module" = "xyes"],
                     [enable_javascript_common_js_module=yes])],
              [enable_javascript_common_js_module=no])
AM_CONDITIONAL([ENABLE_JAVASCRIPT_COMMON_JS_MODULE], [test "x$enable_javascript_common_js_module" = "xyes" ])

case "-${enable_javascript_common_js_module}-${enable_javascript_iife_module}-${enable_javascript_umd_module}-${enable_javascript_es_module}-" in
    *-yes*)
        AM_CONDITIONAL([ENABLE_JAVASCRIPT_MODULES], true)
    ;;
    *)
        AM_CONDITIONAL([ENABLE_JAVASCRIPT_MODULES], false)
    ;;
esac

AC_ARG_VAR(NPM,"npm executable to use")
AC_PATH_PROG(NPM,npm,,)
AM_CONDITIONAL([NPM_FOUND], [test "x$NPM" != "x" ])
AM_COND_IF([ENABLE_JAVASCRIPT_MODULES],[
    AM_COND_IF([NPM_FOUND],,[AC_MSG_ERROR([npm not found])])
])


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
                           glib-2.0 >= $glib_version
                           jansson >= $jansson_version
                           libavutil
                           libavcodec
                           libavformat
                           ogg
                         ])
      ])

AM_CONDITIONAL([WITH_SOURCE_DATE_EPOCH], [test "x$SOURCE_DATE_EPOCH" != "x"])
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
echo "Compiler:                  $CC"
AM_COND_IF([ENABLE_LIBSRTP_2],
	[echo "libsrtp version:           2.x"],
	[echo "libsrtp version:           1.5.x"])
AM_COND_IF([ENABLE_BORINGSSL],
	[echo "SSL/crypto library:        BoringSSL"
	 AM_COND_IF([ENABLE_DTLS_SETTIMEOUT],
		[echo "DTLS set-timeout:          yes"],
		[echo "DTLS set-timeout:          no"])
	],
	[AM_COND_IF([LIBRESSL_DETECTED],
		[echo "SSL/crypto library:        LibreSSL"],
		[echo "SSL/crypto library:        OpenSSL"])
	 echo "DTLS set-timeout:          not available"])
AM_COND_IF([ENABLE_PTHREAD_MUTEX],
	[echo "Mutex implementation:      pthread mutex"],
	[echo "Mutex implementation:      GMutex (native futex on Linux)"])
AM_COND_IF([ENABLE_SCTP],
	[echo "DataChannels support:      yes"],
	[echo "DataChannels support:      no"])
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
AM_COND_IF([ENABLE_MQTT],
	[echo "    MQTT:                  yes"],
	[echo "    MQTT:                  no"])
AM_COND_IF([ENABLE_PFUNIX],
	[echo "    Unix Sockets:          yes"],
	[echo "    Unix Sockets:          no"])
AM_COND_IF([ENABLE_NANOMSG],
	[echo "    Nanomsg:               yes"],
	[echo "    Nanomsg:               no"])
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
	[echo "    SIP Gateway (Sofia):   yes"],
	[echo "    SIP Gateway (Sofia):   no"])
AM_COND_IF([ENABLE_PLUGIN_SIPRE],
	[echo "    SIP Gateway (libre):   yes"],
	[echo "    SIP Gateway (libre):   no"])
AM_COND_IF([ENABLE_PLUGIN_NOSIP],
	[echo "    NoSIP (RTP Bridge):    yes"],
	[echo "    NoSIP (RTP Bridge):    no"])
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
AM_COND_IF([ENABLE_PLUGIN_TEXTROOM],
	[echo "    Text Room:             yes"],
	[echo "    Text Room:             no"])
AM_COND_IF([ENABLE_PLUGIN_LUA],
	[echo "    Lua Interpreter:       yes"],
	[echo "    Lua Interpreter:       no"])
AM_COND_IF([ENABLE_PLUGIN_DUKTAPE],
	[echo "    Duktape Interpreter:   yes"],
	[echo "    Duktape Interpreter:   no"])
echo "Event handlers:"
AM_COND_IF([ENABLE_SAMPLEEVH],
	[echo "    Sample event handler:  yes"],
	[echo "    Sample event handler:  no"])
AM_COND_IF([ENABLE_RABBITMQEVH],
	[echo "    RabbitMQ event handler:yes"],
	[echo "    RabbitMQ event handler:no"])
AM_COND_IF([ENABLE_MQTTEVH],
	[echo "    MQTT event handler:    yes"],
	[echo "    MQTT event handler:    no"])
AM_COND_IF([ENABLE_JAVASCRIPT_MODULES], [
	echo "JavaScript modules:        yes"
	echo "    Using npm:             $NPM"
	AM_COND_IF([ENABLE_JAVASCRIPT_ES_MODULE],
		[echo "    ES syntax:             yes"],
		[echo "    ES syntax:             no"])
	AM_COND_IF([ENABLE_JAVASCRIPT_IIFE_MODULE],
		[echo "    IIFE syntax:           yes"],
		[echo "    IIFE syntax:           no"])
	AM_COND_IF([ENABLE_JAVASCRIPT_UMD_MODULE],
		[echo "    UMD syntax:            yes"],
		[echo "    UMD syntax:            no"])
	AM_COND_IF([ENABLE_JAVASCRIPT_COMMON_JS_MODULE],
		[echo "    CommonJS syntax:       yes"],
		[echo "    CommonJS syntax:       no"])
	],
	[echo "JavaScript modules:        no"])

echo
echo "If this configuration is ok for you, do a 'make' to start building Janus. A 'make install' will install Janus and its plugins to the specified prefix. Finally, a 'make configs' will install some sample configuration files too (something you'll only want to do the first time, though)."
echo
