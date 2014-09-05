#!/bin/sh

PKG_CONFIG=`which pkg-config`
MAKE=`which make`
GENGETOPT=`which gengetopt`
DOXYGEN=`which doxygen`
DOT=`which dot`
WGET=`which wget`
CURL=`which curl`

export INSTALLSH="install.sh"

NODOCS=0
NODATACHANS=0
NOWEBSOCKETS=0
case "$1" in
	--help)
		echo "Usage: $0 [options]"
		echo "    --nodatachans        disable Data Channels support (no usrsctp needed)"
		echo "    --nowebsockets       disable WebSockets support (no libwebsock needed)"
		echo "    --nodocs             don't build documentation"
		echo "    --help               show this help message and exit"
		exit 0
		;;
esac
echo "Installing the Janus WebRTC gateway..."
case "$1" in
	nodocs)
		echo "  -- nodocs passed, skipping documentation!"
		NODOCS=1
		;;
	nodatachans)
		echo "  -- nodatachans passed, disabling Data Channels support!"
		NODATACHANS=1
		;;
	nowebsockets)
		echo "  -- nowebsockets passed, disabling WebSockets support!"
		NOWEBSOCKETS=1
		;;
esac
case "$2" in
	nodocs)
		echo "  -- nodocs passed, skipping documentation!"
		NODOCS=1
		;;
	nodatachans)
		echo "  -- nodatachans passed, disabling Data Channels support!"
		NODATACHANS=1
		;;
	nowebsockets)
		echo "  -- nowebsockets passed, disabling WebSockets support!"
		NOWEBSOCKETS=1
		;;
esac
case "$3" in
	nodocs)
		echo "  -- nodocs passed, skipping documentation!"
		NODOCS=1
		;;
	nodatachans)
		echo "  -- nodatachans passed, disabling Data Channels support!"
		NODATACHANS=1
		;;
	nowebsockets)
		echo "  -- nowebsockets passed, disabling WebSockets support!"
		NOWEBSOCKETS=1
		;;
esac

if [ -z "$PKG_CONFIG" ]
then
	echo "pkg-config is missing, please install it";
	exit 1;
fi
if [ -z "$MAKE" ]
then
	echo "No make?? please install it...";
	exit 1;
fi

echo
echo "Checking dependencies..."
for x in glib-2.0 nice libmicrohttpd jansson libssl libcrypto sofia-sip-ua ini_config
do
	DEPENDENCY=`pkg-config --cflags --libs $x`
	if [ -z "$DEPENDENCY" ]
	then
		echo "$x is missing, please install it"
		exit 1;
	fi
done
pkg-config --atleast-version=2.32 glib-2.0
if [ $? != 0 ]
then
	echo "  -- The installed glib-2.0 version (`pkg-config --modversion glib-2.0`) is outdated, at least 2.32 is required"
	exit 1
fi
pkg-config --atleast-version=1.0.1 openssl
if [ $? != 0 ]
then
	echo "  -- The installed openssl version (`pkg-config --modversion openssl`) is outdated, at least 1.0.1e is required"
	exit 1
fi
pkg-config --exists opus
if [ $? != 0 ]
then
	echo "  -- opus is not installed, the AudioBridge plugin will not be built"
	sleep 2
else
	export HAVE_OPUS=1
fi
pkg-config --exists ogg
if [ $? != 0 ]
then
	echo "  -- libogg is not installed, the VoiceMail plugin will not be built"
	sleep 2
else
	export HAVE_OGG=1
fi
LIBNICE=`ldconfig -p | grep libnice.so | tail -n 1`
set -- junk $LIBNICE
shift
PORTRANGE=`nm -AD $4 | grep nice_agent_set_port_range`
if [ -z "$PORTRANGE" ]
then
	echo "  -- Your version of libnice does not have nice_agent_set_port_range: support for configuring an RTP/RTCP range will be disabled"
	sleep 2
else
	export HAVE_PORTRANGE="-DHAVE_PORTRANGE"
fi
if test $NODATACHANS -eq 0
then
	export SCTP_LIB="-lusrsctp"
	export HAVE_SCTP="-DHAVE_SCTP"
	$MAKE sctptest
	if [ $? != 0 ]
	then
		echo
		echo "The installer couldn't find the usrsctp lib, which is needed for Data Channels"
		echo "You can install it with the following steps:"
		echo "    svn co http://sctp-refimpl.googlecode.com/svn/trunk/KERN/usrsctp usrsctp"
		echo "    cd usrsctp"
		echo "    ./bootstrap"
		echo "    ./configure --prefix=/usr && make && sudo make install"
		echo
		echo "    [Note: you may need to pass --libdir=/usr/lib64 to the configure script if you're installing on a x86_64 distribution]"
		echo
		echo "If you're not interested in Data Channels, you can disable them passing nodatachans to the install script:" 
		echo "    ./install.sh nodatachans"
		echo 
		exit 1
	fi
fi
if test $NOWEBSOCKETS -eq 0
then
	export WS_LIB="-lwebsock"
	export HAVE_WEBSOCKETS="-DHAVE_WEBSOCKETS"
	$MAKE wstest
	if [ $? != 0 ]
	then
		echo
		echo "The installer couldn't find the libwebsock lib, which is needed for WebSockets"
		echo "You can install version 1.0.4 (required!) with the following steps:"
		echo "    wget http://paydensutherland.com/libwebsock-1.0.4.tar.gz"
		echo "    tar xfv libwebsock-1.0.4.tar.gz"
		echo "    cd libwebsock-1.0.4"
		echo "    ./configure --prefix=/usr && make && sudo make install"
		echo
		echo "    [Note: you may need to pass --libdir=/usr/lib64 to the configure script if you're installing on a x86_64 distribution]"
		echo
		echo "If you're not interested in WebSockets support, you can disable them passing nowebsockets to the install script:" 
		echo "    ./install.sh nowebsockets"
		echo 
		exit 1
	fi
fi

echo
echo "Compiling..."
$MAKE cmdline
$MAKE
if test $? -eq 0
then
	echo "Built!"
else
	echo "Error compiling, giving up..."
	exit 1
fi

if test $NODOCS -eq 0
then
	echo
	echo "Generating documentation..."
	if [ -z "$DOXYGEN" ] || [ -z "$DOT" ]
	then
		echo "Doxygen or graphviz missing, no documentation will be built...";
	else
		$MAKE docs
	fi
fi

echo
echo "Downlading samples for the streaming demo..."
if [ -n "$WGET" ]
then
	[ ! -f ./plugins/streams/radio.alaw ] && $WGET -c -O ./plugins/streams/radio.alaw http://janus.conf.meetecho.com/samples/radio.alaw
	[ ! -f ./plugins/streams/music.mulaw ] && $WGET -c -O ./plugins/streams/music.mulaw http://janus.conf.meetecho.com/samples/music.mulaw
elif [ -n "$CURL" ]
then
	[ ! -f ./plugins/streams/radio.alaw ] && $CURL -C - -o ./plugins/streams/radio.alaw http://janus.conf.meetecho.com/samples/radio.alaw
	[ ! -f ./plugins/streams/music.mulaw ] && $CURL -C - -o ./plugins/streams/music.mulaw http://janus.conf.meetecho.com/samples/music.mulaw
else
	echo "  Couldn't find wget or curl, please download the following files"
	echo "  yourself and place them in the plugins/streams/ folder if you want to"
	echo "  test the default configuration of the Streaming plugin:"
	echo "   -- http://janus.conf.meetecho.com/samples/radio.alaw"
	echo "   -- http://janus.conf.meetecho.com/samples/music.mulaw"
fi

echo
echo "Done! Check the configuration files for both the gateway and the plugins in the 'conf' folder."
echo
echo "If you're also interested in compiling the Janus recordings post-processing utility, launch the install.sh script in the postprocessing folder:"
echo "    cd postprocessing"
echo "    ./install.sh"
echo
echo "Type './janus -h' for help on Janus"
echo
