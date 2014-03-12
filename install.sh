#!/bin/sh

PKG_CONFIG=`which pkg-config`
MAKE=`which make`
GENGETOPT=`which gengetopt`
DOXYGEN=`which doxygen`
DOT=`which dot`
WGET=`which wget`
CURL=`which curl`

echo "Installing the Janus WebRTC gateway..."

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

echo
echo "Compiling..."
$MAKE
if test $? -eq 0
then
	echo "Built!"
else
	echo "Error compiling, giving up..."
	exit 1
fi

echo
echo "Generating documentation..."
if [ -z "$DOXYGEN" ] || [ -z "$DOT" ]
then
	echo "Doxygen or graphviz missing, no documentation will be built...";
else
	$MAKE docs
fi

echo
echo "Downlading samples for the streaming demo..."
if [ -n "$WGET" ]
then
	$WGET -c -O ./plugins/streams/radio.alaw http://janus.conf.meetecho.com/samples/radio.alaw
	$WGET -c -O ./plugins/streams/music.mulaw http://janus.conf.meetecho.com/samples/music.mulaw
elif [ -n "$CURL" ]
then
	$CURL -C - -o ./plugins/streams/radio.alaw http://janus.conf.meetecho.com/samples/radio.alaw
	$CURL -C - -o ./plugins/streams/music.mulaw http://janus.conf.meetecho.com/samples/music.mulaw
else
	echo "  Couldn't find wget or curl, please download the following files"
	echo "  yourself and place them in the plugins/streams/ folder if you want to"
	echo "  test the default configuration of the Streaming plugin:"
	echo "   -- http://janus.conf.meetecho.com/samples/radio.alaw"
	echo "   -- http://janus.conf.meetecho.com/samples/music.mulaw"
fi

echo
echo "Done! Check the configuration files for both the gateway and the plugins in the 'conf' folder."
./janus -h
