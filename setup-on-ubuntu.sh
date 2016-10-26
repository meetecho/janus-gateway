#!/bin/bash

# REF: https://groups.google.com/forum/#!msg/meetecho-janus/RYP4FBaeUi0/bIGSPZlpEQAJ
# Test env: ubuntu {14.04,16.04} LTS

# 0. Get infos and params without empty
# ======
# Default setting
SOURCE_LOCATE=$HOME
COMPILE_FOLDER=/opt/janus
ENABLE_POST_PROCESS=false
ENABLE_DATA_CHANNEL=false
ENABLE_WEB_SOCKET=false

while getopts "s:c:pdw" OPT; do
	case $OPT in
		s)
			SOURCE_LOCATE=$OPTARG
			echo "Set 'SOURCE_LOCATE' to '${OPTARG}'."
			;;
		c)
			COMPILE_FOLDER=$OPTARG
			echo "Set 'COMPILE_FOLDER' to '${OPTARG}'."
			;;
		p)
			ENABLE_POST_PROCESS=true
			echo "Enable feature: 'post-process'."
			;;
		d)
			ENABLE_DATA_CHANNEL=true
			echo "Enable feature: 'data-channel'."
			;;
		w)
			ENABLE_WEB_SOCKET=true
			echo "Enable feature: 'web-socket'."
			;;
		\?)
			echo "Invalid option: ${OPTARG}."
			echo "
Usage: ./setup-janus [-s <SOURCE_LOCATE>] [-c <COMPILE_FOLDER>] [OPTION]...

Params
  -s    SOURCE_LOCATE, Source code will be put here.
  -c    COMPILE_FOLDER, 'janus-gateway' will be compiled here.

Options
  -p    Enable feature: 'post-process'.
  -d    Enable feature: 'data-channel'.
  -w    Enable feature: 'web-socket'.
"
			exit 1
			;;
	esac
done

echo "Janus will be setup on '${COMPILE_FOLDER}', and its source code locates '${SOURCE_LOCATE}/janus-gateway'"

# 0. Preinstall and prepare
# ======
sudo apt-get update
CONFIG_COMMAND="./configure --prefix=${COMPILE_FOLDER} --enable-docs --disable-rabbitmq --disable-data-channels --disable-websockets"

# 1. Install dependencies
# ======
sudo apt-get install libmicrohttpd-dev libjansson-dev libnice-dev \
	libssl-dev libsrtp-dev libsofia-sip-ua-dev libglib2.0-dev \
	libopus-dev libogg-dev libini-config-dev libcollection-dev \
	pkg-config gengetopt automake libtool doxygen graphviz git cmake

# 2. Active Module
# ======
if [ "$ENABLE_POST_PROCESS" = true ]; then
	CONFIG_COMMAND="$CONFIG_COMMAND --enable-post-processing"
	sudo apt-get install libavformat-dev
fi

if [ "$ENABLE_DATA_CHANNEL" = true ]; then
	CONFIG_COMMAND=$(echo $CONFIG_COMMAND | sed -e "s/ --disable-data-channels//g")
	sudo apt-get install subversion
	svn co http://sctp-refimpl.googlecode.com/svn/trunk/KERN/usrsctp usrsctp
	cd usrsctp
	./bootstrap
	./configure --prefix=/usr && make && sudo make install
	cd ..
fi

if [ "$ENABLE_WEB_SOCKET" = true ]; then
	CONFIG_COMMAND=$(echo $CONFIG_COMMAND | sed -e "s/ --disable-websockets//g")
	git clone git://git.libwebsockets.org/libwebsockets
	cd libwebsockets
	mkdir build
	cd build
	cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
	make && sudo make install
	cd ../..
fi

# 3. Compile `janus-gateway`
# ======
# Get code
cd $SOURCE_LOCATE
git clone https://github.com/meetecho/janus-gateway.git
cd janus-gateway

# Config with generated the configure file
sh autogen.sh
eval $CONFIG_COMMAND

# Compile as usual
make clean
make
sudo make install
sudo make configs
