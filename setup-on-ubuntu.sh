#!/bin/bash

# REF: https://github.com/meetecho/janus-gateway/blob/master/README.md
# REF: https://groups.google.com/forum/#!msg/meetecho-janus/RYP4FBaeUi0/bIGSPZlpEQAJ
# Tested enviroment: ubuntu {14.04,16.04} LTS
# Tested Janus version: 0.2.0

# 0. Get infos and params without empty
# ======
set -e

# Default setting
SOURCE_LOCATE=$HOME
COMPILE_FOLDER=/opt/janus
ENABLE_POST_PROCESS=false
ENABLE_DATA_CHANNEL=false
ENABLE_WEB_SOCKET=false
TEMP_DIR=/tmp

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
Example: ./setup-janus -pdw

Params
  -s    SOURCE_LOCATE, Source code will be put here, DEFAULT: '${HOME}'.
  -c    COMPILE_FOLDER, 'janus-gateway' will be compiled here, DEFAULT: '/opt/janus'.

Options
  -p    Enable feature: 'post-process', DEFAULT: 'false'.
  -d    Enable feature: 'data-channel', DEFAULT: 'false'.
  -w    Enable feature: 'web-socket', DEFAULT: 'false'.
"
            exit 1
            ;;
    esac
done

echo "Janus will be setup on '${COMPILE_FOLDER}', and its source code locates '${SOURCE_LOCATE}/janus-gateway'"

# 0. Preparion
# ======
sudo apt-get update
CONFIG_COMMAND="./configure --prefix=${COMPILE_FOLDER} --enable-docs --disable-rabbitmq --disable-data-channels --disable-websockets"

# 1. Install dependencies
# ======
sudo apt-get install libmicrohttpd-dev libjansson-dev libnice-dev \
    libssl-dev libsrtp-dev libsofia-sip-ua-dev libglib2.0-dev \
    libopus-dev libogg-dev libini-config-dev libcollection-dev \
    curl libcurl3 libcurl3-dev \
    pkg-config gengetopt automake libtool doxygen graphviz git cmake

# Install `paho.mqtt.c-1.1.0`
if [ -f /usr/local/lib/libpaho-mqtt3cs.so.1 ]; then
    echo "Remove existing symlinks built by 'paho.mqtt.c' previously."
    cd /usr/local/lib
    sudo rm libpaho-mqtt3a.so libpaho-mqtt3a.so.1 libpaho-mqtt3as.so libpaho-mqtt3as.so.1 libpaho-mqtt3c.so libpaho-mqtt3c.so.1 libpaho-mqtt3cs.so libpaho-mqtt3cs.so.1
fi
cd $TEMP_DIR
wget https://github.com/eclipse/paho.mqtt.c/archive/v1.1.0.tar.gz
tar xfv v1.1.0.tar.gz
cd paho.mqtt.c-1.1.0
sudo make && sudo make install

# 2. Active Module
# ======
if [ "$ENABLE_POST_PROCESS" = true ]; then
    CONFIG_COMMAND="$CONFIG_COMMAND --enable-post-processing"
    sudo apt-get install libavformat-dev
fi

if [ "$ENABLE_DATA_CHANNEL" = true ]; then
    CONFIG_COMMAND=$(echo $CONFIG_COMMAND | sed -e "s/ --disable-data-channels//g")

    # Install `libsrtp-1.5.0`
    cd $TEMP_DIR
    wget https://github.com/cisco/libsrtp/archive/v1.5.0.tar.gz
    tar xfv v1.5.0.tar.gz
    cd libsrtp-1.5.0
    ./configure --prefix=/usr --enable-openssl
    sudo make libsrtp.so && sudo make install \
        || {
        sudo make uninstall
        sudo make libsrtp.so && sudo make install
    }

    # Install `usrsctp-0.9.3.0`
    cd $TEMP_DIR
    wget https://github.com/sctplab/usrsctp/archive/0.9.3.0.tar.gz
    tar xfv 0.9.3.0.tar.gz
    cd usrsctp-0.9.3.0
    ./bootstrap
    ./configure --prefix=/usr && sudo make && sudo make install
fi

if [ "$ENABLE_WEB_SOCKET" = true ]; then
    CONFIG_COMMAND=$(echo $CONFIG_COMMAND | sed -e "s/ --disable-websockets//g")

    cd $TEMP_DIR
    if [ ! -d libwebsockets ]; then
        git clone git://git.libwebsockets.org/libwebsockets
    fi
    cd libwebsockets

    if [ ! -d build ]; then
        mkdir build
    fi
    cd build
    sudo cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
    sudo make && sudo make install
fi

# 3. Compile `janus-gateway`
# ======
# Get code
cd $SOURCE_LOCATE
if [ ! -d janus-gateway ]; then
    git clone https://github.com/meetecho/janus-gateway.git
fi
cd janus-gateway

# Config with generated the configure file
sh autogen.sh
eval $CONFIG_COMMAND

# Compile as usual
sudo make clean
sudo make
sudo make install
sudo make configs
