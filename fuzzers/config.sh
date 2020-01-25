#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

# Default environment
DEFAULT_ENV="local"

# Working paths
DEFAULT_SRC="$(dirname $(dirname $SCRIPTPATH))"
DEFAULT_OUT="$SCRIPTPATH/out"
DEFAULT_WORK="$SCRIPTPATH"
DEFAULT_JANUSGW="janus-gateway"

# CFLAGS and LDFLAGS for local fuzzing
DEFAULT_CC="clang"
DEFAULT_CCLD=$DEFAULT_CC
DEFAULT_CFLAGS="-O1 -fno-omit-frame-pointer -g -ggdb3 -fsanitize=address,undefined -fsanitize-address-use-after-scope -fno-sanitize-recover=undefined -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
DEFAULT_LDFLAGS="-O1 -fno-omit-frame-pointer -g -ggdb3 -fsanitize=address,undefined -fno-sanitize-recover=undefined -fsanitize-address-use-after-scope"
COVERAGE_CFLAGS="-O1 -fno-omit-frame-pointer -g -ggdb3 -fprofile-instr-generate -fcoverage-mapping -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
COVERAGE_LDFLAGS="-O1 -fno-omit-frame-pointer -g -ggdb3 -fprofile-instr-generate -fcoverage-mapping -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

# Janus configure flags
JANUS_CONF_FLAGS="--disable-docs --disable-post-processing --disable-turn-rest-api --disable-all-transports --disable-all-plugins --disable-all-handlers --disable-data-channels"

# Janus objects needed for fuzzing
JANUS_OBJECTS="janus-log.o janus-utils.o janus-rtcp.o janus-rtp.o janus-sdp-utils.o"

# CFLAGS for fuzzer dependencies
DEPS_CFLAGS="$(pkg-config --cflags glib-2.0)"

# Libraries to link in with fuzzers
DEPS_LIB="-Wl,-Bstatic $(pkg-config --libs glib-2.0 jansson) -pthread -Wl,-Bdynamic"
DEPS_LIB_SHARED="$(pkg-config --libs glib-2.0 jansson zlib) -pthread"
