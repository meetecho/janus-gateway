#!/bin/sh

set -e

echo_eval ()
{
    echo $@
    eval $@
}

echo "Number of cores available for the build: $(nproc)"
echo_eval cd /janus/src
echo_eval ./autogen.sh
echo_eval ./configure --prefix=/janus/dist $@
echo_eval make clean # useful for local development
echo_eval make # note: we do not yet take advantage of available parallelism: -j $(nproc)
echo_eval make install
