#!/bin/bash

janus_configure() {
  sh autogen.sh                                                                          
  export CPPFLAGS="-I${HOME}/install/srtp/include -I${HOME}/install/boringssl/include -I${HOME}/install/usrsctp/include -I${HOME}/install/rabbit/include"
  export LDFLAGS="-L${HOME}/install/srtp/lib -L${HOME}/install/boringssl/lib -L${HOME}/install/usrsctp/lib -L${HOME}/install/rabbit/lib"
  ./configure --enable-boringssl="${HOME}/install/boringssl" --disable-all-plugins
}

janus_build() {
  make
}

janus_all() {
  janus_configure
  janus_build
}

set -ev

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 {janus_configure|janus_build|janus_all}"
  exit 1
fi

eval "$1"
