FROM ubuntu:16.04
MAINTAINER Laurent COGNE <laurent@dazzl.tv>

ARG LIBSRTP=1.5.4
ARG RABBITC=2ca1774

WORKDIR /root

# Upgrade and instal basic tools
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y ca-certificates golang\
  && apt-get install -y --no-install-recommends \
    git curl wget zsh ssh-client \
    # Install build tools
    libtool build-essential automake cmake \
    # Install Janus dependencies
    ##  several pre-packaged modules...
# RUN apt-get install -y --no-install-recommends \
    libmicrohttpd-dev libjansson-dev \
    # libnice-dev libssl-dev libsrtp-dev libsofia-sip-ua-dev \
    libnice-dev libssl-dev \
    libglib2.0-dev libopus-dev libogg-dev libini-config-dev \
    libcollection-dev pkg-config gengetopt libavutil-dev \
    libconfig-dev libavformat-dev libavcodec-dev libcurl4-gnutls-dev

## srtp lib better than 1.4
# RUN apt-get remove -y libsrtp0-dev libsrtp0
RUN wget https://github.com/cisco/libsrtp/archive/v$LIBSRTP.tar.gz -O libsrtp-v$LIBSRTP.tar.gz \
  && tar xzf libsrtp-v$LIBSRTP.tar.gz \
  && rm libsrtp-v$LIBSRTP.tar.gz \
  && cd libsrtp-$LIBSRTP \
  && ./configure --prefix=/usr --enable-openssl \
  && make shared_library\
  && make install

## usrtp for data channels
RUN git clone https://github.com/sctplab/usrsctp \
  && cd usrsctp \
  && ./bootstrap \
  && ./configure --prefix=/usr \
  && make \
  && make install

# Boring SSL (go lang is needed)
# RUN apt-get install -y golang
RUN git clone https://boringssl.googlesource.com/boringssl \
  && cd boringssl \
  && sed -i s/" -Werror"//g CMakeLists.txt \
  && mkdir -p build \
  && cd build \
  && cmake -DCMAKE_CXX_FLAGS="-lrt" .. \
  && make \
  && cd .. \
  && mkdir -p /opt/boringssl \
  && cp -R include /opt/boringssl/ \
  && mkdir -p /opt/boringssl/lib \
  && cp build/ssl/libssl.a /opt/boringssl/lib/ \
  && cp build/crypto/libcrypto.a /opt/boringssl/lib/

# Rabbit MQ
RUN git clone https://github.com/alanxz/rabbitmq-c \
  && cd rabbitmq-c \
  && git checkout $RABBITC \
  && git submodule init \
  && git submodule update \
  && autoreconf -i \
  && ./configure --prefix=/usr \
  && make \
  && make install

# Install Janus itself
COPY / janus-gateway
RUN cd janus-gateway \
  && sh autogen.sh \
  && ./configure --prefix=/usr/local \
    --enable-boringssl --enable-post-processing --enable-data-channels --disable-docs \
    # Transports
    --enable-rabbitmq --disable-unix-socket \
    --disable-websockets --disable-mqtt --disable-rest --disable-nanomsg \
    # Plugins
    --disable-plugin-audiobridge --disable-plugin-echotest --disable-plugin-recordplay \
    --disable-plugin-sip --disable-plugin-streaming --disable-plugin-videocall \
    --disable-plugin-videoroom --disable-plugin-voicemail --disable-plugin-textroom \
    --disable-plugin-duktape --disable-plugin-lua --disable-plugin-sipre \
    --disable-plugin-nosip \
    && make \
    && make configs \
    && make install

# Clean container
RUN apt-get remove -y golang \
  && rm -r janus-gateway libsrtp-$LIBSRTP boringssl rabbitmq-c usrsctp

# Command to execute for starting janus
ENTRYPOINT ["/usr/local/bin/janus"]
CMD ["-d4"]
