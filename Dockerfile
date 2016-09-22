FROM ubuntu:16.04
MAINTAINER Laurent COGNE <laurent@dazzl.tv>

WORKDIR /root

# Upgrade and instal basic tools
RUN apt-get update && apt-get upgrade -y && apt-get install -y ca-certificates \
    && apt-get install -y --no-install-recommends git curl wget \
    && apt-get install -y --no-install-recommends zsh

# Install build tools
RUN apt-get install -y --no-install-recommends libtool build-essential automake cmake

# Install Janus dependencies
##  several pre-packaged modules...
RUN apt-get install -y --no-install-recommends libmicrohttpd-dev libjansson-dev \
                    libnice-dev libssl-dev libsrtp-dev libsofia-sip-ua-dev \
                    libglib2.0-dev libopus-dev libogg-dev libini-config-dev \
                    libcollection-dev pkg-config  gengetopt libavutil-dev \
                    libavformat-dev libavcodec-dev

## srtp lib better than 1.4
RUN apt-get remove -y libsrtp0-dev libsrtp0
RUN wget https://github.com/cisco/libsrtp/archive/v1.5.4.tar.gz -O libsrtp-v1.5.4.tar.gz \
    && tar xzf libsrtp-v1.5.4.tar.gz && rm libsrtp-v1.5.4.tar.gz
RUN cd libsrtp-1.5.4 && ./configure --prefix=/usr --enable-openssl \
    && make shared_library && make install && cd

## usrtp for data channels
RUN git clone https://github.com/sctplab/usrsctp && cd usrsctp && ./bootstrap \
    && ./configure --prefix=/usr && make && make install && cd

## Websockets
RUN git clone git://git.libwebsockets.org/libwebsockets && cd libwebsockets \
    && git checkout v1.5-chrome47-firefox41 && mkdir build \
    && cd build && cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make && make install && cd

# Boring SSL (go lang is needed)
RUN apt-get install -y golang
RUN git clone https://boringssl.googlesource.com/boringssl && cd boringssl \
    && sed -i s/" -Werror"//g CMakeLists.txt && mkdir -p build && cd build \
    && cmake -DCMAKE_CXX_FLAGS="-lrt" .. && make && cd .. \
    && mkdir -p /opt/boringssl && cp -R include /opt/boringssl/ \
    && mkdir -p /opt/boringssl/lib && cp build/ssl/libssl.a /opt/boringssl/lib/ \
    && cp build/crypto/libcrypto.a /opt/boringssl/lib/ && cd

# Rabbit MQ
RUN git clone https://github.com/alanxz/rabbitmq-c && cd rabbitmq-c \
    && git submodule init && git submodule update && autoreconf -i \
    && ./configure --prefix=/usr && make && make install && cd

# Install Janus itself
COPY / janus-gateway
RUN cd janus-gateway && sh autogen.sh && ./configure --prefix=/usr/local \
    --enable-boringssl --enable-post-processing --disable-docs \
    && make && make configs && make install && cd

# Configure Janus
RUN sed -i -e 's/^;[[:space:]]*\(debug_timestamps.*$\)/\1/' \
        /usr/local/etc/janus/janus.cfg

# Command to execute for starting janus
ENTRYPOINT ["/usr/local/bin/janus"]
CMD ["-d4"]
