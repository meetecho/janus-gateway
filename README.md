Janus WebRTC Gateway
====================

Janus is an open source, general purpose, WebRTC gateway designed and
developed by [Meetecho](http://www.meetecho.com). This version
of the gateway can be installed on Linux, OS X and Windows systems.

For some online demos and documentations, make sure you pay the
[project website](http://janus.conf.meetecho.com/) a visit!

To discuss Janus with us and other users, there's a Google Group called
[meetecho-janus](http://groups.google.com/d/forum/meetecho-janus) that
you can use. If you encounter issues, though, please submit an issue
on [github](https://github.com/meetecho/janus-gateway/issues) instead.


##Dependencies on Linux or OS X
To install it, you'll need to satisfy the following dependencies:

* [Jansson](http://www.digip.org/jansson/)
* [libnice](http://nice.freedesktop.org/wiki/)
* [OpenSSL](http://www.openssl.org/) (at least v1.0.1e)
* [libsrtp](https://github.com/cisco/libsrtp) (at least v1.5 suggested)
* [Sofia-SIP](http://sofia-sip.sourceforge.net/)
* [usrsctp](https://github.com/sctplab/usrsctp) (only needed if you
are interested in Data Channels)
* [libmicrohttpd](http://www.gnu.org/software/libmicrohttpd/) (only
needed if you are interested in REST support for the Janus API)
* [libwebsockets](https://libwebsockets.org/) (only needed if
you are interested in WebSockets support for the Janus API)
* [cmake](http://www.cmake.org/) (only needed if you are interested in
WebSockets and/or BoringSSL support, as they make use of it)
* [rabbitmq-c](https://github.com/alanxz/rabbitmq-c) (only needed if
you are interested in RabbitMQ support for the Janus API)

A couple of plugins depend on a few more libraries:

* [libopus](http://opus-codec.org/) (only needed for the bridge plugin)
* [libogg](http://xiph.org/ogg/) (only needed for the voicemail plugin)

Additionally, you'll need the following libraries and tools:

* [GLib](http://library.gnome.org/devel/glib/)
* [pkg-config](http://www.freedesktop.org/wiki/Software/pkg-config/)
* [gengetopt](http://www.gnu.org/software/gengetopt/)

All of those libraries are usually available on most of the most common
distributions. Installing these libraries on a recent Fedora, for
instance, is very simple:

    yum install libmicrohttpd-devel jansson-devel libnice-devel \
       openssl-devel libsrtp-devel sofia-sip-devel glib-devel \
       opus-devel libogg-devel pkgconfig gengetopt libtool autoconf automake

Notice that you may have to ```yum install epel-release``` as well if you're
attempting an installation on a CentOS machine instead.

On Ubuntu or Debian, it would require something like this:

	aptitude install libmicrohttpd-dev libjansson-dev libnice-dev \
		libssl-dev libsrtp-dev libsofia-sip-ua-dev libglib2.0-dev \
		libopus-dev libogg-dev pkg-config gengetopt libtool automake

* *Note:* please notice that libopus may not be available out of the box
on Ubuntu or Debian, unless you're using a recent version (e.g., Ubuntu
14.04 LTS). In that case, you'll have to [install it manually](http://www.opus-codec.org).

If your distro ships a pre-1.5 version of libsrtp, it may be better to
uninstall that version and [install 1.5 manually](https://github.com/cisco/libsrtp/releases).
In fact, 1.4.x is known to cause several issues with WebRTC. Installation
is quite straightforward:

	wget https://github.com/cisco/libsrtp/archive/v1.5.0.tar.gz
	tar xfv v1.5.0.tar.gz
	cd libsrtp-1.5.0
	./configure --prefix=/usr --enable-openssl
	make libsrtp.so && sudo make install

* *Note:* you may need to pass --libdir=/usr/lib64 to the configure
script if you're installing on a x86_64 distribution.

If you want to make use of BoringSSL instead of OpenSSL (e.g., because
you want to take advantage of `--enable-dtls-settimeout`), you'll have
to manually install it to a specific location. Use the following steps:

	git clone https://boringssl.googlesource.com/boringssl
	cd boringssl
	# Don't barf on errors
	sed -i s/" -Werror"//g CMakeLists.txt
	# Build
	mkdir -p build
	cd build
	cmake -DCMAKE_CXX_FLAGS="-lrt" ..
	make
	cd ..
	# Install
	sudo mkdir -p /opt/boringssl
	sudo cp -R include /opt/boringssl/
	sudo mkdir -p /opt/boringssl/lib
	sudo cp build/ssl/libssl.a /opt/boringssl/lib/
	sudo cp build/crypto/libcrypto.a /opt/boringssl/lib/

Once the library is installed, you'll have to pass an additional
```--enable-boringssl``` flag to the configure script, as by default
Janus will be build assuming OpenSSL will be used. If you were using
OpenSSL and want to switch to BoringSSL, make sure you also do a
```make clean``` in the Janus folder before compiling with the new
BoringSSL support.

For what concerns usrsctp, which is needed for Data Channels support, it
is usually not available in repositories, so if you're interested in
them (support is optional) you'll have to install it manually. It is a
pretty easy and standard process:

	git clone https://github.com/sctplab/usrsctp
	cd usrsctp
	./bootstrap
	./configure --prefix=/usr && make && sudo make install

* *Note:* you may need to pass --libdir=/usr/lib64 to the configure
script if you're installing on a x86_64 distribution.

The same applies for libwebsockets, which is needed for the optional
WebSockets support. If you're interested in supporting WebSockets to
control Janus, as an alternative (or replacement) to the default plain
HTTP REST API, you'll have to install it manually:

	git clone git://git.libwebsockets.org/libwebsockets
	cd libwebsockets
	# If you want the stable version of libwebsockets, uncomment the next line
	# git checkout v1.5-chrome47-firefox41
	mkdir build
	cd build
	cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_C_FLAGS="-fpic" ..
	make && sudo make install

* *Note:* if libwebsockets.org is unreachable for any reason, replace
the first line with this:

	git clone https://github.com/warmcat/libwebsockets.git

Finally, the same can be said for rabbitmq-c as well, which is needed
for the optional RabbitMQ support. In fact, several different versions
of the library can be found, and the versions usually available in most
distribution repositories are not up-do-date with respect to the current
state of the development. As such, if you're interested in integrating
RabbitMQ queues as an alternative (or replacement) to HTTP and/or
WebSockets to control Janus, you can install the latest version with the
following steps:

	git clone https://github.com/alanxz/rabbitmq-c
	cd rabbitmq-c
	git submodule init
	git submodule update
	autoreconf -i
	./configure --prefix=/usr && make && sudo make install

* *Note:* you may need to pass --libdir=/usr/lib64 to the configure
script if you're installing on a x86_64 distribution.

To conclude, should you be interested in building the gateway
documentation as well, you'll need some additional tools too:

* [Doxygen](http://www.doxygen.org)
* [Graphviz](http://www.graphviz.org/)

On Fedora:

	yum install doxygen graphviz

On Ubuntu/Debian:

	aptitude install doxygen graphviz

#Dependencies on Windows

Compilation under Windows is pretty complicated. It requires
MSYS2 development environment to be installed. In order to install it follow
the guide under following link:

	https://msys2.github.io/

Once it is installed open migw32 or mingw64 shell and install additional MSYS2
tools:

	pacman -S --noconfirm make git wget libtool autoconf automake doxygen \
		gengetopt pkg-config patch

and following packages for x86 version (mingw32) to build 32-bit binary:

	pacman -S --noconfirm mingw-w64-i686-toolchain mingw-w64-i686-glib2 \
		mingw-w64-i686-libnice mingw-w64-i686-dlfcn \
		mingw-w64-i686-libwebsockets mingw-w64-i686-opus \
		mingw-w64-i686-libogg mingw-w64-i686-jansson \
		mingw-w64-i686-curl mingw-w64-i686-cmake mingw-w64-i686-ffmpeg \
		mingw-w64-i686-libsrtp mingw-w64-i686-usrsctp mingw-w64-i686-rabbitmq-c

Similarly you can install packages for x86_64 version (mingw64) to build 64-bit
binary:

	pacman -S --noconfirm mingw-w64-x86_64-toolchain mingw-w64-x86_64-glib2 \
		mingw-w64-x86_64-libnice  mingw-w64-x86_64-dlfcn \
		mingw-w64-x86_64-libwebsockets mingw-w64-x86_64-opus \
		mingw-w64-x86_64-libogg mingw-w64-x86_64-jansson \
		mingw-w64-x86_64-curl mingw-w64-x86_64-cmake mingw-w64-x86_64-ffmpeg \
		mingw-w64-x86_64-libsrtp mingw-w64-x86_64-usrsctp \
		mingw-w64-x86_64-rabbitmq-c

There are some dependencies that you have to compile and install manually
because its binaries are not accessible from pacman repository yet.
However pacman scripts with all the patches for all remianing dependencies
were submitted to

	https://github.com/Alexpux/MINGW-packages

for your convenience.

libmicrohttpd (x86, x86_64):

	mkdir mingw-w64-libmicrohttpd
	cd mingw-w64-libmicrohttpd
	wget https://raw.githubusercontent.com/Alexpux/MINGW-packages/master/mingw-w64-libmicrohttpd/PKGBUILD
	makepkg-mingw -sLfi --noconfirm

Sofia-SIP (x86, x86_64):

	mkdir mingw-w64-sofia-sip-git
	cd mingw-w64-sofia-sip-git
	wget https://raw.githubusercontent.com/Alexpux/MINGW-packages/master/mingw-w64-sofia-sip-git/PKGBUILD
	wget https://raw.githubusercontent.com/Alexpux/MINGW-packages/master/mingw-w64-sofia-sip-git/0001-add-mingw-support.patch
	wget https://raw.githubusercontent.com/Alexpux/MINGW-packages/master/mingw-w64-sofia-sip-git/0002-su-select-port.patch
	wget https://raw.githubusercontent.com/Alexpux/MINGW-packages/master/mingw-w64-sofia-sip-git/0003-inet-pton-ntop-fix.patch
	wget https://raw.githubusercontent.com/Alexpux/MINGW-packages/master/mingw-w64-sofia-sip-git/0004-add-su_win32_port.patch
	wget https://raw.githubusercontent.com/Alexpux/MINGW-packages/master/mingw-w64-sofia-sip-git/0005-add-no-undefined-flag.patch
	makepkg-mingw -sLfi --noconfirm

* *Note:*

If you need to build Janus Gateway documentation please install Windows version
of Graphviz from

	http://www.graphviz.org/Download_windows.php

and make sure ```dot``` tool is in the PATH and

	MSYS2_PATH_TYPE=inherit

is not commented out in the mingw*.ini file.

* *Note:*

Windows version of Janus WebRTC Gateway fully supports Service Control
Manager. You can create Janus WebRTC Gateway Windows Service by e.g.:

	sc create "Janus WebRTC Gateway" binpath=c:/msys64/mingw64/bin/janus.exe

To remove the service from Windows system type:

	sc delete "Janus WebRTC Gateway"

To start Janus WebRTC Windows Service execute:

	sc start "Janus WebRTC Gateway"

To stop Janus WebRTC Windows Service execute: 

	sc stop "Janus WebRTC Gateway"

##Compile
Once you have installed all the dependencies, get the code:

	git clone https://github.com/meetecho/janus-gateway.git
	cd janus-gateway

Then just use:

	sh autogen.sh

to generate the configure file. After that, configure and compile as
usual to start the whole compilation process:

	./configure --prefix=/opt/janus
	make
	make install

Since Janus requires configuration files for both the core and its
modules in order to work, you'll probably also want to install the
default configuration files to use, which you can do this way:

	make configs

Remember to only do this once, or otherwise a subsequent ```make configs```
will overwrite any configuration file you may have modified in the
meanwhile.

If you're not interested in Data Channels, WebSockets and/or RabbitMQ
(or you don't care about either of them) you can disable them when
configuring:

	./configure --disable-websockets --disable-data-channels --disable-rabbitmq

If Doxygen and graphviz are available, the process can also build the
documentation for you. By default the compilation process will not try
to build the documentation, so if you instead prefer to build it, use the
--enable-docs configuration option:

	./configure --enable-docs

You can also selectively enable/disable other features (e.g., specific
plugins you don't care about). Use the --help option when configuring
for more info.


##Configure and start
To start the gateway, you can use the janus executable. There are several
things you can configure, either in a configuration file:

	<installdir>/etc/janus/janus.cfg

or on the command line:

	<installdir>/bin/janus --help
	
	janus 0.2.0

	Usage: janus [OPTIONS]...

	-h, --help                    Print help and exit
	-V, --version                 Print version and exit
	-b, --daemon                  Launch Janus in background as a daemon
                                  (default=off)
	-N, --disable-stdout          Disable stdout based logging  (default=off)
	-L, --log-file=path           Log to the specified file (default=stdout only)
	-i, --interface=ipaddress     Interface to use (will be the public IP)
	-P, --plugins-folder=path     Plugins folder (default=./plugins)
	-C, --config=filename         Configuration file to use
	-F, --configs-folder=path     Configuration files folder (default=./conf)
	-c, --cert-pem=filename       DTLS certificate
	-k, --cert-key=filename       DTLS certificate key
	-S, --stun-server=filename    STUN server(:port) to use, if needed (e.g.,
								  gateway behind NAT, default=none)
	-1, --nat-1-1=ip              Public IP to put in all host candidates,
                                  assuming a 1:1 NAT is in place (e.g., Amazon
                                  EC2 instances, default=none)
	-E, --ice-enforce-list=list   Comma-separated list of the only interfaces to
                                  use for ICE gathering; partial strings are
                                  supported (e.g., eth0 or eno1,wlan0,
                                  default=none)
	-X, --ice-ignore-list=list    Comma-separated list of interfaces or IP
                                  addresses to ignore for ICE gathering;
                                  partial strings are supported (e.g.,
                                  vmnet8,192.168.0.1,10.0.0.1 or
                                  vmnet,192.168., default=vmnet)
	-6, --ipv6-candidates         Whether to enable IPv6 candidates or not
                                  (experimental)  (default=off)
	-l, --libnice-debug           Whether to enable libnice debugging or not
                                  (default=off)
	-I, --ice-lite                Whether to enable the ICE Lite mode or not
                                  (default=off)
	-T, --ice-tcp                 Whether to enable ICE-TCP or not (warning: only
                                  works with ICE Lite)
                                  (default=off)
	-U, --bundle                  Whether to force BUNDLE or not (whether audio,
                                  video and data will always be bundled)
                                  (default=off)
	-u, --rtcp-mux                Whether to force rtcp-mux or not (whether RTP
                                  and RTCP will always be muxed)  (default=off)
	-q, --max-nack-queue=number   Maximum size of the NACK queue per user for
                                  retransmissions
	-r, --rtp-port-range=min-max  Port range to use for RTP/RTCP (only available
								  if the installed libnice supports it)
	-d, --debug-level=1-7         Debug/logging level (0=disable debugging,
                                  7=maximum debug level; default=4)
	-D, --debug-timestamps        Enable debug/logging timestamps  (default=off)
	-o, --disable-colors          Disable color in the logging  (default=off)
	-a, --apisecret=randomstring  API secret all requests need to pass in order
                                  to be accepted by Janus (useful when wrapping
                                  Janus API requests in a server, none by
                                  default)
	-A, --token-auth              Enable token-based authentication for all
                                  requests  (default=off)

Options passed through the command line have the precedence on those
specified in the configuration file. To start the gateway, simply run:

	<installdir>/bin/janus

This will start the gateway, and have it look at the configuration file.

As far as transports are concerned (that is, with respect to how you can
interact with your Janus instance), using the default configuration files
provided after issuing a ```make configs``` will result in Janus only
enabling an HTTP webserver (port 8088) and a plain WebSocket server (8188),
assuming the related transport modules have been compiled, of course.
To enable HTTPS or Secure WebSockets support, edit the related transport
configuration file accordingly. You can also change the base path that
the webserver uses: by default this is ```/janus```, but you can change
it to anything you want and with any nesting you want (e.g., ```/mypath```,
```/my/path```, or ```/my/really/nested/path```). This is done to allow
you to more easily customize rules in any frontend you may have (e.g.,
Apache in front of your services). Please notice that the path configuration
is not provided for WebSockets, instead, as it is not needed there. The
RabbitMQ module, if compiled, is disabled by default, so you'll have
to enable it manually if interested in it.

To test whether it's working correctly, you can use the demos provided
with this package in the ```html``` folder: these are exactly the same demos
available online on the [project website](http://janus.conf.meetecho.com/).
Just copy the file it contains in a webserver, or use a userspace webserver
to serve the files in the ```html``` folder (e.g., with php or python),
and open the index.html page in either Chrome or Firefox. A list of demo
pages exploiting the different plugins will be available. Remember to
edit the transport/port details in the demo JavaScript files if you
changed any transport-related configuration from its defaults.


##Help us!
Any thought, feedback or (hopefully not!) insult is welcome!

Developed by [@meetecho](https://github.com/meetecho)
