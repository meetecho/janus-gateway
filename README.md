Janus WebRTC Gateway
====================

Janus is an open source, general purpose, WebRTC gateway designed and
developed by [Meetecho](http://www.meetecho.com). This version
of the gateway can only be installed on Linux systems: next versions
will take into account cross compilation on different environments.

For some online demos and documentations, make sure you pay the
[project website](http://janus.conf.meetecho.com/) a visit!

To discuss Janus with us and other users, there's a Google Group called
[meetecho-janus](http://groups.google.com/d/forum/meetecho-janus) that
you can use. If you encounter issues, though, please submit an issue
on [github](https://github.com/meetecho/janus-gateway/issues) instead.


##Dependencies
To install it, you'll need to satisfy the following dependencies:

* [libmicrohttpd](http://www.gnu.org/software/libmicrohttpd/)
* [libini-config](https://fedorahosted.org/sssd/) (INI configurations)
* [Jansson](http://www.digip.org/jansson/)
* [libnice](http://nice.freedesktop.org/wiki/)
* [OpenSSL](http://www.openssl.org/) (at least v1.0.1e)
* [libsrtp](http://srtp.sourceforge.net/srtp.html)
* [Sofia-SIP](http://sofia-sip.sourceforge.net/)
* [usrsctp](http://code.google.com/p/sctp-refimpl/) (only needed if you
are interested in Data Channels)
* [libwebsock](https://github.com/payden/libwebsock) (only needed if
you are interested in WebSockets support)
* [rabbitmq-c](https://github.com/alanxz/rabbitmq-c) (only needed if
you are interested in RabbitMQ support)

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
       opus-devel libogg-devel libini_config-devel pkg-config gengetopt

On Ubuntu or Debian, it would require something like this:

	aptitude install libmicrohttpd-dev libjansson-dev libnice-dev \
		libssl-dev libsrtp-dev libsofia-sip-ua-dev libglib2.0-dev \
		libopus-dev libogg-dev libini-config-dev libcollection-dev \
		pkg-config gengetopt

* *Note:* please notice that libopus may not be available out of the box
on Ubuntu or Debian, unless you're using a recent version (e.g., Ubuntu
14.04 LTS). In that case, you'll have to [install it manually](http://www.opus-codec.org).

For what concerns usrsctp, which is needed for Data Channels support, it
is usually not available in repositories, so if you're interested in
them (support is optional) you'll have to install it manually. It is a
pretty easy and standard process:

	svn co http://sctp-refimpl.googlecode.com/svn/trunk/KERN/usrsctp usrsctp
	cd usrsctp
	./bootstrap
	./configure --prefix=/usr && make && sudo make install
	
* *Note:* you may need to pass --libdir=/usr/lib64 to the configure
script if you're installing on a x86_64 distribution.

The same applies for libwebsock, which is needed for the optional
WebSockets support. If you're interested in supporting WebSockets to
control Janus, as an alternative (or replacement) to the default plain
HTTP REST API, you'll have to install the version ```1.0.4``` manually:

	wget http://paydensutherland.com/libwebsock-1.0.4.tar.gz
	tar xfv libwebsock-1.0.4.tar.gz
	cd libwebsock-1.0.4
	./configure --prefix=/usr && make && sudo make install
	
* *Note:* you may need to pass --libdir=/usr/lib64 to the configure
script if you're installing on a x86_64 distribution.

Please notice that you have to install version ```1.0.4``` and not any
later version. In fact, recent versions of libwebsock added support for
threading in the library, but it is currently experimental and doesn't
work as expected in Janus.

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
    configure --prefix=/usr && make && sudo make install

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


##Compile
Once you have installed all the dependencies, just use:

	sh autogen.sh

to generate the configure file. After that, configure and compile as
usual to start the whole compilation process:

	./configure --prefix=/opt/janus
	make
	make install

* *Note:* please beware that subsequent ```make install``` commands will
likely overwrite any configuration file you may have edited, so make
sure you backup them before updating a Janus installation.

If you're not interested in Data Channels, WebSockets and/or RabbitMQ
(or you don't care about either of them) you can disable them when
configuring: 

	./configure --disable-websockets --disable-data-channels --disable-rabbitmq

If Doxygen and graphviz are available, the process will also build the
documentation for you. If you prefer not to build it, use the
--disable-docs configuration option:

	./configure --disable-docs

You can also selectively enable/disable other features (e.g., specific
plugins you don't care about). Use the --help option when configuring
for more info.


##Configure and start
To start the gateway, you can use the janus executable. There are several
things you can configure, either in a configuration file:

	<installdir>/etc/janus/janus.cfg

or on the command line:

	<installdir>/bin/janus --help
	
	janus 0.0.6

	Usage: janus [OPTIONS]...

	-h, --help                    Print help and exit
	-V, --version                 Print version and exit
	-i, --interface=ipaddress     Interface to use (will be the public IP)
	-p, --port=portnumber         Web server HTTP port (default=8088)
	-s, --secure-port=portnumber  Web server HTTPS port (default=no HTTPS)
	-n, --no-http                 Disable insecure HTTP web server  (default=off)
	-b, --base-path=basepath      Base path to bind to in the web server 
								  (default=/janus) 
	-w, --ws-port=portnumber      WebSockets server port (default=no WebSockets)
	-W, --ws-secure-port=portnumber
                                  Secure WebSockets server port (default=no 
                                  secure WebSockets)
	-N, --no-websockets           Disable insecure WebSockets server  
                                  (default=off)
	-m, --admin-port=portnumber   Admin/monitor web server HTTP port 
                                  (default=7088)
	-M, --admin-secure-port=portnumber
                                  Admin/monitor web server HTTPS port (default=no 
                                  HTTPS)
	-O, --no-admin                Disable insecure HTTP admin/monitor web server  
                                  (default=off)
	-B, --admin-base-path=basepath
                                  Base path to bind to in the HTTP/HTTPS 
                                  admin/monitor web server (default=/admin) 
	-Q, --admin-secret=randomstring
                                  Admin/monitor secret all requests need to pass 
                                  in order to be accepted by Janus (useful a 
                                  crude form of authentication, none by 
                                  default)
	-L, --admin-acl=list          Comma-separated list of IP addresses allowed to 
                                  use the Admin/monitor; partial strings are 
                                  supported (e.g., 192.168.0.1,10.0.0.1 or 
                                  192.168., default=no restriction)
	-P, --plugins-folder=path     Plugins folder (default=./plugins)
	-C, --config=filename         Configuration file to use
	-F, --configs-folder=path     Configuration files folder (default=./conf)
	-c, --cert-pem=filename       HTTPS/DTLS certificate
	-k, --cert-key=filename       HTTPS/DTLS certificate key
	-S, --stun-server=filename    STUN server(:port) to use, if needed (e.g., 
								  gateway behind NAT, default=none)
	-X, --ice-ignore-list=list    Comma-separated list of interfaces or IP 
                                  addresses to ignore for ICE gathering; 
                                  partial strings are supported (e.g., 
                                  vmnet8,192.168.0.1,10.0.0.1 or 
                                  vmnet,192.168., default=vmnet)
	-e, --public-ip=ipaddress     Public address of the machine, to use in SDP
	-r, --rtp-port-range=min-max  Port range to use for RTP/RTCP (only available
								  if the installed libnice supports it)
	-d, --debug-level=1-7         Debug/logging level (0=disable debugging, 
                                  7=maximum debug level; default=4)
	-a, --apisecret=randomstring  API secret all requests need to pass in order 
                                  to be accepted by Janus (useful when wrapping 
                                  Janus API requests in a server, none by 
                                  default)
	-R, --enable-rabbitmq         Enable RabbitMQ support  (default=off)
	-H, --rabbitmq-host=string    Address (host:port) of the RabbitMQ server to 
                                  use (default=localhost:5672)
	-t, --rabbitmq-in-queue=string
                                  Name of the RabbitMQ queue for incoming 
                                  messages (no default)
	-f, --rabbitmq-out-queue=string
                                  Name of the RabbitMQ queue for outgoing 
                                  messages (no default)

Options passed through the command line have the precedence on those
specified in the configuration file. To start the gateway, simply run:

	<installdir>/bin/janus

This will start the gateway, and have it look at the configuration file.
By default, only an HTTP webserver is started. To enable HTTPS support,
edit the configuration file accordingly or use the command line. The
webserver will make use of the same certificates provided for DTLS. You
can also change the base path that the webserver uses: by default this
is /janus, but you can change it to anything you want and with any nesting
you want (e.g., /mypath, /my/path, or /my/really/nested/path). This is
done to allow you to more easily customize rules in any frontend you
may have (e.g., Apache in front of your services). Please notice that
the path configuration has no effect on the WebSockets usage of the API,
instead, as it is not needed there.
 
In the absence of a configuration file, the only mandatory options to
specify in the command line are the ones related to the DTLS certificate.
A default certificate is provided with this package in the certs folder,
which you can use launching the executable with these parameters:

	<installdir>/bin/janus -c /path/to/mycert.pem -k /path/to/mycert.key

At this point, the gateway will be listening on the 8088 port (or whatever
you changed that to) of your machine. To test whether it's working
correctly, you can use the demos provided with this package in the html
folder: these are exactly the same demos available online on the
[project website](http://janus.conf.meetecho.com/). Just copy the file
it contains in a webserver, and open the index.html page in either
Chrome or Firefox. A list of demo pages exploiting the different plugins
will be available.


##Help us!
Any thought, feedback or (hopefully not!) insult is welcome!

Developed by [@meetecho](https://github.com/meetecho)
