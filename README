Janus WebRTC Gateway
====================

Janus is an open source, general purpose, WebRTC gateway. This version
of the gateway can only be installed on Linux systems: next versions
will take into account cross compilation on different environments.

For some online demos and documentations, make sure you pay the
[project website](http://janus.conf.meetecho.com/) a visit!

##Dependencies
To install it, you'll need to satisfy the following dependencies:

* [libmicrohttpd](http://www.gnu.org/software/libmicrohttpd/)
* [libini-config](https://fedorahosted.org/sssd/) (INI configurations)
* [Jansson](http://www.digip.org/jansson/)
* [libnice](http://nice.freedesktop.org/wiki/)
* [OpenSSL](http://www.openssl.org/) (at least v1.0.1e)
* [libsrtp](http://srtp.sourceforge.net/srtp.html)
* [Sofia-SIP](http://sofia-sip.sourceforge.net/)

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
		libogg-dev libini-config-dev libcollection-dev pkg-config gengetopt

* *Note:* apparently libopus is not available on Ubuntu: you'll have to
install it manually.

Should you be interested in building the gateway documentation as well,
you'll need an additional component installed too:

* [Doxygen](http://www.doxygen.org)
* [Graphviz](http://www.graphviz.org/)

On Fedora:

	yum install doxygen graphviz

On Ubuntu/Debian:

	aptitude install doxygen graphviz


##Compile
Once you have installed all the dependencies, just use:

	sh install.sh

to start the whole compilation process. The script will try to check
whether you have all the dependencies installed, and then issue a 'make'
for you to start compiling. If Doxygen and graphviz are available, it
will also build the documentation for you as well.

If you prefer doing this manually, a simple

	make

will start compiling the gateway. To build the documentation as well:

	make docs

will create the documentation in the docs/html subfolder.


##Configure and start
To start the gateway, you can use the janus executable. There are several
things you can configure, either in a configuration file:

	./conf/janus.cfg

or on the command line:

	./janus --help
	
	janus 0.0.1

	Usage: janus [OPTIONS]...

	-h, --help                    Print help and exit
	-V, --version                 Print version and exit
	-i, --interface=ipaddress     Interface to use (will be the public IP)
	-p, --port=portnumber         Web server HTTP port (default=8088)
	-s, --secure-port=portnumber  Web server HTTPS port (default=no HTTPS)
	-n, --no-http                 Disable insecure HTTP web server  (default=off)
	-b, --base-path=basepath      Base path to bind to in the web server 
								  (default=/janus) 
	-P, --plugins-folder=path     Plugins folder (default=./plugins)
	-C, --config=path             Configuration file to use
	-F, --configs-folder=path     Configuration files folder (default=./conf)
	-c, --cert-pem=filename       HTTPS/DTLS certificate
	-k, --cert-key=filename       HTTPS/DTLS certificate key
	-S, --stun-server=filename    STUN server(:port) to use, if needed (e.g., 
								  gateway behind NAT, default=none)

Options passed through the command line have the precedence on those
specified in the configuration file. To start the gateway, simply run:

	./janus

This will start the gateway, and have it look at the configuration file.
By default, only an HTTP webserver is started. To enable HTTPS support,
edit the configuration file accordingly or use the command line. The
webserver will make use of the same certificates provided for DTLS. You
can also change the base path that the webserver uses: by default this
is /janus, but you can change it to anything you want and with any nesting
you want (e.g., /mypath, /my/path, or /my/really/nested/path). This is
done to allow you to more easily customize rules in any frontend you
may have (e.g., Apache in front of your services).
 
In the absence of a configuration file, the only mandatory options to
specify in the command line are the ones related to the DTLS certificate.
A default certificate is provided with this package in the certs folder,
which you can use launching the executable with these parameters:

	./janus -c certs/mycert.pem -k certs/mycert.key

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
