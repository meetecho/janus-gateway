#!/bin/sh

# Note: if you're on Ubuntu, good chances are your Gstreamer distribution
# will not have a plugin for Opus installed out of the box. You can try
# using the one available on Debian, e.g., installing the package you
# can find here:
#    http://packages.debian.org/sid/i386/gstreamer0.10-plugins-bad/download
# For instance:
#    wget http://ftp.it.debian.org/debian/pool/main/g/gst-plugins-bad0.10/gstreamer0.10-plugins-bad_0.10.23-7.1_i386.deb
#    ar xv gstreamer0.10-plugins-bad_0.10.23-7.1_i386.deb
#    tar xfv data.tar.xv
#    cp usr/lib/i386-linux-gnu/gstreamer-0.10/libgstopus.so /usr/lib/i386-linux-gnu/gstreamer-0.10/

gst-launch \
	audiotestsrc ! \
		audioresample ! audio/x-raw-int,channels=1,rate=16000 ! \
		opusenc bitrate=20000 ! \
			rtpopuspay ! udpsink host=127.0.0.1 port=5002 \
	videotestsrc ! \
		video/x-raw-rgb,width=320,height=240,framerate=15/1 ! \
		videoscale ! videorate ! ffmpegcolorspace ! timeoverlay ! \
		vp8enc bitrate=256000 speed=2 max-latency=1 error-resilient=true ! \
			rtpvp8pay ! udpsink host=127.0.0.1 port=5004
