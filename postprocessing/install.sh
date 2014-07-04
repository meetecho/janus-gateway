#!/bin/sh

PKG_CONFIG=`which pkg-config`
MAKE=`which make`

echo "Installing the Janus post-processing utility..."

if [ -z "$PKG_CONFIG" ]
then
	echo "pkg-config is missing, please install it";
	exit 1;
fi
if [ -z "$MAKE" ]
then
	echo "No make?? please install it...";
	exit 1;
fi

echo
echo "Checking dependencies..."
for x in libavutil libavcodec libavformat ogg
do
	DEPENDENCY=`pkg-config --cflags --libs $x`
	if [ -z "$DEPENDENCY" ]
	then
		echo "$x is missing, please install it"
		exit 1;
	fi
done

echo
echo "Compiling..."
export INSTALLSH="install.sh"
$MAKE
if test $? -eq 0
then
	echo "Built!"
else
	echo "Error compiling, giving up..."
	exit 1
fi

echo
./janus-pp-rec -h
