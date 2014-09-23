#!/bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

autoreconf --verbose --force --install || exit 1
