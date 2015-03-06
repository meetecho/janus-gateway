#!/bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

mkdir -p m4

autoreconf --verbose --force --install || exit 1
