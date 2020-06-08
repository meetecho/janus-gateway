#!/bin/bash -eu

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
JANUS_SRC="$( dirname $SCRIPTPATH )"

TEST=${1-"$SCRIPTPATH/echo.py"}
URL=${2-"ws://localhost:8188/"}

echo "Starting Janus binary from $JANUS_SRC ..."
$JANUS_SRC/janus >/dev/null 2>&1 &
JANUS_PID=$!

echo "Waiting for some seconds before launching the test ..."
sleep 5

echo "Launching test $TEST ..."
python3 $TEST $URL

if [ $? -eq 0 ]; then
    echo "TEST SUCCEEDED"
    kill -9 $JANUS_PID 2>/dev/null
    exit 0
else
    echo "TEST FAILED"
    kill -9 $JANUS_PID 2>/dev/null
    exit 1
fi
