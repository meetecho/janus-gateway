#!/bin/bash -eu

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

VENVPATH="$SCRIPTPATH/.venv"
python3 -m venv $VENVPATH
$VENVPATH/bin/pip install -r "$SCRIPTPATH/requirements.txt"

JANUS_SRC="$( dirname $SCRIPTPATH )"

TEST=${1-"$SCRIPTPATH/echo.py"}
URL=${2-"ws://localhost:8188/"}

echo "Starting Janus binary from $JANUS_SRC ..."
$JANUS_SRC/src/janus >/dev/null 2>&1 &
JANUS_PID=$!

echo "Waiting for some seconds before launching the test ..."
sleep 5

echo "Launching test $TEST ..."
$VENVPATH/bin/python3 $TEST $URL
RES=$?

kill $JANUS_PID 2>/dev/null

if [ $RES -eq 0 ]; then
    echo "TEST SUCCEEDED"
    exit 0
else
    echo "TEST FAILED"
    exit 1
fi
