#!/bin/bash -eu

TEST=${1-"echo.py"}
URL=${2-"ws://localhost:8188/"}

echo "Starting Janus ..."
../janus >/dev/null 2>&1 &
JANUS_PID=$!

sleep 3

echo "Launching test $TEST ..."
python3 $TEST $URL

if [ $? -eq 0 ]; then
    echo "TEST SUCCEDED"
    kill -9 $JANUS_PID
    exit 0
else
    echo "TEST FAILED"
    kill -9 $JANUS_PID
    exit 1
fi
