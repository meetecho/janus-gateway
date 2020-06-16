# Janus testing

The files in this sub-folder are intended to be used for testing Janus.

## aiortc functional testing

We implemented some RTC Python clients based on [aiortc](https://github.com/aiortc/aiortc).
In order to use them you'll need Python >= 3.4 (Python 3.6 is recommended).

Also you'll need all of the [aiortc requirements](https://github.com/aiortc/aiortc#requirements) and the following python libraries:

```bash
pip3 install setuptools websockets aiortc
```

### echo.py

This script does a quick echotest with a specified Janus instance.
The source code has been largely inspired by the examples on the aiortc repository.
The program basically initiates a Janus session through a WebSocket connection, then creates a new echotest handle and starts an audio/video negotiation according to the echotest API.

Once everything has been succesfully set up, the client waits for 5 seconds and then checks the following assertions:
* WebSocket is connected
* ICE Connection State is completed
* DTLS state is connected
* outbound RTP packets are greater or equal than inbound RTP packets

If any of these assertion fails, the client returns a non-zero value.
No assertion has been made on the RTP packets to check if they contains valid media or not, I guess this is something that might be added in future.

The script is invoked like this:

```bash
python3 echo.py ws://localhost:8188/ --play-from media_file --verbose
```

The websocket endpoint default is `ws://localhost:8188/`.
The media_file is optional and if omitted dummy audio/video tracks will be generated.

### The test_aiortc.sh helper script

We have added a `test_aiortc.sh` helper script in order to easily launch a Janus aiortc-based test.
The scripts must be invoked like this:

```bash
./test_aiortc.sh echo.py ws://localhost:8188/
```

It will start a Janus instance in the background taking the binary files from the Janus sources directory.
Then it will wait for some seconds before invoking the Python script specified in the first parameter.
Finally it will check the exit status of the Python script and kill the Janus instance.
