import argparse
import asyncio
import logging
import random
import string
import sys

import websockets as ws
import json


from aiortc import RTCPeerConnection, RTCSessionDescription
from aiortc.mediastreams import AudioStreamTrack, VideoStreamTrack
from aiortc.contrib.media import MediaPlayer


logger = logging.getLogger('echo')


class WebSocketClient():

    def __init__(self, url='ws://localhost:8188/'):
        self._url = url
        self.connection = None
        self._transactions = {}

    async def connect(self):
        self.connection = await ws.connect(self._url,
                                           subprotocols=['janus-protocol'],
                                           ping_interval=10,
                                           ping_timeout=10,
                                           compression=None)
        if self.connection.open:
            asyncio.ensure_future(self.receiveMessage())
            logger.info('WebSocket connected')
            return self

    def transaction_id(self):
        return ''.join(random.choice(string.ascii_letters) for x in range(12))

    async def send(self, message):
        tx_id = self.transaction_id()
        message.update({'transaction': tx_id})
        tx = asyncio.get_event_loop().create_future()
        tx_in = {'tx': tx, 'request': message['janus']}
        self._transactions[tx_id] = tx_in
        try:
            await asyncio.gather(self.connection.send(json.dumps(message)), tx)
        except Exception as e:
            tx.set_result(e)
        return tx.result()

    async def receiveMessage(self):
        try:
            async for message in self.connection:
                data = json.loads(message)
                tx_id = data.get('transaction')
                response = data['janus']

                # Handle ACK
                if tx_id and response == 'ack':
                    logger.debug(f'Received ACK for transaction {tx_id}')
                    if tx_id in self._transactions:
                        tx_in = self._transactions[tx_id]
                        if tx_in['request'] == 'keepalive':
                            tx = tx_in['tx']
                            tx.set_result(data)
                            del self._transactions[tx_id]
                            logger.debug(f'Closed transaction {tx_id}'
                                         f' with {response}')
                    continue

                # Handle Success / Event / Error
                if response not in {'success', 'error'}:
                    logger.info(f'Janus Event --> {response}')
                if tx_id and tx_id in self._transactions:
                    tx_in = self._transactions[tx_id]
                    tx = tx_in['tx']
                    tx.set_result(data)
                    del self._transactions[tx_id]
                    logger.debug(f'Closed transaction {tx_id}'
                                 f' with {response}')
        except Exception:
            logger.error('WebSocket failure')
        logger.info('Connection closed')

    async def close(self):
        if self.connection:
            await self.connection.close()
            self.connection = None
        self._transactions = {}


class JanusPlugin:
    def __init__(self, session, handle_id):
        self._session = session
        self._handle_id = handle_id

    async def sendMessage(self, message):
        logger.info('Sending message to the plugin')
        message.update({'janus': 'message', 'handle_id': self._handle_id})
        response = await self._session.send(message)
        return response


class JanusSession:
    def __init__(self, url='ws://localhost:8188/'):
        self._websocket = None
        self._url = url
        self._handles = {}
        self._session_id = None
        self._ka_interval = 15
        self._ka_task = None

    async def send(self, message):
        message.update({'session_id': self._session_id})
        response = await self._websocket.send(message)
        return response

    async def create(self):
        logger.info('Creating session')
        self._websocket = await WebSocketClient(self._url).connect()
        message = {'janus': 'create'}
        response = await self.send(message)
        assert response['janus'] == 'success'
        session_id = response['data']['id']
        self._session_id = session_id
        self._ka_task = asyncio.ensure_future(self._keepalive())
        logger.info('Session created')

    async def attach(self, plugin):
        logger.info('Attaching handle')
        message = {'janus': 'attach', 'plugin': plugin}
        response = await self.send(message)
        assert response['janus'] == 'success'
        handle_id = response['data']['id']
        handle = JanusPlugin(self, handle_id)
        self._handles[handle_id] = handle
        logger.info('Handle attached')
        return handle

    async def destroy(self):
        logger.info('Destroying session')
        if self._session_id:
            message = {'janus': 'destroy'}
            await self.send(message)
            self._session_id = None
        if self._ka_task:
            self._ka_task.cancel()
            try:
                await self._ka_task
            except asyncio.CancelledError:
                pass
            self._ka_task = None
        self._handles = {}
        logger.info('Session destroyed')

        logger.info('Closing WebSocket')
        if self._websocket:
            await self._websocket.close()
            self._websocket = None

    async def _keepalive(self):
        while True:
            logger.info('Sending keepalive')
            message = {'janus': 'keepalive'}
            await self.send(message)
            logger.info('Keepalive OK')
            await asyncio.sleep(self._ka_interval)


async def run(pc, player, session, bitrate=512000, record=False):
    @pc.on('track')
    def on_track(track):
        logger.info(f'Track {track.kind} received')

        @track.on('ended')
        def on_ended():
            print(f'Track {track.kind} ended')

    @pc.on('iceconnectionstatechange')
    def on_ice_state_change():
        # logger.info(f'ICE state changed to {pc.iceConnectionState}')
        pass

    # create session
    await session.create()

    # configure media
    media = {'audio': True, 'video': True}
    if player and player.audio:
        pc.addTrack(player.audio)
    else:
        pc.addTrack(AudioStreamTrack())
    if player and player.video:
        pc.addTrack(player.video)
    else:
        pc.addTrack(VideoStreamTrack())

    # attach to echotest plugin
    plugin = await session.attach('janus.plugin.echotest')

    # create data-channel
    channel = pc.createDataChannel('JanusDataChannel')
    logger.info(f'DataChannel ({channel.label}) created')
    dc_probe_message = 'echo-ping'
    dc_open = False
    dc_probe_received = False

    @channel.on('open')
    def on_open():
        nonlocal dc_open
        dc_open = True
        logger.info(f'DataChannel ({channel.label}) open')
        logger.info(
            f'DataChannel ({channel.label}) sending: {dc_probe_message}')
        channel.send(dc_probe_message)

    @channel.on('close')
    def on_close():
        nonlocal dc_open
        dc_open = False
        logger.info(f'DataChannel ({channel.label}) closed')

    @channel.on('message')
    def on_message(message):
        logger.info(f'DataChannel ({channel.label}) received: {message}')
        if dc_probe_message in message:
            nonlocal dc_probe_received
            dc_probe_received = True

    # send offer
    await pc.setLocalDescription(await pc.createOffer())
    request = {'record': record, 'bitrate': bitrate}
    request.update(media)
    response = await plugin.sendMessage(
        {
            'body': request,
            'jsep': {
                'sdp': pc.localDescription.sdp,
                'trickle': False,
                'type': pc.localDescription.type,
            },
        }
    )
    assert response['plugindata']['data']['result'] == 'ok'

    # apply answer
    answer = RTCSessionDescription(
        sdp=response['jsep']['sdp'],
        type=response['jsep']['type']
    )
    await pc.setRemoteDescription(answer)

    logger.info('Running for a while...')
    await asyncio.sleep(5)

    # Check WebSocket status
    assert session._websocket.connection.open

    # Get RTC stats and check the status
    rtcstats = await pc.getStats()
    rtp = {'audio': {'in': 0, 'out': 0}, 'video': {'in': 0, 'out': 0}}
    dtls_state = None
    for stat in rtcstats.values():
        if stat.type == 'inbound-rtp':
            rtp[stat.kind]['in'] = stat.packetsReceived
        elif stat.type == 'outbound-rtp':
            rtp[stat.kind]['out'] = stat.packetsSent
        elif stat.type == 'transport':
            dtls_state = stat.dtlsState
    # ICE succeded
    assert pc.iceConnectionState == 'completed'
    # DTLS succeded
    assert dtls_state == 'connected'
    # Janus echoed the sent packets
    assert rtp['audio']['out'] >= rtp['audio']['in'] > 0
    assert rtp['video']['out'] >= rtp['video']['in'] > 0
    # DataChannels worked
    assert dc_open
    assert dc_probe_received

    logger.info('Ending the test now')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Janus')
    parser.add_argument('url',
                        help='Janus root URL, e.g. ws://localhost:8188/')
    parser.add_argument('--play-from',
                        help='Read the media from a file and sent it.'),
    parser.add_argument('--verbose', '-v', action='count')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # create signaling and peer connection
    session = JanusSession(args.url)
    pc = RTCPeerConnection()

    # create media source
    if args.play_from:
        player = MediaPlayer(args.play_from)
    else:
        player = None

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            run(pc=pc, player=player, session=session)
        )
        logger.info('Test Passed')
        sys.exit(0)
    except Exception:
        logger.exception('Test Failed')
        sys.exit(1)
    finally:
        loop.run_until_complete(pc.close())
        loop.run_until_complete(session.destroy())
