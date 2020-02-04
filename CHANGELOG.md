# Changelog

All notable changes to this project will be documented in this file.


## [v0.8.2] - 2020-02-04

- Added Travis CI integration (thanks @fippo for kickstarting it!)
- New configuration property to add protected folders not to save recordings and pcap captures to
- Fixed rare race condition when joining and destroying a VideoRoom session
- Improved parsing of headers in RTSP messages (thanks @kefir266!)
- Fixed segfault in AudioBridge when leaving a room before PeerConnection is ready
- Fixed '500' errors being sent in response to incoming OPTIONS in the SIP plugin (thanks @ycherniavskyi!)
- Fixed helpers not being able to send SUBSCRIBE requests in SIP plugin
- Added option to fix audio skew compensation, if present, to janus-pp-rec
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.8.1] - 2020-01-13

- Added binary data support to data channels
- Fixed segfault at startup if event handlers or loggers directory couldn't be opened (thanks @kazzmir!)
- Fixed potential segfault when closing logging at shutdown
- Allowed RTCP ports to be picked randomly using 0, in Streaming plugin
- Fixed occasional memory leak when destroying mountpoints in Streaming plugin
- Fixed memory leak in SIP plugin
- Updated 'referred_by' field to contain the value of SIP referred-by header, and not just the URI (thanks @pawnnail!)
- Don't keep TextRoom plugin loaded if data channels were not compiled
- Removed SIPre plugin from the repo
- Fixed late initialization of janus.js constructor callbacks
- Changed janus.js to use sendBeacon instead of XHR when closing/refreshing page
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.8.0] - 2019-12-12

- Added changelog file to the repo and docs (thanks @oscarvadillog!)
- Added new category of plugins for modular logging (stdout and file still there, and part of the core)
- Removed option to enable rtx (now always supported, when negotiated)
- Added gzip compression helper method to the core utils
- Fixed RTSP SETUP issues when url contains query string parameters
- Added option to gzip events when using the Sample Event Handler
- Streamlined janus.js (thanks @oscarvadillog!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.7.6] - 2019-11-27

- Split SDP lines when parsing on line feed only, and trim carriage feed instead (\n instead of \r\n)
- Reduced default twcc_period (how often to send feedback when using Transport Side BWE) from 1s to 200ms
- Added option to skip (and disable) unreachable STUN/TURN server at startup (thanks @sjkummer!)
- Fixed video desynchronization when doing G.722/iSac audio
- Other generic fixes on A/V desync
- Added support for multiple concurrent calls for the same account to the SIP plugin
- Added support for blind and attended transfers to the SIP plugin
- Added way to inject custom Contact params in REGISTER to the SIP plugin
- Added way to intercept non-standard headers in SIP messages to SIP plugin (thanks @ihusejnovic!)
- Fixed missing SIP CANCEL when hanging up outgoing unanswered calls in SIP plugin
- Added support for domain names (and IPv6) to RTP forwarders in AudioBridge and VideoRoom
- Fixed broken b=TIAS SDP attribute support for Firefox in VideoRoom (thanks @MvEerd!)
- Fixed and improved VP9 SVC support in VideoRoom and Streaming plugins
- Added IPv6 support to Streaming plugin
- Fixed potential segfault in Streaming plugin (thanks @garry81!)
- Fixed occasional latching issues for RTSP in Streaming plugin
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.7.5] - 2019-10-28

- Added warning at startup if libnice version is outdated (at least 0.1.15 recommended)
- Added option to specify CWD when launching Janus as a daemon (thanks @l7s!)
- Extended the STUN test via Admin API to support binding to a specific port, and return the public one
- Fixed simulcast issue when needing to automatically drop to lower layers
- Fixed potential endless loop when binding ports in the Streaming plugin
- Made creating Streaming mountpoints more asynchronous (especially for RTSP)
- Added support for SIP SUBSCRIBE/NOTIFY to SIP plugin
- Added ability to add custom headers to SIP BYE (thanks @mmujic!)
- Added option to specify IP to bind to for media in SIP plugin (thanks @razvancrainea!)
- Fixed occasional segfault when leaving a VideoRoom
- Added audio level dBov average to talk events in VideoRoom plugin (thanks @aconchillo!)
- Added new synchronous API to mute other participants in the AudioBridge plugin (thanks @klanjabrik!)
- Fixed typo in SDP processing in Duktape/JavaScript plugin, and tied Duktape logging to the one in the Janus core (thanks @l7s!)
- Tied Lua logging to the one in the Janus core
- Added command line option to janus-pp-rec to specify the output format (thanks @rscreene!)
- Added new WebSocket and Nanomsg event handlers
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.7.4] - 2019-09-06

- Fixed duplicate values in config that could result in wrong property being used
- Fixed occasional race condition when processing SDPs (thanks @Bug-Fairy!)
- Fixed broken SDP when rejecting audio/video m-line
- Fixed Admin API not responding after sending messages to unresponsive plugins
- Fixed some issues with RTSP support in Streaming plugin
- Added option to keep recording Streaming mountpoints even when disabled
- Allow SIP plugin to negotiate SRTP separately for audio and video
- Fixed autoaccept_reinvites=FALSE not working when accepting calls in SIP plugin, and improved re-INVITEs support in general (thanks @pawnnail!)
- Added possibility to have different addresses for remote audio and video in SIP, SIPre and NoSIP plugins (thanks @pawnnail!)
- Make sure remote addresses are reset when call ends in SIP, SIPre and NoSIP plugins (thanks @pawnnail!)
- Added SIP Reason Header (RFC3326) info to "hangup" event in SIP plugin, if available (thanks @ihusejnovic!)
- Added method to list participants in a TextRoom (thanks @mtltechtemp!)
- Added method to send a room announcement in TextRoom plugin
- Fixed occasional segfault in TextRoom when using Admin API to send requests (thanks @MvEerd!)
- Added support for MQTT v5, and fixed reconnection issue (thanks @feymartynov!)
- Fixed occasional crashes when using more than one event handler at the same time
- Added configurable bitrate values for rid-based simulcast to janus.js (thanks @vivaldi-va!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.7.3] - 2019-07-10

- Added Admin API method to make synchronous requests to plugins
- Fixed broken media when removing/adding it again in renegotiations
- Fixed several issues related to datachannels
- Fixed occasional memory leak in the core when ending sessions from plugins (thanks @uxmaster!)
- Changed Janus API 'slowlink' event to use lost packets instead of NACKs, and made it configurable with a dynamic threshold
- Fixed broken SDES length in compound RTCP packets (thanks @glenn-hpcnt!)
- Fixed DTLS window size support in the core (thanks @garry81!)
- Added status messages to MQTT transport (thanks @feymartynov!)
- Changed default for sender-side bandwidth estimation in VideoRoom to TRUE
- Fixed occasional segfaults when using RTP forwarders with RTCP support
- Added VideoRoom RTP forwarder events to event handlers notifications
- Added a configurable RTP range to the Streaming plugin settings
- Fixed broken H.264 simulcast support in Streaming plugin
- Refactored janus-pp-rec to support command line options
- Fixed occasional segfault when post-processing VP8 recordings
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.7.2] - 2019-06-07

- Removed requirement for both sdpMid and sdpMLineIndex to be in trickle messages
- Set ICE remote credentials when receiving remote SDP, instead of later
- Fixed occasional segfaults when using WebSocket as a transport
- Fixed segfault in WebSocket transport when using ACL
- Added new Admin API messages to destroy a session, detach a handle and hangup a PeerConnection (same as Janus API)
- Fixed leak when RTP forwarding with RTCP feedback in the VideoRoom plugin
- Added support for third spatial layer when using VP9 SVC in VideoRoom (assuming EnabledByFlag_3SL3TL is used)
- Fixed segfault when changing rooms in AudioBridge
- Made sure the SIP stack doesn't accept new calls until the previous one has freed all resources
- Fixed occasional segfault when pushing SIP messages to event handlers
- Added option to locally cleanup handles when destroying a session in janus.js
- Fixed exception in janus.js when using datachannels
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.7.1] - 2019-05-20

- Added experimental debug mode with disabled WebRTC encryption (to use with the --disable-webrtc-encryption in Chrome unstable)
- Added Janus API ping/pong mechanism to Admin API as well
- Added Admin API methods to check address resolving capabilities and test a provided STUN server
- Added check on ICE gathering process start (fixes issue with exhausted port range)
- Added support for temporal layer in H.264 simulcast via frame marking
- Made sure a PLI is sent on all layers, when simulcast is used
- Fixed a crash when using event handlers in SIP plugin
- Fixed some race conditions on hangups in SIP plugin
- Added option to lock RTP forwarding functionality via an admin key/secret (VideoRoom and AudioBridge)
- Fixed regression in Streaming plugin RTCP support
- Added option to override payload type for RTSP mountpoints in Streaming plugin
- Fixed a few issues saving permanent mountpoints in Streaming plugin
- Separated checks for PeerConnection and getUserMedia support in janus.js (since plain HTTP hides getUserMedia now)
- Added sanity checks on createOffer/createAnswer in janus.js
- Fixed regression in simulcasting when doing SDP munging in janus.js
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.7.0] - 2019-05-10

- Added support for multiple datachannel streams in the same PeerConnection
- Forced DTLS 1.2 on older OpenSSL versions
- Added first integration of SDP support in the fuzzers
- Fixed several leaks in SDP utils
- Explicitly disabled support for encrypted RTP extensions (was causing SDP inconsistencies)
- Added count of incoming retransmissions to Admin API and Event Handlers stats
- Improved check for H.264 keyframe (thanks bwerther!)
- Modified "cap REMB" behavior to "replace REMB"
- Fixed missing notification of lurkers when first joining VideoRoom with notify_join=TRUE
- Improved support for incoming re-INVITEs in SIP plugin
- Fixed check in WebSocket transport that could lead to crashes
- Fixed occasional segfaults when postprocessing H.264 recordings
- Added new callback to janus.js to intercept the SDP before it is sent, e.g., for munging purposes (thx @carlcc!)
- Fixed direction property error in janus.js on Safari (thx @alienpavlov!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.6.3] - 2019-03-20

- Removed folder with self-signed certificate (unneeded and confusing)
- Added many fixes and improvements to the RTCP code
- Fixed typos that caused issues when sending retransmissions using RFC4588
- Fixed typo when sending empty RR coupled with REMB
- Made sure the CNAME is always the same for all m-lines in an SDP
- Added support for mid RTP extension
- Improved support for rid-based simulcasting
- Fixed publish errors in MQTT transport and event handler
- Fixed issue when switching Streaming mountpoints powered by helper threads
- Added info on whether VideoRoom publisher is simulcasting to join events
- Added option for new VideoRoom subscribers to specify simulcast substream/layer to subscribe to in join request (before it was configure-only)
- Added type definitions for janus.js (thanks Elias!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.6.2] - 2019-03-04

- Added RTP/RTCP fuzzing targets and tools
- Fixed occasional crash when pushing the local SDP to event handlers, when enabled
- Fixed NACK issue when receiving an out of order keyframe
- Added option to configure the TWCC feedback period
- Added option to include opaqueID in Janus API events
- Added option to negotiate Opus inband FEC in the VideoRoom
- Added option to specify temporary extension when recording AudioBridge rooms, and event handler notification for when recording is over
- Fixed occasional playout issue after recording, using Record&Play demo
- Fixed typo in janus.js that affected replacing audio tracks in renegotiations
- Changed default maxev (number of events in long poll results) to 10 in janus.js
- Updated path of getDisplayMedia in janus.js to reflect current spec (thanks cb22!)
- Fixed ambiguous check in Janus.isWebrtcSupported in janus.js
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.6.1] - 2019-02-11

- Added several fixes to RTP/RTCP parsing after fuzzing tests
- Added fixes to keyframe detection after fuzzing tests
- Fixed some demos not working after update to Chrome 72
- Fixed occasional crashes when saving .jfcg files (e.g., saving permanent Streaming mountpoints)
- Added new Admin API command to temporarily stop/resume accepting sessions (e.g., for draining servers)
- Fixed recordings sometimes not closed/destroyed/renamed when hanging up SIP sessions
- Added option to SIP/SIPre/NoSIP plugin to override c= IP in SDP
- Fixed missing RTSP support in Streaming plugin if TURN REST API was disabled in configure
- Fixed Streaming plugin not returning complete information on secret-less mountpoints (thanks @Musashi178!)
- Fixed missing .jfcg support in Duktape plugin (thanks @fbertone!)
- Updated janus.js to use transceivers for Chrome >=72
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.6.0] - 2019-01-07

- Changed default configuration format to libconfig (INI still supported but deprecated)
- Fixed several RTCP parsing issues that could lead to crashes (thanks to Fippo for bringing fuzzying to our attention!)
- Added support to clang compiler (needed for fuzzying)
- Fixed rtx packets ending up in retransmission buffer (thanks glenn-hpcnt!)
- Fixed occasional crash when cleaning NACK buffer (thanks tmatth!)
- Fixed loop termination warning when handling event handlers (thanks tmatth!)
- Fixed occasional invalid rtx payload type
- Fixed local SDP notification to event handlers
- Fixed typo in link quality calculation
- Fixed occasional crash in SIP plugin
- Added option to provide custom headers in SIP 200 OK as well (thanks ihusejnovic!)
- Fixed typo in Range header when sending RTSP PLAY in Streaming plugin (thanks Phil1972!)
- Made MQTT and RabbitMQ configuration files more consistent with other ones (thanks manifest!)
- Added support for Last Will and Testament to MQTT event handler (thanks 0nkery!)
- Fixed broken video when post-processing recordings with high-profile H.264
- Fixed missing success callback in sendDtmf JS method (thanks nevcos!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.5.0] - 2018-11-20

- Refactored core to have a persistent GMainLoop/thread per handle
- Added option to share static number of GMainLoop/thread instances for multiple handles
- Better management of incoming RTCP packets before passing them to plugins
- Updated TURN REST API to support both "key" and "api" as parameters
- Added support for dumping directly to .pcap, rather than text first via text2pcap
- Fixed occasional missing notifications of temporal layer changes, when doing simulcast
- Fixed occasional crash in TextRoom plugin
- Fixed crashes in Duktape plugin after some iterations
- Added .mjr metadata to media files when postprocessing the recordings, if supported by the container
- Fixed datachannels not working in Streaming demo, when configured
- Fixed dangling "Publish" button in VideoRoom demo
- Better management of timeout notifications when using websockets in janus.js (thanks @nevcos!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.4.5] - 2018-10-16

- Switched to GMutex for locks by default (changeable in configure)
- Fixed missing sdpMid in some trickle candidates, which could break full-trickle support
- Fixed missing TWCC info when handling rtx duplicates (thanks garry81!)
- Fixed H.264 keyframe detection and broken H.264 simulcast code
- Fixed bug in skew compensation code
- Fixed occasional crashes when closing PeerConnections in AudioBridge
- Fixed broken Record-Route usage in SIP plugin (thanks Dan!)
- Removed outdated autoack property from SIP plugin
- Switched from SET_PARAMETER to OPTIONS as an RTSP keep-alive (thanks cnzjy!)
- Fixed missing endianness for RTP packets in postprocessor, which caused problems on MacOS
- Fixed crash in postprocessor when handling high(er) H.264 profiles (e.g., Safari 12)
- Fixed multiple "First keyframe" log lines when postprocessing video
- Added support for parsing a few RTP extensions in the postprocessor
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.4.4] - 2018-09-28

- Added several important fixes to NACK and retransmission code
- Fixed connectivity establishment when only available candidates are prflx
- Fixed some leaks in TWCC code
- Fixed missing information when reporting TWCC reports (thanks Kangsik!)
- Made the timeout for trickle candidates configurable
- Added support for mDNS candidates (see draft-ietf-rtcweb-mdns-ice-candidates)
- Added option to configure the DTLS retransmission timer (BoringSSL only)
- Optimized DTLS writes by removing a copy on each send (thanks Joachim!)
- Added option to override codecs to negotiate in EchoTest
- Added H.264 simulcasting support to plugins that did VP8 simulcast already
- Added VP9/SVC support to the Streaming plugin
- Improved the way simulcast streams can be recorded and forwarded
- Added partial RTCP support to RTP forwarders (thanks Adam!)
- Fixed occasional segfaults in the VideoRoom when forcing private IDs (thanks tugtugtug!)
- Added option to use helper threads for Streaming plugin mountpoints
- Fixed a couple of errors in the RTSP support of the Streaming plugin (thanks nu774!)
- Several fixes in the NoSIP plugin (thanks Dmitry!)
- Fixed broken SIP MESSAGE support in SIP plugin
- Fixed occasional segfaults in SIP and SIPre plugins (thanks mharcar!)
- Fixed broken recording support in the VideoCall plugin (thanks codebot!)
- Fixed potential deadlock in Lua and Duktape plugins (thanks Gabriel!)
- Fixed memory leaks in VideoRoom, AudioBridge and TextRoom
- Added new MQTT event handler (thanks Olle!)
- Made HTTP REST API optionally more consistent with other transports
- Added new flag to postprocessor for just printing the JSON header
- Fixed occasional segfaults when processing recordings
- Added getDisplayMedia() support to janus.js
- Added better support to constraints when screensharing (thanks Sol!)
- Added better iOS devices support to janus.js and the demos
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.4.3] - 2018-08-27

- Fixed occasional crash when closing PeerConnections
- Fixed way of negotiating datachannels in Firefox Nightly
- Fixed broken check when enabling TURN REST API
- Fixed occasional crash when post-processing H.264 recordings (thanks Thomas!)
- Fixed occasional issue when creating PID file
- Fixed broken SDES generation (thanks Garry!)
- Added new Duktape plugin to write plugin logic in JavaScript
- Fixed occasional crash in VideoCall plugin when declining calls
- Added basic RTCP support to the Streaming plugin (thanks Adam!)
- Added basic RTCP support to RTP forwarders in the VideoRoom plugin
- Added new Nanomsg transport
- Changed the way libwebsockets logging is configured
- Updated janus.js to use promises for WebRTC APIs (thanks Philipp!)
- Some more bug fixes and improvements


## [v0.4.2] - 2018-06-18

- Fixed ICE loop not terminating at times, and spiking the CPU
- Fixed compilation against older OpenSSL versions (thanks Joachim!)
- Added option to statically enable locking debug via command line or configuration file
- Fixed occasional crash in VideoRoom when destroying rooms
- Fixed VideoRoom not closing subscribers PeerConnections when publisher goes away, if so configured
- Fixed SRTP errors when resuming VideoRoom subscribers that were paused for a long time
- Added new option to really force a cap on the bitrate in VideoRoom rooms
- Fixed recording not being started for VideoRoom publishers media added in a renegotiation
- Fixed occasional crash in AudioBridge when closing PeerConnections under load
- Added Opus FEC support to AudioBridge (thanks Eric!)
- Fixed pipe socket initialization in Streaming plugin (thanks Adam!)
- Added systemd support to Unix Sockets transport plugin (thanks Adam!)
- WebSocket connection is no longer torn down in case of a Janus session timeout
- Added options to configure keep-alive and long-poll timers in janus.js
- Some more bug fixes and improvements


## [v0.4.1] - 2018-05-29

- Single thread per PeerConnection, instead of two
- Fixed issue with API secret, where sessions would be created anyway
- Cleanup of ICE related code (thx Joachim!)
- Removed ad-hoc thread for SCTP code
- Fixed deadlock in VideoRoom plugin
- Fixed segfault in SIPre plugin
- Fixed leaks when using event handlers (thx zgjzzhw!)
- Fixed some missing events when closing PeerConnections
- Fixed broken dependencies mechanism in janus.js (thx Philippe!)
- Some more bug fixes and improvements


## [v0.4.0-broken] - 2018-05-22

- Changed memory management to use reference counters
- New plugin to write application logic in Lua
- Added mechanism to reclaim sessions after a reconnection (thx Geige!)
- Fixed broken renegotiations when upgrading from audio-only to audio-video
- Fixed typo in evaluation of RTT from RTCP packets
- Fixed crash when SRTP profile is missing in DTLS handshake
- Improved and streamlined a few events (event handlers), e.g., selected-pair
- Added new "external" events (event handlers), for events pushed via Admin API
- Fixed deadlock when joining a VideoRoom with notify_join=true
- Fixed some info not saved permanently in some plugins when editing
- Added media latching to RTSP streams setup in the Streaming plugin
- Fixed an issue with simulcast support in the Streaming plugin
- Fixed occasional unexpected WebSockets disconnects when using the Streaming plugin
- Fixed Streaming plugin not returning bound ports when creating mountpoints with random ones (port=0)
- Improved and streamlined documentation for all plugins
- Added option to limit ciphers/protocols in HTTP and WebSockets (thx Alexander!)
- Added transceivers support to janus.js for proper renegotiations in Firefox
- More bug fixing and general cleanup (thx to mtdxc, fancycode and others!)
- Added a way to support other screensharing extensions in janus.js in a programmatic way (thx Sol!)


## [v0.3.1] - 2018-04-04

- Changed threading model for processing requests in the core
- Added support for SRTP AES-GCM to core and SIP/SIPre/NoSIP plugins
- Changed set of ciphers negotiated in DTLS, disabling weaker ones (thanks Chad!)
- Added option to specify passphrase when dealing with certificates/keys
- Added ability for Admin API requests to tweak Event Handlers
- Integrated link quality stats info (thanks Piter!)
- Added support for storage-less authentication via Signed Tokens (thanks Sol!)
- Added option to force TCP for SIP messages in the SIP plugin
- Added option to not fail RTSP mountpoint creation right away if backend is not up
- Added SSL/TLS support to the MQTT transport (thanks Andrei!)
- Added new request to edit some Streaming mountpoint properties (thanks Rob!)
- Fixed management of DTMF in janus.js
- Updated management of constraints in janus.js (thanks Igor!)
- Bug fixing and general improvements


## [v0.3.0] - 2018-02-23

- Implemented renegotiations and ICE restarts
- Bundle and rtcp-mux now are always forced
- Added support to Transport Wide CC sender-side BWE (thanks Sergio!)
- Added SRTP support to Streaming mountpoints
- Implemented a skew compensation algorithm in the Streaming plugin
- Added SRTP support to RTP forwarders
- Implemented support for RFC4588 (rtx/90000 retransmissions)
- Janus can now do full-trickle too
- SIP plugin now supports 407 (proxy authentication)
- Fixed post-processing of G.711 recordings
- Added versioning info to janus-pp-rec
- Several fixes and cleanup


## [v0.2.6] - 2017-12-19

- New SIP plugin based on libre, SIPre (janus.plugin.sipre), and related demo
- New NoSIP plugin, that can be used with legacy applications (like SIP) without doing any signalling itself
- VideoRoom can now support multiple codecs at the same time, instead of being forced to choose just one per media type
- Plugins now record streams specifying the actual codec in use, instead of making assumptions (e.g., like Record&Play did with Opus and VP8)
- Streaming plugin now allows you to temporarily pause audio and/or video delivery via "configure" requests
- Removed RTCP BYE as a trigger to shutdown a PeerConnection (fixes Firefox 52 issues)
- Added RTCP support for simulcast SSRCs
- Fixed parsing of Firefox simulcast offer when order of attributes was different than expected
- Improved RTP headers rewriting in case of SSRC changes (e.g., context switches)
- Improved performance of the ICE send threads/loops and computation of transfer rates, by getting rid of all list traversals
- Added support for MSG_EOR in SCTP datachannels
- Added "exchange" support to RabbitMQ transport
- Added new info to Event Handlers (server info in "started" event, and server name in "emitter")
- Added RabbitMQ Event Handler
- You can now add additional constraints for a PeerConnection when invoking createOffer and createAnswer in janus.js
- Fixed occasional problems when postprocessing .mjr recordings, especially long ones, and Opus recordings
- Several bug and typo fixes, in both core and janus.js


## [v0.2.5] - 2017-10-23

- VP8 simulcasting supported in a few plugins (you may have experimented with it on the online demos already);
- VP9 SVC is also available (VideoRoom only);
- VideoRoom and Streaming plugins allow you to subscribe to a subset of the feed's media (e.g., only get audio even though feed is audio/video);
- automatic fallback in the VideoRoom to subset of the media in case of unsupported codecs (e.g., Safari joining VP8 room falls back to audio only);
- added option to override rtpmap and fmtp SDP attributes for RTSP mountpoints in the Streaming plugin;
- added support for other codecs besides opus and VP8 in Record&Play plugin;
- added option to have a static RTP forwarder for an AudioBridge room in the configuration file;
- added possibility to specify an RTP range to use in the SIP plugin;
- implemented text2pcap support to dump incoming and outgoing unencrypted RTP/RTCP traffic for debugging purposes;
- added support to G.722 in postprocessor;
- made sure that each m-line now has its own a=end-of-candidates attribute;
- fixed crash in websockets transport plugin when SSL was enabled on both APIs;
- added support to ping/pong mechanism in websockets transport plugin;
- switched from addstream to addtrack in janus.js;
- decoupled the dependencies in janus.js to allow for dynamic override of some features;
- added support to build JavaScript modules out of janus.js.


## [v0.2.4] - 2017-07-28

- binding to some or all interfaces/families has been fixed in the HTTP transport;
- the Access-Control-Allow-Origin return value is now configurable in the HTTP transport;
- fixed occasional slow WebSocket request management when DNS was involved;
- there's a new timer before we return an ICE failed (as due to trickling there may be a success shortly after a temporary failure);
- the frequency of media stats notifications (event 32) in event handlers has been made configurable (default is still 1s);
- event handlers now notify about each local and remote candidate as well;
- the admin.html demo page now prompts you with the password (although you can still hardcode it in the page, as before);
- several changes in the SIP plugin: support for offerless INVITEs, early media (183+SDP), outbound proxies, and fixes to some POLLERR messages;
- added support for LibreSSL as an alternative to OpenSSL and BoringSSL;
- added a=end-of-candidates to all m-lines, since we half-trickle (fixes Edge support);
- fixed a race condition in the TextRoom plugin;
- fixed the way janus.js used getStats, in particular for Firefox;
- fixed device selection demo;
- several smaller fixes derived from a static analysis of the code via Coverity.


## [v0.2.3] - 2017-06-12

- A few janus.js fixes (among which a small fix to get it working with Safari, and the possibility to add mic audio when screensharing);
- Several RTCP related enhancements in the Streaming plugin;
- Support for on-hold in SIP plugin;
- Fixed MQTT transport when credentials are needed;
- Improved "kick" in VideoRoom (needs forcing of private_id when creating room);
- Possibility to create Streaming mountpoints with random ports, instead of specifying them via API;
- Optional "talking" events in AudioBridge and VideoRoom;
- Possibility to force BUNDLE/rtcp-mux per handle via API (no need to wait for complete negotiation);
- Several bug fixes, a couple of them to nasty race conditions that finally got solved.


## [v0.2.2] - 2017-03-08

- ACL/Kick support in VideoRoom/AudioBridge/TextRoom
- Man pages for Janus and post-processor
- Opaque identifiers for Event handlers + Transport related events
- Ability to specify SSRC + payload type when using RTP forwarders
- Ability to relay datachannels in Streaming plugin
- Ability to send some TextRoom commands (e.g., create/list/etc.) via Janus API instead of only datachannels
- Configurable session timeouts
- Configurable "no-media" timeouts
- Optional temporary extension for recordings until they're done
- cleanup and bug fixing


## [v0.2.1] - 2016-12-13

- Missing info


## [v0.2.0] - 2016-10-10

- Missing info


## [v0.1.2] - 2016-09-05

- Missing info


## [v0.1.1] - 2016-06-15

- Missing info


## [v0.1.0] - 2016-05-27

- Missing info


## [v0.0.9] - 2015-11-11

- First release
