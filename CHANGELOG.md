# Changelog

All notable changes to this project will be documented in this file.


## [v1.3.3] - 2025-10-21

- Refactored keyframe buffering in Streaming plugin to store following deltas too (thanks [Byborg](https://www.byborgenterprises.com/)!) [[PR-3564](https://github.com/meetecho/janus-gateway/pull/3564)]
- Added optional events for RTSP disconnections/reconnections in the Streaming plugin [[PR-3578](https://github.com/meetecho/janus-gateway/pull/3578)]
- Fixed rare crash when reconnecting to RTSP servers in the Streaming plugin [[PR-3580](https://github.com/meetecho/janus-gateway/pull/3580)]
- Fixed small leak when recording Streaming mountpoints
- Fixed memory leak when stopping non-existing forwarders in the VideoRoom plugin
- Fixed rare crash in AudioBridge when notifying participants [[PR-3589](https://github.com/meetecho/janus-gateway/pull/3589)]
- Fixed payload type when RTP-forwarding AudioBridge rooms using G.711
- Added option for managing ringing manually in the SIP plugin (thanks @adnanel!) [[PR-3556](https://github.com/meetecho/janus-gateway/pull/3556)]
- Save custom headers and send them on SIP hangup event (thanks @kenangenjac!) [[PR-3558](https://github.com/meetecho/janus-gateway/pull/3558)]
- Fix small memory leak in SIP plugin (thanks @oleksandr-mihal-zultys!) [[PR-3565](3565)]
- Added support for Linux cooked capture v2 to pcap2mjr
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.3.2] - 2025-07-10

- Added workaround to potential libnice issue
- Deprecated nice_debug option (libnice debugging can be enabled via env variables) [[PR-3546](https://github.com/meetecho/janus-gateway/pull/3546)]
- Fixed broken session count in case of timeouts [[Issue-3526](https://github.com/meetecho/janus-gateway/issues/3526)]
- Fixed broken session count in case of API disconnections [[Issue-3532](https://github.com/meetecho/janus-gateway/issues/3532)]
- Added experimental support for the video-layers-allocation extension [PR-3504](https://github.com/meetecho/janus-gateway/pull/3504)]
- Added optional signal handler for log rotation [[PR-3550](https://github.com/meetecho/janus-gateway/pull/3550)]
- Fixed memory leaks when using dummy publishers [[PR-3541](https://github.com/meetecho/janus-gateway/pull/3541)]
- New options to advertise VideoRoom dummy publishers as e2ee [[PR-3553](https://github.com/meetecho/janus-gateway/pull/3553)]
- Fixed rare crash when using remote publishers in VideoRoom [[PR-3557](https://github.com/meetecho/janus-gateway/pull/3557)]
- Added request to stop all AudioBridge announcements in a room (thanks @keremcadirci!) [[PR-3403](https://github.com/meetecho/janus-gateway/pull/3403)]
- Allow plain RTP participants in AudioBridge to use generate_offer too [[PR-3534](https://github.com/meetecho/janus-gateway/pull/3534)]
- Fixed breaking condition in AudioBridge
- Fixed broken canvas demo [[Issue-3527](https://github.com/meetecho/janus-gateway/issues/3527)]
- Fixed broken multiopus demo
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.3.1] - 2025-03-05

- Make ip-utils aware of 0.0.0.0 and :: [[Issue-3470](https://github.com/meetecho/janus-gateway/issues/3470)]
- Optimize NACKs handling [[PR-3491](https://github.com/meetecho/janus-gateway/pull/3491)]
- Skip medium lookup when relaying RTCP by plugins to fix rare deadlock [[PR-3515](https://github.com/meetecho/janus-gateway/pull/3515)]
- Fixed FEC and DTX negotiated in VideoRoom also when not enabled in the room settings
- Fixed memory leak in VideoRoom (thanks @m08pvv!) [[PR-3493](https://github.com/meetecho/janus-gateway/pull/3493)]
- Fixed broken recordings when using remote publishers in the VideoRoom [[PR-3509](https://github.com/meetecho/janus-gateway/pull/3509)]
- Check if IPv6 is disabled when loading the Streaming plugin [[PR-3519](https://github.com/meetecho/janus-gateway/pull/3519)]
- Fixed SSRC not being set to a default value in AudioBridge forwarders when not explicitly set in the request
- Add support for "progress" request on SIP Plugin (thanks @adnan-mujagic!) [[PR-3466](https://github.com/meetecho/janus-gateway/pull/3466)]
- New programmatic API to ask for keyframes in SIP and NoSIP plugins [[PR-3517](https://github.com/meetecho/janus-gateway/pull/3517)]
- Fixed missing libcurl linking in TextRoom plugin
- Added support for private recordings in Record&Play [[PR-3518](https://github.com/meetecho/janus-gateway/pull/3518)]
- Fixed leak in recorder when adding descriptions (thanks @m08pvv!) [[PR-3487](https://github.com/meetecho/janus-gateway/pull/3487)]
- Fixed WebSocket transport binding to the wrong IP address in particular setups [[Issue-3500](https://github.com/meetecho/janus-gateway/issues/3550)]
- Improve DTX detection in janus-pp-rec [[PR-3488](#3488)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.3.0] - 2024-11-25

- Refactored logging internals [[PR-3428](https://github.com/meetecho/janus-gateway/pull/3428)]
- Use strtok to parse SDPs [[PR-3424](https://github.com/meetecho/janus-gateway/pull/3424)]
- Fixed rare condition that could lead to a deadlock in the VideoRoom [[PR-3446](https://github.com/meetecho/janus-gateway/pull/3446)]
- Fixed broken switch when using remote publishers in VideoRoom [[PR-3447](https://github.com/meetecho/janus-gateway/pull/3447)]
- Added SRTP support to VideoRoom remote publishers (thanks @spscream!) [[PR-3449](https://github.com/meetecho/janus-gateway/pull/3449)]
- Added support for generic JSON metadata to VideoRoom publishers (thanks @spscream!) [[PR-3467](https://github.com/meetecho/janus-gateway/pull/3467)]
- Fixed deadlock in VideoRoom when failing to open a socket for a new RTP forwarder (thanks @spscream!) [[PR-3468](https://github.com/meetecho/janus-gateway/pull/3468)]
- Fixed deadlock in VideoRoom caused by reverse ordering of mutex locks [[PR-3474](https://github.com/meetecho/janus-gateway/pull/3474)]
- Fixed memory leaks when using remote publishers in VideoRoom [[PR-3475](https://github.com/meetecho/janus-gateway/pull/3475)]
- Diluted frequency of PLI in the VideoRoom (thanks @natikaltura!) [[PR-3423](https://github.com/meetecho/janus-gateway/pull/3423)]
- Better cleanup after failed mountpoint creations in Streaming plugin [[PR-3465](https://github.com/meetecho/janus-gateway/pull/3465)]
- Fixed compilation of AudioBridge in case libogg isn't available (thanks @tmatth!) [[PR-3438](https://github.com/meetecho/janus-gateway/pull/3438)]
- Better management of call cleanup in SIP plugin [[Issue-3430](https://github.com/meetecho/janus-gateway/issues/3430)]
- Change the way call-IDs are tracked in the SIP plugin (thanks WebTrit!) [[PR-3443](https://github.com/meetecho/janus-gateway/pull/3443)]
- Increased maximum size of custom SIP headers [[Issue-3459](https://github.com/meetecho/janus-gateway/issues/3459)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.2.4] - 2024-09-10

- Limit number of SDP lines when parsing (workaround for OSS-Fuzz issue) [[PR-3414](https://github.com/meetecho/janus-gateway/pull/3414)]
- Normalized monotonic time to Janus start
- Added documentation for remote publishers feature in VideoRoom (SFU cascading)
- Added PLC (packet loss concealment) support to the AudioBridge (thanks @spscream!) [[PR-3349](https://github.com/meetecho/janus-gateway/pull/3349)]
- Cleanup participant queues when muted in the AudioBridge [[PR-3368](https://github.com/meetecho/janus-gateway/pull/3368)]
- Added "listannouncements" request to the AudioBridge (thanks @keremcadirci!) [[PR-3391](https://github.com/meetecho/janus-gateway/pull/3391)]
- Use sequence numbers instead of timestamps for the jitter buffer in the AudioBridge [[PR-3406](https://github.com/meetecho/janus-gateway/pull/3406)]
- Fixed event handers for SIP plugin when using Sofia SIP >= 1.13 (thanks @ ycherniavskyi!) [[PR-3386](https://github.com/meetecho/janus-gateway/pull/3386)]
- Fixed management of data buffering in Streaming plugin [[PR-3412](https://github.com/meetecho/janus-gateway/pull/3412)]
- Fixed small leak in Lua and Duktape plugins [[PR-3409](https://github.com/meetecho/janus-gateway/pull/3409)]
- Fixed recvonly m-lines not being added to SDP in janus.js when offering
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.2.3] - 2024-06-20

- Reduced size of RTP header struct in core
- Added support for helper threads to VideoRoom [[PR-3067]((https://github.com/meetecho/janus-gateway/pull/3067)]
- Fixed rare race condition in VideoRoom when destroying rooms [[PR-3361]((https://github.com/meetecho/janus-gateway/pull/3361)]
- Fixed rare crash in VideoRoom when using SVC
- Added optional RNNoise support to AudioBridge [[PR-3185]((https://github.com/meetecho/janus-gateway/pull/3185)]
- Handle jitter buffer delay manually in AudioBridge [[PR-3353]((https://github.com/meetecho/janus-gateway/pull/3353)]
- Fixed rare segfault when changing rooms in AudioBridge [[PR-3356]((https://github.com/meetecho/janus-gateway/pull/3356)]
- Empty queues in AudioBridge when muting status changes [[PR-3368]((https://github.com/meetecho/janus-gateway/pull/3368)]
- Fixed rare deadlock in AudioBridge plugin when closing connections [[PR-3387]((https://github.com/meetecho/janus-gateway/pull/3387)]
- Fixed compilation errors on MacOS for HTTP transport plugin [[Issue-3366]((https://github.com/meetecho/janus-gateway/issues/3366)]
- Fixed missing '--version' command line switch (thanks @fancycode!) [[PR-3384]((https://github.com/meetecho/janus-gateway/pull/3384)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.2.2] - 2024-04-02

* Update demos and docs to Bootstrap 5.x [[PR-3300](https://github.com/meetecho/janus-gateway/pull/3300)]
* Fixed rare race condition in VideoRoom [[PR-3331](https://github.com/meetecho/janus-gateway/pull/3331)]
* Fixed broken end-to-end encryption for subscribers in VideoRoom
* Fixed ports leak when using remote publishers in VideoRoom plugin [[Issue-3345](https://github.com/meetecho/janus-gateway/issues/3345)]
* Perform audio-level detection in AudioBridge participant thread [[PR-3312](https://github.com/meetecho/janus-gateway/pull/3312)]
* Fixed memory leak in AudioBridge in case of late packets
* Ship speexdsp's jitter buffer as part of local AudioBridge dependencies [[PR-3348](https://github.com/meetecho/janus-gateway/pull/3348)]
* Add support of abs-capture-time RTP extension to Streaming plugin (thanks @IbrayevRamil!) [[PR-3291](https://github.com/meetecho/janus-gateway/pull/3291)]
* Don't call close_pc in SIP plugin if there was no SDP [[PR-3339](https://github.com/meetecho/janus-gateway/pull/3339)]
* Fixed broken faststart when postprocessing AV1 recordings (thanks @corthiclem!) [[PR-3317](https://github.com/meetecho/janus-gateway/pull/3317)]
* Added new connectionState callback to janus.js (thanks @RSATom!) [[PR-3343](https://github.com/meetecho/janus-gateway/pull/3343)]
* Exposed Janus and Admin API ping request via GET [[Issue-3336](https://github.com/meetecho/janus-gateway/issues/3336)]
* Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.2.1] - 2023-12-06

* Added support for abs-capture-time RTP extension [[PR-3161](https://github.com/meetecho/janus-gateway/pull/3161)]
* Fixed truncated label in datachannels (thanks @veeting!) [[PR-3265](https://github.com/meetecho/janus-gateway/pull/3265)]
* Support larger values for SDP attributes (thanks @petarminchev!) [[PR-3282](https://github.com/meetecho/janus-gateway/pull/3282)]
* Fixed rare crash in VideoRoom plugin (thanks @tmatth!) [[PR-3259](https://github.com/meetecho/janus-gateway/pull/3259)]
* Don't create VideoRoom subscriptions to publisher streams with no associated codecs
* Added suspend/resume participant API to AudioBridge [[PR-3301](https://github.com/meetecho/janus-gateway/pull/3301)]
* Fixed rare crash in AudioBridge
* Fixed rare crash in Streaming plugin when doing ICE restarts [[Issue-3288](https://github.com/meetecho/janus-gateway/issues/3288)]
* Allow SIP and NoSIP plugins to bind media to a specific address (thanks @pawnnail!) [[PR-3263](https://github.com/meetecho/janus-gateway/pull/3263)]
* Removed advertised support for SIP UPDATE in SIP plugin
* Parse RFC2833 DTMF to custom events in SIP plugin (thanks @ywmoyue!) [[PR-3280](https://github.com/meetecho/janus-gateway/pull/3280)]
* Fixed missing Contact header in some dialogs in SIP plugin (thanks @ycherniavskyi!) [[PR-3286](https://github.com/meetecho/janus-gateway/pull/3286)]
* Properly set mid when notifying about ended tracks in janus.js
* Fixed broken restamping in janus-pp-rec
* Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.2.0] - 2023-08-09

- Added support for VP9/AV1 simulcast, and fixed broken AV1/SVC support [[PR-3218](https://github.com/meetecho/janus-gateway/pull/3218)]
- Fixed RTCP out quality stats [[PR-3228](https://github.com/meetecho/janus-gateway/pull/3228)]
- Default link quality stats to 100
- Added support for ICE consent freshness [[PR-3234](https://github.com/meetecho/janus-gateway/pull/3234)]
- Fixed rare race condition in VideoRoom [[PR-3219](https://github.com/meetecho/janus-gateway/pull/3219)] [[PR-3247](https://github.com/meetecho/janus-gateway/pull/3247)]
- Use speexdsp's jitter buffer in the AudioBridge [[PR-3233](https://github.com/meetecho/janus-gateway/pull/3233)]
- Fixed crash in Streaming plugin on mountpoints with too many streams [[Issue-3225](https://github.com/meetecho/janus-gateway/issues/3225)]
- Support for batched configure requests in Streaming plugin (thanks @petarminchev!) [[PR-3239](https://github.com/meetecho/janus-gateway/pull/3239)]
- Fixed rare deadlock in Streamin plugin [[PR-3250](https://github.com/meetecho/janus-gateway/pull/3250)]
- Fix simulated leave message for longer string ID rooms in TextRoom (thanks @adnanel!) [PR-3243](https://github.com/meetecho/janus-gateway/pull/3243)]
- Notify about count of sessions, handles and PeerConnections on a regular basis, when event handlers are enabled [[PR-3221](https://github.com/meetecho/janus-gateway/pull/3221)]
- Fixed broken Insertable Streams for recvonly streams when answering in janus.js
- Added background selector and blur support to Virtual Background demo
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.1.4] - 2023-05-19

- Moved discussions from Google Group to Discourse
- Fixed typo in command line argument validation
- Refactored RTP forwarder internals as a core feature [[PR-3155](https://github.com/meetecho/janus-gateway/pull/3155)]
- Refactored SVC processing as a core feature, and removed deprecated VP9/SVC demo [[PR-3174](https://github.com/meetecho/janus-gateway/pull/3174)]
- Don't create IPv6 sockets if IPv6 is completely disabled [[PR-3179](https://github.com/meetecho/janus-gateway/pull/3179)]
- Fixed some VideoRoom race conditions [[PR-3167](https://github.com/meetecho/janus-gateway/pull/3167)]
- Added simulcast/SVC params to switch in VideoRoom (thanks @brave44!) [[PR-3197](https://github.com/meetecho/janus-gateway/pull/3197)]
- Add support for receiving offers in Streaming plugin (for WHEP) [[PR-3199](https://github.com/meetecho/janus-gateway/pull/3199)]
- Add newline for SIP headers that are overflown in length (thanks @zayim!) [[PR-3184](https://github.com/meetecho/janus-gateway/pull/3184)]
- Save SIP reason state on multiple callbacks (thanks @kenangenjac!) [[PR-3210](https://github.com/meetecho/janus-gateway/pull/3210)]
- Avoid parsing whitespace as invalid JSON when receiving WebSocket messages (thanks @htrendev!) [[PR-3208](https://github.com/meetecho/janus-gateway/pull/3208)]
- Remove old tracks before adding/replacing new ones in janus.js [[PR-3203](https://github.com/meetecho/janus-gateway/pull/3203)]
- Tweaks to some janus.js internals (thanks @i8-pi!) [[PR-3211](https://github.com/meetecho/janus-gateway/pull/3211)]
- Fixed some typos and added some tweaks to Admin API demo
- Refactored npm version of janus.js
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.1.3] - 2023-03-06

- Use getaddrinfo instead of gethostbyname [[PR-3159](https://github.com/meetecho/janus-gateway/pull/3159)]
- Removed VoiceMail plugin and demo [[PR-3172](https://github.com/meetecho/janus-gateway/pull/3172)]
- Added configurable cap to number of queued events when reconnecting WebSocket event handler [[PR-3148](https://github.com/meetecho/janus-gateway/pull/3148)]
- Fixed broken support for text datachannels in Streaming plugin
- Add option to manually insert SPS/PPS RTP packets for H.264 mountpoints [[PR-3168](https://github.com/meetecho/janus-gateway/pull/3168)]
- Fixed From/To checks when getting a SIP INVITE [[Issue-3164](https://github.com/meetecho/janus-gateway/issues/3164)]
- Allow changing mjrs dir also when stopping recordings in AudioBridge [[Issue-3171](https://github.com/meetecho/janus-gateway/issues/3171)]
- Allow Lua and Duktape plugins to relay extensions when relaying RTP packets [[PR-3162](https://github.com/meetecho/janus-gateway/pull/3162)]
- Optionally support X-Forwarded-For in both HTTP and WebSocket transports [[PR-3160](https://github.com/meetecho/janus-gateway/pull/3160)]
- Add reason of track being added/removed in onremotetrack in janus.js (thanks @marekpiechut!) [[PR-3150](https://github.com/meetecho/janus-gateway/pull/3150)]
- Fixed broken VP9-SVC demo room [[Issue-3169](https://github.com/meetecho/janus-gateway/issues/3169)]
- Linted whole JS demo codebase [[PR-3170](https://github.com/meetecho/janus-gateway/pull/3170)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.1.2] - 2023-01-17

- Always add mid to the SDP, even for disabled m-lines
- Don't allow mid changes for m-line during renegotiations [[PR-3136](https://github.com/meetecho/janus-gateway/pull/3136)]
- Consider RTCP feedback messages when evaluating receiver SSRC
- Added partial support for L16 codec (uncompressed audio) [[PR-3116](https://github.com/meetecho/janus-gateway/pull/3116)]
- Fixed overwriting of 7-bit PictureID when doing VP8 simulcast [[PR-3121](https://github.com/meetecho/janus-gateway/pull/3121)]
- Send data stats when using event handlers [[PR-3126](https://github.com/meetecho/janus-gateway/pull/3126)]
- Copy formats from datachannel m-lines also when rejecting them [[Issue-3134](https://github.com/meetecho/janus-gateway/issues/3134)]
- Fixed compiler issue with recent versions of libcurl (thanks @bkmgit!) [[PR-3138](https://github.com/meetecho/janus-gateway/pull/3138)]
- Close mountpoint sockets when leaving relay thread [[PR-3143](https://github.com/meetecho/janus-gateway/pull/3143)]
- Fixed segfault in SIP plugin in case of broken SUBSCRIBE [[Issue-3133](https://github.com/meetecho/janus-gateway/issues/3133)]
- Support multiple requests in a single websocket message (thanks @jwittner!) [[PR-3123](https://github.com/meetecho/janus-gateway/pull/3123)]
- Fixed inability to add recvonly tracks in janus.js ([[Issue-3119](https://github.com/meetecho/janus-gateway/issues/3119)]
- Updated janus.d.ts type definitions (thanks @jerry4718!) [[PR-3125](https://github.com/meetecho/janus-gateway/pull/3125)]
- Fixed out of range error when passing large SSRC values to pcap2mjr
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.1.1] - 2022-12-07

- Added timing info on ICE starting and gathering done to Admin API
- Fixed rare crash when generating SDP to send [[Issue-3081](https://github.com/meetecho/janus-gateway/issues/3081)]
- Fixed rare crash when checking payload types (thanks @zevarito!) [[PR-3086](3086)]
- Fixed double a=ssrc attribute in SDP for inactive m-line
- Replaced non-portable strcasestr() with strncasecmp() (thanks @iskraman!) [[PR-3076](https://github.com/meetecho/janus-gateway/pull/3076)]
- Fixed parameters not being URL-encoded when using TURN REST API [[Issue-3112](https://github.com/meetecho/janus-gateway/issues/3112)]
- Fixed renegotiation sent to VideoRoom subscribers when a room is destroyed [[Issue-3083](https://github.com/meetecho/janus-gateway/issues/3083)]
- Added option to prevent automatic SDP offer updates to VideoRoom subscribers when a publisher leaves
- Fixed "send" property not being automatically reset to "true" in the VideoRoom for new subscriptions
- Fixed small memory leak in AudioBridge (thanks @RSATom!) [[PR-3088](https://github.com/meetecho/janus-gateway/pull/3088)]
- Minor fixes to the Streaming plugin
- Enforced media direction policies when SIP call is on hold [PR-3087](https://github.com/meetecho/janus-gateway/pull/3087)]
- Added code to send PLI to SIP peer when recording [[PR-3093](https://github.com/meetecho/janus-gateway/pull/3093)]
- Fixed renegotiations in VideoCall not updating session properties
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.1.0] - 2022-10-03

- Added versioning to .so files [[PR-3075](https://github.com/meetecho/janus-gateway/pull/3075)]
- Allow plugins to specify msid in SDPs [[PR-2998](https://github.com/meetecho/janus-gateway/pull/2998)]
- Fixed broken RTCP timestamp on 32bit architectures [[Issue-3045](https://github.com/meetecho/janus-gateway/issues/3045)]
- Fixed problems compiling against recent versions of libwebsockets [[Issue-3039](https://github.com/meetecho/janus-gateway/issues/3039)]
- Updated deprecated DTLS functions to OpenSSL v3.0 [PR-3048](https://github.com/meetecho/janus-gateway/pull/3048)]
- Switched to SHA256 for signing self signed DTLS certificates (thanks @tgabi333!) [[PR-3069](https://github.com/meetecho/janus-gateway/pull/3069)]
- Started using strnlen to optimize performance of some strlen calls (thanks @tmatth!) [[PR-3059](https://github.com/meetecho/janus-gateway/pull/3059)]
- Added checks to avoid RTX payload type collisions [[PR-3080](https://github.com/meetecho/janus-gateway/pull/3080)]
- Added new APIs for cascading VideoRoom publishers [[PR-3014](https://github.com/meetecho/janus-gateway/pull/3014)]
- Fixed deadlock when using legacy switch in VideoRoom [[Issue-3066](https://github.com/meetecho/janus-gateway/issues/3066)]
- Fixed disabled property not being advertized to subscribers when VideoRoom publishers removed tracks
- Fixed occasional deadlock when using G.711 in the AudioBridge [[Issue-3062](https://github.com/meetecho/janus-gateway/issues/3062)]
- Added new way of capturing devices/tracks in janus.js [[PR-3003](https://github.com/meetecho/janus-gateway/pull/3003)]
- Removed call to .stop() for remote tracks in demos [[PR-3056](https://github.com/meetecho/janus-gateway/pull/3056)]
- Fixed missing message/info/transfer buttons in SIP demo page
- Fixed postprocessing compilation issue on older FFmpeg versions [[PR-3064](https://github.com/meetecho/janus-gateway/pull/3064)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.0.4] - 2022-08-01

- Fixed problem with duplicate ptypes when codecs are added in renegotiations
- Added codec info to event handlers stats
- Allow offers to include other roles besides 'actpass' for DTLS [[PR-3020](https://github.com/meetecho/janus-gateway/pull/3020)]
- Fixed rare race conditions when attempting to relay packets sent by plugins [[PR-3010](https://github.com/meetecho/janus-gateway/pull/3010)]
- Fixed unprotected access to medium instances in janus_plugin_handle_sdp
- Set appropriate channel type when sending DATA_CHANNEL_OPEN_REQUEST message (thanks @ktyu!) [[PR-3018](https://github.com/meetecho/janus-gateway/pull/3018)]
- Fixed rare race condition when handling incoming RTCP feedback in VideoRoom
- Fixed memory leak in VideoRoom when using rid-based simulcast (thanks @OxleyS!) [[PR-2995](https://github.com/meetecho/janus-gateway/pull/2995)]
- Fixed IPv6 always enabled for VideoRoom RTP forwarders [[Issue-3011](https://github.com/meetecho/janus-gateway/issues/3011)]
- Start recording VideoRoom publisher on PeerConnection establishment, if needed (thanks @adnanel!) [[PR-3013](https://github.com/meetecho/janus-gateway/pull/3013)]
- Added an optional ID in subscribe requests to match with subscription events (thanks @JanFellner!) [[PR-3027](https://github.com/meetecho/janus-gateway/pull/3027)]
- Make Streaming plugin use SDP utils, and codecs instead of rtpmaps [[PR-2994](https://github.com/meetecho/janus-gateway/pull/2994)]
- Check response codes of RTSP requests in Streaming plugin [[Issue-3015](https://github.com/meetecho/janus-gateway/issues/3015)]
- Fixed small memory leak in SIP plugin [[Issue-3032](https://github.com/meetecho/janus-gateway/issues/3032)]
- Fixed broken simulcast support in Lua and Duktape plugins
- Don't use .clone() on tracks to render them in demos [[PR-3009](https://github.com/meetecho/janus-gateway/pull/3009)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.0.3] - 2022-06-20

- Keep track of RTP extensions when storing packets for retransmission [[PR-2981](https://github.com/meetecho/janus-gateway/pull/2981)]
- Fixed negotiation of RTP extensions when direction is involved
- Fixed broken VP8 payload descriptor parsing when 7-bit PictureID are used
- Support for batched configure requests in VideoRoom [[PR-2986](https://github.com/meetecho/janus-gateway/pull/2986)]
- Added missing info to VideoRoom publisher's info own event [[Issue-2988](https://github.com/meetecho/janus-gateway/issues/2988)]
- Fixed memory leaks in when upgrading old-style Videoroom requests (thanks @OxleyS!) [[PR-3002](https://github.com/meetecho/janus-gateway/pull/3002)]
- Fixed memory leak in VideoRoom when updating subscriptions with no changes
- Added 'kick_all' requests and possibility to remove PIN code to both Audiobridge and Streaming plugins (thanks @mikaelnousiainen!) [[PR-2978](https://github.com/meetecho/janus-gateway/pull/2978)]
- Added support for notifications in the Streaming plugin when metadata for a mountpoint is changed (thanks @amoizard!) [[PR-3000](https://github.com/meetecho/janus-gateway/pull/3000)]
- Fixed missing checks on auth challenges in SIP plugin
- Fixed missing Contact header in SUBSCRIBE requests in SIP plugin [[PR-2973](https://github.com/meetecho/janus-gateway/pull/2973)]
- Fixed segfault in SIP plugin when freeing a session with a subscription still active [[PR-2974](https://github.com/meetecho/janus-gateway/pull/2974)]
- Add new shared JavaScript file for settings in demos [[PR-2991](https://github.com/meetecho/janus-gateway/pull/2991)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.0.2] - 2022-05-23

- Abort DTLS handshake if DTLSv1_handle_timeout returns an error
- Fixed rtx not being offered on Janus originated PeerConnections
- Added configurable property to put a cap to task threads [[Issue-2964](https://github.com/meetecho/janus-gateway/issues/2964)]
- Fixed build issue with libressl >= 3.5.0 (thanks @ffontaine!) [[PR-2980](https://github.com/meetecho/janus-gateway/pull/2980)]
- Link to -lresolv explicitly when building websockets transport
- Fixed RED parsing not returning blocks when only primary data is available
- Fixed typo in stereo support in EchoTest plugin
- Added support for dummy publishers in VideoRoom [[PR-2958](https://github.com/meetecho/janus-gateway/pull/2958)]
- Added new VideoRoom request to combine subscribe and unsubscribe operations [[PR-2962](https://github.com/meetecho/janus-gateway/pull/2962)]
- Fixed incorrect removal of owner/subscriptions mapping in VideoRoom plugin [[Issue-2965](https://github.com/meetecho/janus-gateway/issues/2965)]
- Explicitly return list of IDs VideoRoom users are subscribed to for data [[Issue-2967](https://github.com/meetecho/janus-gateway/issues/2967)]
- Fixed data port not being returned when creating Streaming mountpoints with the legacy API
- Fix address size in Streaming plugin RTCP sendto call (thanks @sjkummer!) [[PR-2976](https://github.com/meetecho/janus-gateway/pull/2976)]
- Added custom headers for SIP SUBSCRIBE requests (thanks @oriol-c!) [[PR-2971](https://github.com/meetecho/janus-gateway/pull/2971)]
- Make SIP timer T1X64 configurable (thanks @oriol-c!) [[PR-2972](https://github.com/meetecho/janus-gateway/pull/2972)]
- Disable IPv6 in WebSockets transport if binding to IPv4 address explicitly [[Issue-2969](https://github.com/meetecho/janus-gateway/issues/2969)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.0.1] - 2022-04-26

- Removed gengetopt as a dependency, to use Glib's GOptionEntry instead [[PR-2898](https://github.com/meetecho/janus-gateway/pull/2898)]
- Fixed occasional problem of duplicate mid attribute in Janus SDPs [[Issue-2917](https://github.com/meetecho/janus-gateway/issues/2917)]
- Fixed receiving=false events not being sent right away for higher simulcast substreams [[Issue-2919](https://github.com/meetecho/janus-gateway/issues/2919)]
- Fix highest sequence number not being properly initialized in the RTCP context [[Issues-2920](https://github.com/meetecho/janus-gateway/issues/2920)]
- Reset rids when renegotiating SDPs [[PR-2931](https://github.com/meetecho/janus-gateway/pull/2931)]
- Fixed missing PLI when restoring previously paused streams in VideoRoom (thanks @flaviogrossi!) [[PR-2922](https://github.com/meetecho/janus-gateway/pull/2922)]
- Fixed deadlock when using the moderate API in the VideoRoom [[Issue-2956](https://github.com/meetecho/janus-gateway/issues/2956)]
- Check if IPv6 is disabled to avoid failure when creating forwarder sockets in AudioBridge and VideoRoom [[PR-2916](https://github.com/meetecho/janus-gateway/pull/2916)]
- Fixed invalid computation of Streaming mountpoint stream age (thanks @RouquinBlanc!) [[PR-2928](https://github.com/meetecho/janus-gateway/pull/2928)]
- Also return reason header protocol and cause if present in BYE in the SIP plugin (thanks @ajsa-terko!) [[PR-2935](https://github.com/meetecho/janus-gateway/pull/2935)]
- Fixed segfault in UNIX transport teardown caused by pathnames of different sizes
- Added new demos on WebAudio and Virtual Backgrounds [[PR-2941](https://github.com/meetecho/janus-gateway/pull/2941)]
- Fixed potential race conditions in multistream VideoRoom demo [[Issue-2929](https://github.com/meetecho/janus-gateway/issues/2929)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v1.0.0] - 2022-03-03

- Refactored Janus to support multistream PeerConnections [[PR-2211](https://github.com/meetecho/janus-gateway/pull/2211)]
- Moved all source files under new 'src' folder to unclutter the repo [[PR-2885](https://github.com/meetecho/janus-gateway/pull/2885)]
- Fixed definition of trylock wrapper when using pthreads [[Issue-2894](https://github.com/meetecho/janus-gateway/issues/2894)]
- Fixed broken RTP when no extensions are negotiated
- Added checks when inserting RTP extensions to avoid buffer overflows
- Added missing support for disabled rid simulcast substreams in SDP [[PR-2888](https://github.com/meetecho/janus-gateway/pull/2888)]
- Fixed TWCC feedback when simulcast SSRCs are missing (thanks @OxleyS!) [[PR-2908](https://github.com/meetecho/janus-gateway/pull/2908)]
- Added support for playout-delay RTP extension [[PR-2895](https://github.com/meetecho/janus-gateway/pull/2895)]
- Fixed partially broken H.264 support when using Firefox in VideoRoom
- Fixed new VideoRoom rtp_forward API ignoring some properties
- Fixed deadlock and segfault when stopping Streaming mountpoint recordings [[Issue-2902](https://github.com/meetecho/janus-gateway/issues/2902)]
- Fixed RTSP support in Streaming plugin for cameras that expect path-only DESCRIBE requests (thanks @jp-bennett!) [[PR-2909](https://github.com/meetecho/janus-gateway/pull/2909)]
- Fixed RTP being relayed incorrectly in Lua and Duktape plugins
- Added Duktape as optional dependency, instead of embedding the engine code [[PR-2886](https://github.com/meetecho/janus-gateway/pull/2886)]
- Fixed crash at startup when not able to connect to RabbitMQ server
- Improved fuzzing and checks on RTP extensions
- Removed distinction between simulcast and simulcast2 in janus.js [[PR-2887](https://github.com/meetecho/janus-gateway/pull/2887)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.11.8] - 2022-02-11

- Added initial (and limited) integration of RED audio [[PR-2685](https://github.com/meetecho/janus-gateway/pull/2685)]
- Added support for Two-Byte header RTP extensions (RFC8285) and, partially, for the new Depencency Descriptor RTP extension (needed for AV1-SVC) [[PR-2741](https://github.com/meetecho/janus-gateway/pull/2741)]
- Fixed rare race conditions between sending a packet and closing a connection [[PR-2869](https://github.com/meetecho/janus-gateway/pull/2869)]
- Fix last stats before closing PeerConnection not being sent to handlers (thanks @zodiak83!) [[PR-2874](https://github.com/meetecho/janus-gateway/pull/2874)]
- Changed automatic allocation on static loops from round robin to least used [[PR-2878](https://github.com/meetecho/janus-gateway/pull/2878)]
- Added new API to bulk start/stop MJR-based recordings in AudioBridge [[PR-2862](https://github.com/meetecho/janus-gateway/pull/2862)]
- Fixed broken duration in spatial AudioBridge recordings
- Fixed broken G.711 RTP forwarding in AudioBridge (thanks @AlexYaremchuk!) [[PR-2875](https://github.com/meetecho/janus-gateway/pull/2875)]
- Fixed broken recordings in NoSIP plugin
- Fixed warnings when postprocessing Opus recordings with DTX packets
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.11.7] - 2022-01-24

- Added faster strlcat variant that uses memccpy for writing SDPs [[PR-2835](https://github.com/meetecho/janus-gateway/pull/2835)]
- Fixed occasional crash when updating WebRTC sessions [[Issue-2840](https://github.com/meetecho/janus-gateway/issues/2840)]
- Changed SDP syntax for AV1 from "AV1X" to "AV1" [[Issue-2844](https://github.com/meetecho/janus-gateway/issues/2844)]
- Fixed signed_tokens property not being saved to permanent rooms in VideoRoom (thanks @timsolov!) [[PR-2843](https://github.com/meetecho/janus-gateway/pull/2843)]
- Made record directory changeable via "edit" in both AudioBridge and VideoRoom
- Added configurable expected loss to AudioBridge to actually send FEC [[PR-2802](https://github.com/meetecho/janus-gateway/pull/2802)]
- Fixed SIP plugin not working when using Sofia SIP >= 1.13 [[Issue-2683](https://github.com/meetecho/janus-gateway/issues/2683)]
- Fixed occasional crashes in SIP plugin [[Issue-2853](https://github.com/meetecho/janus-gateway/issues/2853)]
- Take note of video orientation extension when recording video in SIP plugin (thanks @adnanel!) [[PR-2836](https://github.com/meetecho/janus-gateway/pull/2836)]
- Allow 180 besides 183 to have SDP as well (thanks @lejlasolak!) [[PR-2849](https://github.com/meetecho/janus-gateway/pull/2849)]
- Fixed post-processor compilation issue with newer versions of FFmpeg [[Issue-2833](https://github.com/meetecho/janus-gateway/issues/2833)]
- Added option to print extended info on MJR file as JSON in postprocessor (thanks @adnanel!) [[PR-2858](https://github.com/meetecho/janus-gateway/pull/2858)]
- Allow pcap2mjr to autodetect SSRC
- Fixed problems compiling post-processor with older versions of FFmpeg
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.11.6] - 2021-12-13

- Added strlcat helper to detect and report truncations [[PR-2792](https://github.com/meetecho/janus-gateway/pull/2792)]
- Grow buffer as needed when generating SDPs [[PR-2797](https://github.com/meetecho/janus-gateway/pull/2797)]
- Added DTX support to some plugins [[PR-2789](https://github.com/meetecho/janus-gateway/pull/2789)]
- Added option to forcibly quit Janus when getting dlopen errors (thanks @tmatth!) [[PR-2828](https://github.com/meetecho/janus-gateway/pull/2828)]
- Fixed broken signed tokens in VideoRoom when using UUIDs (thanks @timsolov!) [[PR-2812](https://github.com/meetecho/janus-gateway/pull/2812)]
- Added option to choose whether signed tokens should be used in the VideoRoom when enabled in the core [[PR-2825](https://github.com/meetecho/janus-gateway/pull/2825)]
- Added MESSAGE authentication and out-of-dialog MESSAGE support to SIP plugin (thanks thetechpanda!) [[PR-2786](https://github.com/meetecho/janus-gateway/pull/2786)]
- Fixed potential race conditions in SIP plugin [[PR-2823](https://github.com/meetecho/janus-gateway/pull/2823)]
- Added basic history support to TextRoom plugin [[PR-2814](https://github.com/meetecho/janus-gateway/pull/2814)]
- Fixed Cross-site Scripting (XSS) vulnerability in some of the demos (thanks @SoufElhabti!) [[PR-2817](https://github.com/meetecho/janus-gateway/pull/2817)]
- Added support for custom datachannel options in janus.js (thanks @sqxieshuai!) [[PR-2806](https://github.com/meetecho/janus-gateway/pull/2806)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.11.5] - 2021-10-18

- Add API to optionally force Janus to use TURN [[PR-2774](https://github.com/meetecho/janus-gateway/pull/2774)]
- Fixed slow path on SDP parsing [[PR-2776](https://github.com/meetecho/janus-gateway/pull/2776)]
- Added event handlers option to send stats for a PeerConnection in a single event, rather than per-media (thanks @JanFellner!) [[PR-2785](https://github.com/meetecho/janus-gateway/pull/2785)]
- Fixed occasional deadlocks on malformed requests in VideoRoom [[Issue-2780](https://github.com/meetecho/janus-gateway/issues/2780)]
- Fixed AudioBridge plain RTP thread sometimes exiting prematurely
- Fixed broken upsampling when using G.711 in AudioBridge
- Add pause/resume recording functionality to Record&Play and SIP plugins (thanks @isnumanagic!) [[PR-2724](https://github.com/meetecho/janus-gateway/pull/2724)]
- Fixed broken support for Unix Sockets in WebSockets Admin API (thanks @thatsmydoing!) [[PR-2787](https://github.com/meetecho/janus-gateway/pull/2787)]
- Added timing info for video rotation when post-processing recordings
- Added linter checks to janus.js (thanks @davel!) [[PR-2272](https://github.com/meetecho/janus-gateway/pull/2272)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.11.4] - 2021-09-06

- Fixed ICE restart issues with recent versions of libnice [[PR-2729](https://github.com/meetecho/janus-gateway/pull/2729)]
- Changed randon number generators to use crypto-safe functions (thanks @jmfotokite!) [[PR-2738](https://github.com/meetecho/janus-gateway/pull/2738)]
- Added support for abs-send-time RTP extension [[PR-2721](https://github.com/meetecho/janus-gateway/pull/2721)]
- Added configurable mechanism for manually setting static event loop to use for new handles [[PR-2684](https://github.com/meetecho/janus-gateway/pull/2684)]
- Fixed datachannel protocol not being sent to plugins for incoming messages [[Issue-2753](https://github.com/meetecho/janus-gateway/issues/2753)]
- Added ability to specify recordings folder in AudioBridge [[PR-2707](https://github.com/meetecho/janus-gateway/pull/2707)]
- Added support for forwarding groups in AudioBridge [[PR-2653](https://github.com/meetecho/janus-gateway/pull/2653)]
- Fixed missing Contact header in SIP plugin when using Sofia >= 1.13 [[PR-2708](https://github.com/meetecho/janus-gateway/pull/2708)]
- Better SDES-SRTP negotiation in SIP and NoSIP plugins [[PR-2727](https://github.com/meetecho/janus-gateway/pull/2727)]
- Fixed WebSocket transport and event handler lagging 25/30s when shutting down or reconnecting (thanks @JanFellner!) [[Issue-2734](https://github.com/meetecho/janus-gateway/issues/2734)]
- Fixed incoming_header_prefixes not working for helper sessions in SIP plugin
- Fix partial/broken ACL support in TextRoom plugin [[PR-2763](https://github.com/meetecho/janus-gateway/pull/2763)]
- Fixed potential race condition when reclaiming sessions in HTTP transport plugin
- Fixed WebSocket event handler reconnect mechanism (thanks @JanFellner!) [[PR-2736](https://github.com/meetecho/janus-gateway/pull/2736)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.11.3] - 2021-06-15

- Fixed rare crash when detaching handles [[Issue-2464](https://github.com/meetecho/janus-gateway/issues/2464)]
- Added option to offer IPv6 link-local candidates as well [[PR-2689](https://github.com/meetecho/janus-gateway/pull/2689)]
- Added spatial audio support to AudioBridge via stereo mixing [[PR-2446](https://github.com/meetecho/janus-gateway/pull/2446)]
- Added support for plain RTP participants to AudioBridge [[PR-2464](https://github.com/meetecho/janus-gateway/pull/2464)]
- Added API to start/stop AudioBridge recordings dynamically (thanks @rajneeshksoni!) [[PR-2674](https://github.com/meetecho/janus-gateway/pull/2674)]
- Fixed broken mountpoint switching when using different payload types in Streaming plugin [[PR-2692](https://github.com/meetecho/janus-gateway/pull/2692)]
- Fixed occasional deadlock on Streaming plugin mountpoint destroy during RTSP reconnects (thanks @lionelnicolas!) [[PR-2700](https://github.com/meetecho/janus-gateway/pull/2700)]
- Added "Expires" support to SUBSCRIBE in SIP plugin (thanks @nicolasduteil!) [[PR-2661](https://github.com/meetecho/janus-gateway/pull/2661)]
- Added option to specify Call-ID for SUBSCRIBE dialogs in SIP plugin (thanks @nicolasduteil!) [[PR-2664](https://github.com/meetecho/janus-gateway/pull/2664)]
- Fixed broken simulcast support in VideoCall plugin (thanks @lucily-star!) [[PR-2671](https://github.com/meetecho/janus-gateway/pull/2671)]
- Implemented RabbitMQ reconnection logic, in both transport and event handler (thanks @chriswiggins!) [[PR-2651](https://github.com/meetecho/janus-gateway/pull/2651)]
- Added support for renegotiation of external streams in janus.js (thanks @kmeyerhofer!) [[PR-2604](https://github.com/meetecho/janus-gateway/pull/2604)]
- Added support for HEVC/H.265 aggregation packets (AP) to janus-pp-rec (thanks @nu774!) [[PR-2662](https://github.com/meetecho/janus-gateway/pull/2662)]
- Refactored janus-pp-rec to cleanup the code, and use libavformat for Opus as well (thanks @lu-zero!) [[PR-2665](https://github.com/meetecho/janus-gateway/pull/2665)]
- Added additional target formats for some recorded codecs [[PR-2680](https://github.com/meetecho/janus-gateway/pull/2680)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.11.2] - 2021-05-03

- Added support for relative paths in config files, currently only in MQTT event handler (thanks @RSATom!) [[PR-2623](https://github.com/meetecho/janus-gateway/pull/2623)]
- Removed support for now deprecated frame-marking RTP extension [[PR-2640](https://github.com/meetecho/janus-gateway/pull/2640)]
- Fixed rare race condition between VideoRoom publisher leaving and subscriber hanging up [[PR-2637](https://github.com/meetecho/janus-gateway/pull/2637)]
- Fixed occasional crash when using announcements in AudioBridge
- Fixed rare crash in Streaming plugin when reconnecting RTSP streams (thanks @lucylu-star!) [[PR-2542](https://github.com/meetecho/janus-gateway/pull/2542)]
- Fixed broken switch in Streaming plugin when using helper threads
- Fixed rare race conditions on socket close in SIP and NoSIP plugins [[PR-2599](https://github.com/meetecho/janus-gateway/pull/2599)]
- Added support for out-of-dialog SIP MESSAGE requests (thanks @ihusejnovic!) [[PR-2616](https://github.com/meetecho/janus-gateway/pull/2616)]
- Fixed memory leak when using helper threads in Streaming plugin
- Added support for datachannel label/protocol to Lua and Duktape plugins [[PR-2641](https://github.com/meetecho/janus-gateway/pull/2641)]
- Added ability to use WebSockets transport over Unix sockets (thanks @mdevaev!) [[PR-2620](https://github.com/meetecho/janus-gateway/pull/2620)]
- Added janus-pp-rec mechanism to correct wrong RTP timestamps in MJR recordings (thanks @tbence94!) [[PR-2573](https://github.com/meetecho/janus-gateway/pull/2573)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.11.1] - 2021-04-06

- Add new option to configure ICE nomination mode, if libnice is recent enough [[PR-2541](https://github.com/meetecho/janus-gateway/pull/2541)]
- Added support for per-session timeout values (thanks @alg!) [[PR-2577](https://github.com/meetecho/janus-gateway/pull/2577)]
- Added support for compilation on FreeBSD (thanks @jsm222!) [[PR-2508](https://github.com/meetecho/janus-gateway/pull/2508)]
- Fixed occasional auth errors when using both API secret and stored tokens (thanks @deep9!) [[PR-2581](https://github.com/meetecho/janus-gateway/pull/2581)]
- Added support for stdout logging to daemon-mode as well (thanks @mtorromeo!) [[PR-2591](https://github.com/meetecho/janus-gateway/pull/2591)]
- Fixed odr-violation issue between Lua and Duktape plugins [[PR-2540](https://github.com/meetecho/janus-gateway/pull/2540)]
- Fixed missing simulcast stats in Admin API and Event Handlers when using rid [[Issue-2610](https://github.com/meetecho/janus-gateway/issues/2610)]
- Fixed VideoRoom recording not stopped for participants entering after global recording was started [[PR-2550](https://github.com/meetecho/janus-gateway/pull/2550)]
- Fixed 'audiocodec'/'videocodec' being ignored when joining a VideoRoom via 'joinandconfigure'
- Added content type support to MESSAGE in SIP plugin (thanks @tijmenNL!) [[PR-2567](https://github.com/meetecho/janus-gateway/pull/2567)]
- Made RTSP timeouts configurable in Streaming plugin (thanks @pontscho!) [[PR-2598](https://github.com/meetecho/janus-gateway/pull/2598)]
- Fixed incorrect parsing of backend URL in WebSockets event handler [[Issue-2603](https://github.com/meetecho/janus-gateway/issues/2603)]
- Added support for secure connections and lws debugging to WebSockets event handler
- Fixed occasionally broken AV1 recordings post-processing
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.10.10] - 2021-02-06

- Reduced verbosity of a few LOG_WARN messages at startup
- Close libnice agent resources asynchronously when hanging up PeerConnections (thanks @fbellet!) [[PR-2492](https://github.com/meetecho/janus-gateway/pull/2492)]
- Fixed broken parsing of SDP when trying to match specific codec profiles [[PR-2549](https://github.com/meetecho/janus-gateway/pull/2549)]
- Added muting/moderation API to the VideoRoom plugin [[PR-2513](https://github.com/meetecho/janus-gateway/pull/2513)]
- Fixed a few race conditions in VideoRoom plugin that could lead to crashes [[PR-2539](https://github.com/meetecho/janus-gateway/pull/2539)]
- Send 480 instead of BYE when hanging up calls in early dialog in the SIP plugin (thanks @zayim!) [[PR-2521](https://github.com/meetecho/janus-gateway/pull/2521)]
- Added configurable media direction when putting calls on-hold in the SIP plugin [[PR-2525](https://github.com/meetecho/janus-gateway/pull/2525)]
- Fixed rare race condition in AudioBridge when using "changeroom" (thanks @JeckLabs!) [[PR-2535](https://github.com/meetecho/janus-gateway/pull/2535)]
- Fixed broken API secret management in HTTP long polls (thanks @remvst!) [[PR-2524](https://github.com/meetecho/janus-gateway/pull/2524)]
- Report failure if binding to a socket fails in WebSockets transport plugin (thanks @Symbiatch!) [[PR-2534](https://github.com/meetecho/janus-gateway/pull/2534)]
- Updated RabbitMQ logic in both transport and event handler (thanks @chriswiggins!) [[PR-2430](https://github.com/meetecho/janus-gateway/pull/2430)]
- Fixed segfault in WebSocket event handler when backend was unreachable
- Added TLS support to MQTT event handler (thanks @RSATom!) [[PR-2517](https://github.com/meetecho/janus-gateway/pull/2517)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.10.9] - 2020-12-23

- Replaced Travis CI with GitHub Actions [[PR-2486](https://github.com/meetecho/janus-gateway/pull/2486)]
- Fixed data channel messages potentially getting stuck in case of burst transfers (thanks @afshin2003!) [[PR-2427](https://github.com/meetecho/janus-gateway/pull/2427)]
- Fixed simulcast issues when renegotiating PeerConnections [[Issue-2466](https://github.com/meetecho/janus-gateway/issues/2466)]
- Added configurable TURN REST API timeout (thanks @evorw!) [[PR-2470](https://github.com/meetecho/janus-gateway/pull/2470)]
- Added support for recording of binary data channels [[PR-2481](https://github.com/meetecho/janus-gateway/pull/2481)]
- Fixed occasional SRTP errors when pausing and then resuming Streaming plugin handles after a long time
- Fixed occasional SRTP errors when leaving and joining AudioBridge rooms without a new PeerConnection after a long time
- Added support for playout of data channels in Record&Play plugin and demo (thanks @ricardo-salgado-tekever!) [[PR-2468](https://github.com/meetecho/janus-gateway/pull/2468)]
- Added option to override connections limit in HTTP transport plugin [[PR-2489](https://github.com/meetecho/janus-gateway/pull/2489)]
- Added options to enable libmicrohttpd debugging in HTTP transport plugin (thanks @evorw!) [[PR-2471](https://github.com/meetecho/janus-gateway/pull/2471)]
- Fixed a few compile and runtime issues in WebSocket event handler
- Refactored postprocessing management of timestamps to fix some key issues [[PR-2345](https://github.com/meetecho/janus-gateway/pull/2345)]
- Fixed postprocessing of audio recordings containing RTP silence suppression packets [[PR-2467](https://github.com/meetecho/janus-gateway/pull/2467)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.10.8] - 2020-11-23

- Added differentiation between IPv4 and IPv6 NAT-1-1 addresses [[PR-2423](https://github.com/meetecho/janus-gateway/pull/2423)]
- Made NACK buffer cleanup on outgoing keyframe disabled by default but configurable [[PR-2402](https://github.com/meetecho/janus-gateway/pull/2402)]
- Added support for simulcast and TWCC to Duktape and Lua plugins [[PR-2409](https://github.com/meetecho/janus-gateway/pull/2409)]
- Fixed rare crash in AudioBridge plugin when leaving a room [[Issue-2432](https://github.com/meetecho/janus-gateway/issues/2432)]
- Fixed codec names not being updated in the SIP plugin after renegotiations (thanks @ihusejnovic!) [[PR-2417](https://github.com/meetecho/janus-gateway/pull/2417)]
- Fixed crash in SIP plugin when handling REGISTER challenges without WWW-Authenticate headers [[Issue-2419](https://github.com/meetecho/janus-gateway/issues/2419)]
- Added option to SIP plugin to let users CANCEL pending transactions without waiting for a 1xx [[PR-2434](https://github.com/meetecho/janus-gateway/pull/2434)]
- Added option to enforce CORS on the server side in both HTTP and WebSocket transport plugins [[PR-2410](https://github.com/meetecho/janus-gateway/pull/2410)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.10.7] - 2020-10-30

- Fixed SDP negotiation when client uses max-bundle [[Issue-2390](https://github.com/meetecho/janus-gateway/issues/2390)]
- Added optional JSEP flag to invert processing order of simulcast "rid" in SDP [[PR-2385](https://github.com/meetecho/janus-gateway/pull/2385)]
- Fixed broken rid-based simulcast when using less than 3 substreams
- Fixed occasional misleading "private IP" warning on startup (thanks @npikimasu!) [[PR-2386](https://github.com/meetecho/janus-gateway/pull/2386)]
- Added "plugin-offer mode" to AudioBridge [[PR-2366](https://github.com/meetecho/janus-gateway/pull/2366)]
- Fixed occasional deadlock when sending SUBSCRIBE messages via SIP plugin [[PR-2387](https://github.com/meetecho/janus-gateway/pull/2387)]
- Fixed occasional SIGABRT in RabbitMQ transport (thanks @david-goncalves!) [[PR-2380](https://github.com/meetecho/janus-gateway/pull/2380)]
- Fixed broken RTP parsing in janus-pp-rec when there were too many extensions (thanks @isnumanagic!) [[PR-2411](https://github.com/meetecho/janus-gateway/pull/2411)]
- Fixed occasional segfault when post-processing G.722 mjr recordings
- Added configurable simulcast encodings to janus.js (thanks @fippo!) [[PR-2393](https://github.com/meetecho/janus-gateway/pull/2392)]
- Updated old Insertable Streams APIs in janus.js and e2etest.js
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.10.6] - 2020-10-05

- New mechanism to tweak/query transport plugins via Admin API [[PR-2354](https://github.com/meetecho/janus-gateway/pull/2354)]
- Fixed occasional segfault when using event handlers and VideoRoom [[Issue-2352](https://github.com/meetecho/janus-gateway/issues/2352)]
- Fixed occasional "Unsupported codec 'none'" log errors (thanks @neilyoung!) [[PR-2357](https://github.com/meetecho/janus-gateway/pull/2357)]
- Fixed broken AudioBridge RTP forwarding when using G711 [[Issue-2375](https://github.com/meetecho/janus-gateway/issues/2375)]
- Added helper threads support to RTSP mountpoints as well [[PR-2361](https://github.com/meetecho/janus-gateway/pull/2361)]
- Fixed data channels not working as expected in Streaming plugin when using helper threads
- Fixed simulcast occasionally not working in Streaming plugin until manual PLI trigger
- Added proper fragmentation in WebSockets transport plugin [[PR-2355](https://github.com/meetecho/janus-gateway/pull/2355)]
- Fixed timing resolution issue in MQTT transport (thanks @feymartynov!)) [[PR-2358](https://github.com/meetecho/janus-gateway/pull/2358)]
- Fixed MQTT transport issue when trying to shutdown gracefully (thanks @feymartynov!)) [[PR-2374](https://github.com/meetecho/janus-gateway/pull/2374)]
- Fixed broken configuration of Nanomsg Admin API (thanks @sdamodharan!)) [[PR-2372](https://github.com/meetecho/janus-gateway/pull/2372)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.10.5] - 2020-09-08

- Fixed occasional crash in event handlers [[Issue-2312](https://github.com/meetecho/janus-gateway/issues/2312)]
- Fixed occasional crash in VideoRoom plugin [[Issue-2318](https://github.com/meetecho/janus-gateway/issues/2318)]
- Fixed missing PLI when switching Streaming mountpoint [[Issue-2333](https://github.com/meetecho/janus-gateway/issues/2333)]
- Fixed broken recordings in VideoCall plugin (thanks @SamyCookie!) [[PR-2325](https://github.com/meetecho/janus-gateway/pull/2325)]
- Fixed "kick" not working in TextRoom plugin (thanks @backface!) [[PR-2332](https://github.com/meetecho/janus-gateway/pull/2332)]
- Fixed occasional post-processing issues with incomplete mjr files (thanks @SamyCookie!) [[PR-2356](https://github.com/meetecho/janus-gateway/pull/2356)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)

## [v0.10.4] - 2020-08-07

- Fixed usrsctp vulnerability by using internal hashmap in SCTP code [[PR-2302](https://github.com/meetecho/janus-gateway/pull/2302)]
- Fixed some issues when using BoringSSL for DTLS (thanks @fancycode!) [[PR-2278](https://github.com/meetecho/janus-gateway/pull/2278)]
- Added support for multiple nat-1-1 addresses (thanks @fancycode!) [[PR-2279](https://github.com/meetecho/janus-gateway/pull/2279)]
- Fixed negotiation issue on Firefox when Janus is built without datachannels [[PR-2281](https://github.com/meetecho/janus-gateway/pull/2281)]
- Fixed small memory leaks when dealing with local candidates (thanks @fancycode!) [[PR-2288](https://github.com/meetecho/janus-gateway/pull/2288)]
- Fixed occasional segfault in VideoRoom when failing to setup a new subscriber [[Issue-2277](https://github.com/meetecho/janus-gateway/issues/2277)]
- Fixed potential deadlock in AudioBridge when switching rooms (thanks @JeckLabs!) [[PR-2280](https://github.com/meetecho/janus-gateway/pull/2280)]
- Fixed small memory leak in AudioBridge (thanks @JeckLabs!) [[PR-2298](https://github.com/meetecho/janus-gateway/pull/2298)]
- Fixed occasional segfault in VideoCall when hanging up calls [[Issue-2300](https://github.com/meetecho/janus-gateway/issues/2300)]
- Fixed occasional curl hiccups with RTSP on some cameras
- Added reconnect mechanism to RabbitMQ event handler (thanks @david-goncalves!) [[PR-2267](https://github.com/meetecho/janus-gateway/pull/2267)]
- Extended MQTT support in transport and event handler to v5 (thanks @feymartynov!) [[PR-2273](https://github.com/meetecho/janus-gateway/pull/2273)]
- Added settings to configure MQTT buffers in the transport plugin (thanks @feymartynov!) [[PR-2286](https://github.com/meetecho/janus-gateway/pull/2286)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.10.3] - 2020-07-09

- Fixed occasional crashes in VideoRoom related to subscribers activity [[PR-2236](https://github.com/meetecho/janus-gateway/pull/2236)] [[PR-2253](https://github.com/meetecho/janus-gateway/pull/2253)]
- Fixed AudioBridge compilation issues when libogg is missing (thanks @ffontaine!) [[PR-2238](https://github.com/meetecho/janus-gateway/pull/2238)]
- Fixed broken SRTP forwarders in AudioBridge [[PR-2258](https://github.com/meetecho/janus-gateway/pull/2258)]
- Fixed occasional segfaults due to race conditions in SIP plugin [[PR-2247](https://github.com/meetecho/janus-gateway/pull/2247)]
- Fixed occasional recording issues in Janus and Duktape plugins
- Added timeout (120s) on idle connections in HTTP transport
- Fixed Opus recordings occasionally being way too large than the source file when processed via janus-pp-rec (thanks @neilkinnish!) [[PR-2250](https://github.com/meetecho/janus-gateway/pull/2250)]
- Added a new web demo to use canvas elements as a media source for PeerConnections [[PR-2261](https://github.com/meetecho/janus-gateway/pull/2261)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.10.2] - 2020-06-17

- Fixed sscanf-related security issues [[PR-2229](https://github.com/meetecho/janus-gateway/pull/2229)]
- Fixed some RTP extensions not working after renegotiations [[Issue-2192](https://github.com/meetecho/janus-gateway/issues/2192)]
- Fixed occasionally broken simulcast behaviour [[PR-2231](https://github.com/meetecho/janus-gateway/pull/2231)]
- Fixed "switch" request not taking simulcast/SVC into account in VideoRoom and Streaming plugins [[Issue-2219](https://github.com/meetecho/janus-gateway/issues/2219)]
- Fixed inability to ask for random ports when creating Streaming plugin mountpoints with simulcast support [[PR-2225](https://github.com/meetecho/janus-gateway/pull/2225)]
- Fixed occasional crashes in SIP plugin when using helpers [[PR-2216](https://github.com/meetecho/janus-gateway/pull/2216)]
- Updated Duktape dependencies to v2.5, and fixed Duktape plugin relaying text data as binary [[PR-2233](https://github.com/meetecho/janus-gateway/pull/2233)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.10.1] - 2020-06-11

- Added initial support for AV1 and H.265 video codecs [[PR-2120](https://github.com/meetecho/janus-gateway/pull/2120)]
- Added initial support for end-to-end encryption via Insertable Streams [[PR-2074](https://github.com/meetecho/janus-gateway/pull/2074)]
- Fixed security issues when processing SDPs [[PR-2214](https://github.com/meetecho/janus-gateway/pull/2214)]
- Fixed occasional codec profile negotiation issues (thanks @groupboard!) [[PR-2212](https://github.com/meetecho/janus-gateway/pull/2212)]
- Fixed occasional segfaults when hanging up VideoRoom subscribers
- Fixed RTSP issues when fmtp is missing (thanks @lionelnicolas!) [[PR-2190](https://github.com/meetecho/janus-gateway/pull/2190)]
- Fixed RTSP not following redirects, when used (thanks @lionelnicolas!) [[PR-2195](https://github.com/meetecho/janus-gateway/pull/2195)]
- Fixed SRTP-SDES and renegotiation issues in NoSIP plugin (thanks @ihusejnovic!) [[PR-2196](https://github.com/meetecho/janus-gateway/pull/2196)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.10.0] - 2020-06-01

- Added support for negotiation of codec profiles (mainly VP9 and H.264) [[PR-2080](https://github.com/meetecho/janus-gateway/pull/2080)]
- Added new callback to let plugins know when the datachannel first becomes available, and then any time it's writable (empty buffers) [[PR-2060](https://github.com/meetecho/janus-gateway/pull/2060)]
- Added support for data channel subprotocols [[PR-2157](https://github.com/meetecho/janus-gateway/pull/2157)]
- Added new event handler for GrayLog using GELF (thanks @mirkobrankovic!) [[PR-1788](https://github.com/meetecho/janus-gateway/pull/1788)]
- Added per-user override of global room 'audio_active_packets' and 'audio_level_average' properties to AudioBridge and VideoRoom (thanks @mirkobrankovic!) [[PR-2158](https://github.com/meetecho/janus-gateway/pull/2158)]
- Notify speaker that started/stopped talking too, when talking events are triggered in VideoRoom and AudioBridge (thanks @maxboehm!) [[PR-2172](https://github.com/meetecho/janus-gateway/pull/2172)]
- Allow listing of private rooms/mountpoints if an admin_key is used (thanks @robby2016!) [[PR-2161](https://github.com/meetecho/janus-gateway/pull/2161)]
- Fixed RTCP support not triggering PLIs for new simulcast mountpoint viewers [[Issue-2156](https://github.com/meetecho/janus-gateway/issues/2156)]
- Fixed occasional issue binding multicast mountpoints (thanks @PaulKerr!) [[PR-2167](https://github.com/meetecho/janus-gateway/pull/2167)]
- Fixed buffering of keyframes not working in Streaming plugin (thanks @TomFFF!) [[PR-2170](https://github.com/meetecho/janus-gateway/pull/2170)]
- Added support for buffering of keyframes to RTSP mountpoints too (thanks @lionelnicolas!) [[PR-2180](https://github.com/meetecho/janus-gateway/pull/2180)]
- Fixed renegotiation support in SIP plugin when audio/video is added (thanks @ihusejnovic!) [[PR-2164](https://github.com/meetecho/janus-gateway/pull/2164)] [[PR-2173](https://github.com/meetecho/janus-gateway/pull/2173)]
- Fixed menus in html documentation when using Doxygen >= 1.8.14 (thanks @i8-pi!) [[PR-2155](https://github.com/meetecho/janus-gateway/pull/2155)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.9.5] - 2020-05-18

- Fixed sessions not being cleaned up when disabling session timeouts and the transport disconnects (thanks @nicolasduteil!) [[PR-2143](https://github.com/meetecho/janus-gateway/pull/2143)]
- Added option to keep candidates with private host addresses when using nat-1-1, and advertize them too instead of just replacing them
- Added auth token, if available, to 'attached' event (handlers) and to Admin API (handle_info)
- Added new API to start/stop recording a VideoRoom as a whole, and a new option to prevent participants from starting/stopping their own recording (thanks @wheresjames!) [[PR-2137](https://github.com/meetecho/janus-gateway/pull/2137)]
- Fixed rare deadlock when wrapping up Streaming plugin mountpoints [[PR-2141](https://github.com/meetecho/janus-gateway/pull/2141)]
- Fixed rare deadlock when destroying AudioBridge rooms
- Added synchronous request to check if an announcement is playing in the AudioBridge
- Fixed AudioBridge announcement not waking up sleeping forwarder
- Added global room mute/unmute support to AudioBridge
- Added configurable DSCP support for outgoing RTP packets to SIP and NoSIP plugins (thanks @GerardM22!) [[PR-2150](https://github.com/meetecho/janus-gateway/pull/2150)]
- Added support for RTP extensions (audio-level, video-orientation) to NoSIP plugin [[Issue-2152](https://github.com/meetecho/janus-gateway/issues/2152)]
- Added option to configure ciphers suite for secure WebSockets (thanks @agclark81!) [[PR-2135](https://github.com/meetecho/janus-gateway/pull/2135)]
- Added timer to janus.js to avoid spamming onmute/onunmute events and flashing videos [[PR-2147](https://github.com/meetecho/janus-gateway/pull/2147)]
- Added a new tool to convert .pcap captures to .mjr recordings [[PR-2144](https://github.com/meetecho/janus-gateway/pull/2144)]
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.9.4] - 2020-05-04

- Updated code not to wait forever for local candidates when half-trickling and sending an SDP out
- Fixed occasional CPU spiking issues when dealing with ICE failures (thanks @sjkummer!)
- Fixed occasional stall when gathering ICE candidates (thanks @wheresjames!)
- Fixed the incorrect value being set via DSCP, when configured
- Fixed occasional race condition when hanging up VideoRoom subscribers
- Fixed Audiobridge and Streaming plugins not playing the last chunk of .opus files (thanks @RSATom!)
- Fixed duplicate subscriptions (and SRTP/SRTCP errors) on multiple watch requests in Streaming plugin
- Updated Streaming and TextRoom plugins to stop using legacy datachannel negotiation
- Fixed occasional crash in HTTP transport when dealing with unknown requests
- Fixed occasional disconnect in WebSockets (thanks @tomnotcat!)
- Made RabbitMQ exchange type configurable in both transport and event handler (thanks @voicenter!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.9.3] - 2020-04-22

- Change libsrtp detection in the configure script to use pkg-config
- Fixed compilation error with gcc10
- Fixed RTCP issue that could occasionally lead to broken retransmissions when using rtx
- Added option to specify DSCP Type of Service (ToS) for media streams
- Fixed a couple of race conditions during renegotiations
- Fixed VideoRoom and Streaming "destroy" not working properly when using string IDs
- Fix occasional segfault in VideoRoom (thanks @cb22!)
- Fixed AudioBridge "create" not working properly when using string IDs
- Added support for playing Opus files in AudioBridge rooms
- Added support to Opus files for file-based mountpoints in Streaming plugin
- Added support for generic metadata to Streaming mountpoints
- Streaming plugin now returns mountpoint IP address(es) in "create" and "info", when binding to specific IP/interface
- Fixed occasional segfault when using helper threads in Streaming plugin
- Fixed occasional race conditions in HTTP transport
- Added support for specifying screensharing framerate in janus.js (thanks @agclark81!)
- Cleaned up code in janus.js (thanks @alienpavlov!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.9.2] - 2020-03-26

- Converted HTTP transport plugin to single thread (now requires libmicrohttpd >= 0.9.59)
- Fixed .deb file packaging (thanks @FThrum!)
- Added foundation for aiortc-based functional testing (python)
- Fixed occasional audio/video desync
- Added asynchronous resolution of mDNS candidates, and an option to automatically ignore them entirely
- Updated default DTLS ciphers (thanks @fippo!)
- Added option to generate ECDSA certificates at startup, instead of RSA (thanks @Sean-Der!)
- Fixed rare race condition when claiming sessions
- Fixed rare crash in ice.c (thanks @tmatth!)
- Fixed dangerous typo in querylogger_parameters (copy/paste error)
- Fixed occasional deadlocks in VideoRoom (thanks @mivuDing and @agclark81!)
- Added support for RTSP Content-Base header to Streaming plugin
- Fixed double unlock when listing private rooms in AudioBridge
- Made AudioBridge prebuffering property configurable, both per-room and per-participant
- Added G.711 support to AudioBridge (both participants and RTP forwarders)
- Added called URI to 'incomingcall' and 'missed_call' events in SIP plugin (in case the registered user is associated with multiple public URIs)
- Fixed race conditions and leaks in VideoCall and VoiceMail plugins
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.9.1] - 2020-03-10

- Added configurable global prefix for log lines
- Implemented better management of remote candidates with invalid addresses
- Added subtype property to differentiate some macro-types in event handlers
- Improved detection of H.264 keyframes (thanks @cameronlucas3!)
- Added configurable support for strings as unique IDs in AudioBridge, VideoRoom, TextRoom and Streaming plugins
- Fixed small memory leak when creating Streaming mountpoints dynamically
- Fixed segfault when trying to start a SIP call with a non-existing refer_id (thanks @tmatth!)
- Fixed errors negotiating video in SIP plugin when multiple video profiles are provided
- Updated SIP plugin transfer code to answer with a 202 right away, instead of sending a 100 first (which won't work with proxies)
- Added several features and fixes several nits in SIP demo UI
- Fixed janus.js error callback not being invoked when an HTTP error happens trying to attach to a plugin (thanks @hxl-dy!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


## [v0.9.0] - 2020-02-21

- Refactored core-plugin callbacks
- Added RTP extensions termination
- Removed requirement to enable ICE Lite to use ICE-TCP, even though it may cause issues (thanks @sjkummer!)
- Added support for transport-wide CC on outgoing streams (feedback still unused, though)
- Dynamically update NACK queue size depending on RTT
- Fixed risk of RTP header memory misalignment when dealing with rtx packets
- Users muted in AudioBridge by an admin are now notified as well (thanks @klanjabrik!)
- Other smaller fixes and improvements (thanks to all who contributed pull requests and reported issues!)


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
- Fixed occasional crashes when saving .jcfg files (e.g., saving permanent Streaming mountpoints)
- Added new Admin API command to temporarily stop/resume accepting sessions (e.g., for draining servers)
- Fixed recordings sometimes not closed/destroyed/renamed when hanging up SIP sessions
- Added option to SIP/SIPre/NoSIP plugin to override c= IP in SDP
- Fixed missing RTSP support in Streaming plugin if TURN REST API was disabled in configure
- Fixed Streaming plugin not returning complete information on secret-less mountpoints (thanks @Musashi178!)
- Fixed missing .jcfg support in Duktape plugin (thanks @fbertone!)
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
