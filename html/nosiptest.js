// We make use of this 'server' variable to provide the address of the
// REST Janus API. By default, in this example we assume that Janus is
// co-located with the web server hosting the HTML pages but listening
// on a different port (8088, the default for HTTP in Janus), which is
// why we make use of the 'window.location.hostname' base address. Since
// Janus can also do HTTPS, and considering we don't really want to make
// use of HTTP for Janus if your demos are served on HTTPS, we also rely
// on the 'window.location.protocol' prefix to build the variable, in
// particular to also change the port used to contact Janus (8088 for
// HTTP and 8089 for HTTPS, if enabled).
// In case you place Janus behind an Apache frontend (as we did on the
// online demos at http://janus.conf.meetecho.com) you can just use a
// relative path for the variable, e.g.:
//
// 		var server = "/janus";
//
// which will take care of this on its own.
//
//
// If you want to use the WebSockets frontend to Janus, instead, you'll
// have to pass a different kind of address, e.g.:
//
// 		var server = "ws://" + window.location.hostname + ":8188";
//
// Of course this assumes that support for WebSockets has been built in
// when compiling the server. WebSockets support has not been tested
// as much as the REST API, so handle with care!
//
//
// If you have multiple options available, and want to let the library
// autodetect the best way to contact your server (or pool of servers),
// you can also pass an array of servers, e.g., to provide alternative
// means of access (e.g., try WebSockets first and, if that fails, fall
// back to plain HTTP) or just have failover servers:
//
//		var server = [
//			"ws://" + window.location.hostname + ":8188",
//			"/janus"
//		];
//
// This will tell the library to try connecting to each of the servers
// in the presented order. The first working server will be used for
// the whole session.
//
var server = null;
if(window.location.protocol === 'http:')
	server = "http://" + window.location.hostname + ":8088/janus";
else
	server = "https://" + window.location.hostname + ":8089/janus";

var janus = null;

// We'll need two handles for this demo: a caller and a callee
var caller = null, callee = null;
var opaqueId = Janus.randomString(12);
// The local and remote tracks only refer to the caller, though (we ignore the callee)
var localTracks = {}, localVideos = 0,
	remoteTracks = {}, remoteVideos = 0;
var spinner = null;

var videoenabled = true;
var srtp = undefined ; // use "sdes_mandatory" to test SRTP-SDES

$(document).ready(function() {
	// Initialize the library (all console debuggers enabled)
	Janus.init({debug: "all", callback: function() {
		// Use a button to start the demo
		$('#start').one('click', function() {
			$(this).attr('disabled', true).unbind('click');
			// Make sure the browser supports WebRTC
			if(!Janus.isWebrtcSupported()) {
				bootbox.alert("No WebRTC support... ");
				return;
			}
			// Create session
			janus = new Janus(
				{
					server: server,
					success: function() {
						// Attach to NoSIP plugin as a caller
						janus.attach(
							{
								plugin: "janus.plugin.nosip",
								opaqueId: "nosiptest-caller-"+opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									caller = pluginHandle;
									Janus.log("[caller] Plugin attached! (" + caller.getPlugin() + ", id=" + caller.getId() + ")");
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											janus.destroy();
										});
									// Negotiate WebRTC in a second (just to make sure both caller and callee handles exist)
									setTimeout(function() {
										Janus.debug("[caller] Trying a createOffer too (audio/video sendrecv)");
										caller.createOffer(
											{
												media: {audio: true, video: videoenabled},
												success: function(jsep) {
													Janus.debug("[caller] Got SDP!", jsep);
													// We now have a WebRTC SDP: to get a barebone SDP legacy
													// peers can digest, we ask the NoSIP plugin to generate
													// an offer for us. For the sake of simplicity, no SRTP:
													// if you need SRTP support, you can use the same syntax
													// the SIP plugin uses (mandatory vs. optional). We'll
													// get the result in an event called "generated" here.
													var body = {
														request: "generate",
														srtp: srtp
													};
													caller.send({ message: body, jsep: jsep });
												},
												error: function(error) {
													Janus.error("WebRTC error:", error);
													bootbox.alert("WebRTC error... " + error.message);
												}
											});
									}, 1000);
								},
								error: function(error) {
									console.error("[caller]   -- Error attaching plugin...", error);
									bootbox.alert("[caller] Error attaching plugin... " + error);
								},
								consentDialog: function(on) {
									Janus.debug("[caller] Consent dialog should be " + (on ? "on" : "off") + " now");
									if(on) {
										// Darken screen and show hint
										$.blockUI({
											message: '<div><img src="up_arrow.png"/></div>',
											css: {
												border: 'none',
												padding: '15px',
												backgroundColor: 'transparent',
												color: '#aaa',
												top: '10px',
												left: (navigator.mozGetUserMedia ? '-100px' : '300px')
											} });
									} else {
										// Restore screen
										$.unblockUI();
									}
								},
								iceState: function(state) {
									Janus.log("[caller] ICE state changed to " + state);
								},
								mediaState: function(medium, mid, on) {
									Janus.log("[caller] Janus " + (on ? "started" : "stopped") + " receiving our " + medium + " (mid=" + mid + ")");
								},
								webrtcState: function(on) {
									Janus.log("[caller] Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
								},
								slowLink: function(uplink, lost, mid) {
									Janus.warn("[caller] Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on mid " + mid + " (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug("[caller]  ::: Got a message :::", msg);
									// Any error?
									var error = msg["error"];
									if(error) {
										bootbox.alert(error);
										caller.hangup();
										return;
									}
									var result = msg["result"];
									if(result) {
										var event = result["event"];
										if(event === "generated") {
											// We got the barebone SDP offer we wanted, let's have
											// the callee handle it as if it arrived via signalling
											var sdp = result["sdp"];
											$('#localsdp').text(
												"[" + result["type"] + "]\n" + sdp);
											// This will result in a "processed" event on the callee handle
											var processOffer = {
												request: "process",
												type: result["type"],
												sdp: result["sdp"],
												update: result["update"],
												srtp: srtp
											}
											callee.send({ message: processOffer });
										} else if(event === "processed") {
											// As a caller, this means the remote, barebone SDP answer
											// we got from the legacy peer has been turned into a full
											// WebRTC SDP answer we can consume here, let's do that
											if(jsep) {
												Janus.debug("[caller] Handling SDP as well...", jsep);
												caller.handleRemoteJsep({ jsep: jsep });
											}
										}
									}
								},
								onlocaltrack: function(track, on) {
									Janus.debug("[caller] Local track " + (on ? "added" : "removed") + ":", track);
									// We use the track ID as name of the element, but it may contain invalid characters
									var trackId = track.id.replace(/[{}]/g, "");
									if(!on) {
										// Track removed, get rid of the stream and the rendering
										var stream = localTracks[trackId];
										if(stream) {
											try {
												var tracks = stream.getTracks();
												for(var i in tracks) {
													var mst = tracks[i];
													if(mst)
														mst.stop();
												}
											} catch(e) {}
										}
										if(track.kind === "video") {
											$('#myvideo' + trackId).remove();
											localVideos--;
											if(localVideos === 0) {
												// No video, at least for now: show a placeholder
												if($('#videoleft .no-video-container').length === 0) {
													$('#videoleft').append(
														'<div class="no-video-container">' +
															'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
															'<span class="no-video-text">No webcam available</span>' +
														'</div>');
												}
											}
										}
										delete localTracks[trackId];
										return;
									}
									// If we're here, a new track was added
									var stream = localTracks[trackId];
									if(stream) {
										// We've been here already
										return;
									}
									if($('#videoleft video').length === 0) {
										$('#videos').removeClass('hide').show();
									}
									if(track.kind === "audio") {
										// We ignore local audio tracks, they'd generate echo anyway
										if(localVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videoleft .no-video-container').length === 0) {
												$('#videoleft').append(
													'<div class="no-video-container">' +
														'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
														'<span class="no-video-text">No webcam available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										localVideos++;
										$('#videoleft .no-video-container').remove();
										stream = new MediaStream();
										stream.addTrack(track.clone());
										localTracks[trackId] = stream;
										Janus.log("[caller] Created local stream:", stream);
										$('#videoleft').append('<video class="rounded centered" id="myvideo' + trackId + '" width=320 height=240 autoplay playsinline muted="muted"/>');
										Janus.attachMediaStream($('#myvideo' + trackId).get(0), stream);
									}
									if(caller.webrtcStuff.pc.iceConnectionState !== "completed" &&
											caller.webrtcStuff.pc.iceConnectionState !== "connected") {
										$("#videoleft").parent().block({
											message: '<b>Calling...</b>',
											css: {
												border: 'none',
												backgroundColor: 'transparent',
												color: 'white'
											}
										});
									}
								},
								onremotetrack: function(track, mid, on) {
									Janus.debug("[caller] Remote track (mid=" + mid + ") " + (on ? "added" : "removed") + ":", track);
									if(!on) {
										// Track removed, get rid of the stream and the rendering
										var stream = remoteTracks[mid];
										if(stream) {
											try {
												var tracks = stream.getTracks();
												for(var i in tracks) {
													var mst = tracks[i];
													if(mst)
														mst.stop();
												}
											} catch(e) {}
										}
										$('#peervideo' + mid).remove();
										if(track.kind === "video") {
											remoteVideos--;
											if(remoteVideos === 0) {
												// No video, at least for now: show a placeholder
												if($('#videoright .no-video-container').length === 0) {
													$('#videoright').append(
														'<div class="no-video-container">' +
															'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
															'<span class="no-video-text">No remote video available</span>' +
														'</div>');
												}
											}
										}
										delete remoteTracks[mid];
										return;
									}
									// If we're here, a new track was added
									if($('#videoright audio').length === 0 && $('#videoright video').length === 0) {
										$('#videos').removeClass('hide').show();
										$('#videoright').parent().find('h3').html(
											'Send DTMF: <span id="dtmf" class="btn-group btn-group-xs"></span>');
										for(var i=0; i<12; i++) {
											if(i<10)
												$('#dtmf').append('<button class="btn btn-info dtmf">' + i + '</button>');
											else if(i == 10)
												$('#dtmf').append('<button class="btn btn-info dtmf">#</button>');
											else if(i == 11)
												$('#dtmf').append('<button class="btn btn-info dtmf">*</button>');
										}
										$('.dtmf').click(function() {
											// Send DTMF tone (inband)
											caller.dtmf({dtmf: { tones: $(this).text()}});
										});
									}
									if(track.kind === "audio") {
										// New audio track: create a stream out of it, and use a hidden <audio> element
										stream = new MediaStream();
										stream.addTrack(track.clone());
										remoteTracks[mid] = stream;
										Janus.log("[caller] Created remote audio stream:", stream);
										$('#videoright').append('<audio class="hide" id="peervideo' + mid + '" autoplay playsinline/>');
										Janus.attachMediaStream($('#peervideo' + mid).get(0), stream);
										if(remoteVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videoright .no-video-container').length === 0) {
												$('#videoright').append(
													'<div class="no-video-container">' +
														'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
														'<span class="no-video-text">No remote video available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										remoteVideos++;
										$('#videoright .no-video-container').remove();
										stream = new MediaStream();
										stream.addTrack(track.clone());
										remoteTracks[mid] = stream;
										Janus.log("[caller] Created remote video stream:", stream);
										$('#videoright').append('<video class="rounded centered" id="peervideo' + mid + '" width=320 height=240 autoplay playsinline/>');
										Janus.attachMediaStream($('#peervideo' + mid).get(0), stream);
									}
								},
								oncleanup: function() {
									Janus.log("[caller]  ::: Got a cleanup notification :::");
									if(spinner)
										spinner.stop();
									spinner = null;
									$("#videoleft").empty().parent().unblock();
									$('#videoright').empty();
									$('#dtmf').parent().html("Remote UA");
									localTracks = {};
									localVideos = 0;
									remoteTracks = {};
									remoteVideos = 0;
								}
							});
						// Attach to NoSIP plugin as a callee
						janus.attach(
							{
								plugin: "janus.plugin.nosip",
								opaqueId: "nosiptest-callee-"+opaqueId,
								success: function(pluginHandle) {
									callee = pluginHandle;
									Janus.log("[callee] Plugin attached! (" + callee.getPlugin() + ", id=" + callee.getId() + ")");
								},
								error: function(error) {
									console.error("[callee]   -- Error attaching plugin...", error);
									bootbox.alert("[callee] Error attaching plugin... " + error);
								},
								consentDialog: function(on) {
									Janus.debug("[callee] Consent dialog should be " + (on ? "on" : "off") + " now");
									if(on) {
										// Darken screen and show hint
										$.blockUI({
											message: '<div><img src="up_arrow.png"/></div>',
											css: {
												border: 'none',
												padding: '15px',
												backgroundColor: 'transparent',
												color: '#aaa',
												top: '10px',
												left: (navigator.mozGetUserMedia ? '-100px' : '300px')
											} });
									} else {
										// Restore screen
										$.unblockUI();
									}
								},
								iceState: function(state) {
									Janus.log("[callee] ICE state changed to " + state);
								},
								mediaState: function(medium, mid, on) {
									Janus.log("[callee] Janus " + (on ? "started" : "stopped") + " receiving our " + medium + " (mid=" + mid + ")");
								},
								webrtcState: function(on) {
									Janus.log("[callee] Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
								},
								slowLink: function(uplink, lost, mid) {
									Janus.warn("[callee] Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on mid " + mid + " (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug("[callee]  ::: Got a message :::", msg);
									// Any error?
									var error = msg["error"];
									if(error) {
										bootbox.alert(error);
										callee.hangup();
										return;
									}
									var result = msg["result"];
									if(result) {
										var event = result["event"];
										if(event === "processed") {
											// Since we're a callee, this means that the barebone SDP offer
											// the caller gave us (and that we assumed had been sent via
											// signalling)has been processed, and we got a JSEP SDP to process:
											// we need to come up with our own answer now, so let's do that
											Janus.debug("[callee] Trying a createAnswer too (audio/video sendrecv)");
											var update = result["update"];
											callee.createAnswer(
												{
													// This is the WebRTC enriched offer the plugin gave us
													jsep: jsep,
													// No media provided: by default, it's sendrecv for audio and video
													success: function(jsep) {
														Janus.debug("[callee] Got SDP!", jsep);
														// We now have a WebRTC SDP: to get a barebone SDP legacy
														// peers can digest, we ask the NoSIP plugin to generate
														// an answer for us, just as we did for the caller's offer.
														// We'll get the result in an event called "generated" here.
														var body = {
															request: "generate",
															update: update,
															srtp: srtp
														};
														callee.send({ message: body, jsep: jsep });
													},
													error: function(error) {
														Janus.error("WebRTC error:", error);
														bootbox.alert("WebRTC error... " + error.message);
													}
												});

										} else if(event === "generated") {
											// As a callee, we get this when our barebone answer has been
											// generated from the original JSEP answer. Let's have
											// the caller handle it as if it arrived via signalling
											var sdp = result["sdp"];
											$('#remotesdp').text(
												"[" + result["type"] + "]\n" + sdp);
											// This will result in a "processed" event on the caller handle
											var processAnswer = {
												request: "process",
												type: result["type"],
												sdp: result["sdp"],
												update: result["update"],
												srtp: srtp
											}
											caller.send({ message: processAnswer });
										}
									}
								},
								onlocaltrack: function(track, on) {
									// The callee is our fake peer, we don't display anything
								},
								onremotetrack: function(track, mid, on) {
									// The callee is our fake peer, we don't display anything
								},
								oncleanup: function() {
									Janus.log("[callee] ::: Got a cleanup notification :::");
								}
							});
					},
					error: function(error) {
						Janus.error(error);
						bootbox.alert(error, function() {
							window.location.reload();
						});
					},
					destroyed: function() {
						window.location.reload();
					}
				});
		});
	}});
});
