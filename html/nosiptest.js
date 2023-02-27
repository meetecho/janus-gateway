// We import the settings.js file to know which address we should contact
// to talk to Janus, and optionally which STUN/TURN servers should be
// used as well. Specifically, that file defines the "server" and
// "iceServers" properties we'll pass when creating the Janus session.

/* global iceServers:readonly, Janus:readonly, server:readonly */

var janus = null;

// We'll need two handles for this demo: a caller and a callee
var caller = null, callee = null;
var opaqueId = Janus.randomString(12);
// The local and remote tracks only refer to the caller, though (we ignore the callee)
var localTracks = {}, localVideos = 0,
	remoteTracks = {}, remoteVideos = 0;
var spinner = null;

var callstarted = false, videoenabled = true;
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
					iceServers: iceServers,
					// Should the Janus API require authentication, you can specify either the API secret or user token here too
					//		token: "mytoken",
					//	or
					//		apisecret: "serversecret",
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
										// We want bidirectional audio and video by default
										caller.createOffer(
											{
												tracks: [
													{ type: 'audio', capture: true, recv: true },
													{ type: 'video', capture: true, recv: true }
												],
												success: function(jsep) {
													Janus.debug("[caller] Got SDP!", jsep);
													// We now have a WebRTC SDP: to get a barebone SDP legacy
													// peers can digest, we ask the NoSIP plugin to generate
													// an offer for us. For the sake of simplicity, no SRTP:
													// if you need SRTP support, you can use the same syntax
													// the SIP plugin uses (mandatory vs. optional). We'll
													// get the result in an event called "generated" here.
													let body = {
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
								mediaState: function(medium, on, mid) {
									Janus.log("[caller] Janus " + (on ? "started" : "stopped") + " receiving our " + medium + " (mid=" + mid + ")");
								},
								webrtcState: function(on) {
									Janus.log("[caller] Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
									if(on) {
										callstarted = true;
										$('#togglevideo').removeAttr('disabled').click(renegotiateVideo);
									}
								},
								slowLink: function(uplink, lost, mid) {
									Janus.warn("[caller] Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on mid " + mid + " (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug("[caller]  ::: Got a message :::", msg);
									// Any error?
									let error = msg["error"];
									if(error) {
										bootbox.alert(error);
										caller.hangup();
										return;
									}
									let result = msg["result"];
									if(result) {
										let event = result["event"];
										if(event === "generated") {
											// We got the barebone SDP offer we wanted, let's have
											// the callee handle it as if it arrived via signalling
											let sdp = result["sdp"];
											$('#localsdp').text(
												"[" + result["type"] + "]\n" + sdp);
											// This will result in a "processed" event on the callee handle
											let processOffer = {
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
												// If this was a renegotiation, update the button
												if(callstarted) {
													$('#togglevideo')
														.text(videoenabled ? 'Disable video' : 'Enable video')
														.removeAttr('disabled');
												}
											}
										}
									}
								},
								onlocaltrack: function(track, on) {
									Janus.debug("Local track " + (on ? "added" : "removed") + ":", track);
									// We use the track ID as name of the element, but it may contain invalid characters
									let trackId = track.id.replace(/[{}]/g, "");
									if(!on) {
										// Track removed, get rid of the stream and the rendering
										let stream = localTracks[trackId];
										if(stream) {
											try {
												let tracks = stream.getTracks();
												for(let i in tracks) {
													let mst = tracks[i];
													if(mst)
														mst.stop();
												}
											} catch(e) {}
										}
										if(track.kind === "video") {
											$('#myvideot' + trackId).remove();
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
									let stream = localTracks[trackId];
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
										let stream = new MediaStream([track]);
										localTracks[trackId] = stream;
										Janus.log("Created local stream:", stream);
										$('#videoleft').append('<video class="rounded centered" id="myvideot' + trackId + '" width="100%" height="100%" autoplay playsinline muted="muted"/>');
										Janus.attachMediaStream($('#myvideot' + trackId).get(0), stream);
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
									if($('#peervideo' + mid).length > 0)
										return;
									// If we're here, a new track was added
									if($('#videoright audio').length === 0 && $('#videoright video').length === 0) {
										$('#videos').removeClass('hide').show();
										$('#videoright').parent().find('h3').html(
											'Send DTMF: <span id="dtmf" class="btn-group btn-group-xs"></span>');
										for(let i=0; i<12; i++) {
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
										let stream = new MediaStream([track]);
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
										let stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("[caller] Created remote video stream:", stream);
										$('#videoright').append('<video class="rounded centered" id="peervideo' + mid + '" width="100%" height="100%" autoplay playsinline/>');
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
								mediaState: function(medium, on, mid) {
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
									let error = msg["error"];
									if(error) {
										bootbox.alert(error);
										callee.hangup();
										return;
									}
									let result = msg["result"];
									if(result) {
										let event = result["event"];
										if(event === "processed") {
											// Since we're a callee, this means that the barebone SDP offer
											// the caller gave us (and that we assumed had been sent via
											// signalling)has been processed, and we got a JSEP SDP to process:
											// we need to come up with our own answer now, so let's do that
											Janus.debug("[callee] Trying a createAnswer too (audio/video sendrecv)");
											let update = result["update"];
											callee.createAnswer(
												{
													// This is the WebRTC enriched offer the plugin gave us
													jsep: jsep,
													// We want bidirectional audio and video, if offered
													tracks: [
														{ type: 'audio', capture: true, recv: true },
														{ type: 'video', capture: true, recv: true }
													],
													success: function(jsep) {
														Janus.debug("[callee] Got SDP!", jsep);
														// We now have a WebRTC SDP: to get a barebone SDP legacy
														// peers can digest, we ask the NoSIP plugin to generate
														// an answer for us, just as we did for the caller's offer.
														// We'll get the result in an event called "generated" here.
														let body = {
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
											let sdp = result["sdp"];
											$('#remotesdp').text(
												"[" + result["type"] + "]\n" + sdp);
											// This will result in a "processed" event on the caller handle
											let processAnswer = {
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
								// eslint-disable-next-line no-unused-vars
								onlocaltrack: function(track, on) {
									// The callee is our fake peer, we don't display anything
								},
								// eslint-disable-next-line no-unused-vars
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

// We use this helper function to remove/add video to the call
function renegotiateVideo() {
	$('#togglevideo').attr('disabled', true);
	let modifiedTrack = null;
	if(videoenabled) {
		// Renegotiate the call removing local video
		videoenabled = false;
		// We only want to modify the video track, removing our own
		modifiedTrack = [{ type: 'video', mid: '1', remove: true }]
	} else {
		// Renegotiate the call removing local video
		videoenabled = true;
		// We only want to modify the video track, adding our own
		modifiedTrack = [{ type: 'video', mid: '1', replace: true, capture: true }]
	}
	// Create an updated offer
	caller.createOffer(
		{
			tracks: modifiedTrack,
			success: function(jsep) {
				Janus.debug("[caller] Got SDP!", jsep);
				// As before, we ask the NoSIP plugin to generate a
				// plain SDP we can then pass to the callee handle
				let body = {
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
}
