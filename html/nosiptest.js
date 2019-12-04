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

var spinner = null;

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
												// No media provided: by default, it's sendrecv for audio and video
												success: function(jsep) {
													Janus.debug("[caller] Got SDP!");
													Janus.debug(jsep);
													// We now have a WebRTC SDP: to get a barebone SDP legacy
													// peers can digest, we ask the NoSIP plugin to generate
													// an offer for us. For the sake of simplicity, no SRTP:
													// if you need SRTP support, you can use the same syntax
													// the SIP plugin uses (mandatory vs. optional). We'll
													// get the result in an event called "generated" here.
													var body = {
														request: "generate"
													};
													caller.send({message: body, jsep: jsep});
												},
												error: function(error) {
													Janus.error("WebRTC error:", error);
													bootbox.alert("WebRTC error... " + JSON.stringify(error));
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
								mediaState: function(medium, on) {
									Janus.log("[caller] Janus " + (on ? "started" : "stopped") + " receiving our " + medium);
								},
								webrtcState: function(on) {
									Janus.log("[caller] Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
								},
								slowLink: function(uplink, lost) {
									Janus.warn("[caller] Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on this PeerConnection (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug("[caller]  ::: Got a message :::");
									Janus.debug(msg);
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
												update: result["update"]
											}
											callee.send({message: processOffer});
										} else if(event === "processed") {
											// As a caller, this means the remote, barebone SDP answer
											// we got from the legacy peer has been turned into a full
											// WebRTC SDP answer we can consume here, let's do that
											if(jsep) {
												Janus.debug("[caller] Handling SDP as well...");
												Janus.debug(jsep);
												caller.handleRemoteJsep({jsep: jsep});
											}
										}
									}
								},
								onlocalstream: function(stream) {
									Janus.debug("[caller]  ::: Got a local stream :::");
									Janus.debug(stream);
									$('#videos').removeClass('hide').show();
									if($('#myvideo').length === 0)
										$('#videoleft').append('<video class="rounded centered" id="myvideo" width=320 height=240 autoplay playsinline muted="muted"/>');
									Janus.attachMediaStream($('#myvideo').get(0), stream);
									$("#myvideo").get(0).muted = "muted";
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
										// No remote video yet
										$('#videoright').append('<video class="rounded centered" id="waitingvideo" width=320 height=240 />');
										if(spinner == null) {
											var target = document.getElementById('videoright');
											spinner = new Spinner({top:100}).spin(target);
										} else {
											spinner.spin();
										}
									}
									var videoTracks = stream.getVideoTracks();
									if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
										// No webcam
										$('#myvideo').hide();
										if($('#videoleft .no-video-container').length === 0) {
											$('#videoleft').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
													'<span class="no-video-text">No webcam available</span>' +
												'</div>');
										}
									} else {
										$('#videoleft .no-video-container').remove();
										$('#myvideo').removeClass('hide').show();
									}
								},
								onremotestream: function(stream) {
									Janus.debug("[caller]  ::: Got a remote stream :::");
									Janus.debug(stream);
									if($('#peervideo').length === 0) {
										$('#videoright').parent().find('h3').html(
											'Send DTMF: <span id="dtmf" class="btn-group btn-group-xs"></span>');
										$('#videoright').append(
											'<video class="rounded centered hide" id="peervideo" width=320 height=240 autoplay playsinline/>');
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
											// Notice you can also send DTMF tones using SIP INFO
											// 		caller.send({message: {request: "dtmf_info", digit: $(this).text()}});
										});
										// Show the peer and hide the spinner when we get a playing event
										$("#peervideo").bind("playing", function () {
											$('#waitingvideo').remove();
											if(this.videoWidth)
												$('#peervideo').removeClass('hide').show();
											if(spinner !== null && spinner !== undefined)
												spinner.stop();
											spinner = null;
										});
									}
									Janus.attachMediaStream($('#peervideo').get(0), stream);
									var videoTracks = stream.getVideoTracks();
									if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
										// No remote video
										$('#peervideo').hide();
										if($('#videoright .no-video-container').length === 0) {
											$('#videoright').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
													'<span class="no-video-text">No remote video available</span>' +
												'</div>');
										}
									} else {
										$('#videoright .no-video-container').remove();
										$('#peervideo').removeClass('hide').show();
									}
								},
								oncleanup: function() {
									Janus.log("[caller]  ::: Got a cleanup notification :::");
									if(spinner !== null && spinner !== undefined)
										spinner.stop();
									spinner = null;
									$('#myvideo').remove();
									$('#waitingvideo').remove();
									$("#videoleft").parent().unblock();
									$('#peervideo').remove();
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
								mediaState: function(medium, on) {
									Janus.log("[callee] Janus " + (on ? "started" : "stopped") + " receiving our " + medium);
								},
								webrtcState: function(on) {
									Janus.log("[callee] Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
								},
								slowLink: function(uplink, lost) {
									Janus.warn("[callee] Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on this PeerConnection (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug("[callee]  ::: Got a message :::");
									Janus.debug(msg);
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
														Janus.debug("[callee] Got SDP!");
														Janus.debug(jsep);
														// We now have a WebRTC SDP: to get a barebone SDP legacy
														// peers can digest, we ask the NoSIP plugin to generate
														// an answer for us, just as we did for the caller's offer.
														// We'll get the result in an event called "generated" here.
														var body = {
															request: "generate",
															update: update
														};
														callee.send({message: body, jsep: jsep});
													},
													error: function(error) {
														Janus.error("WebRTC error:", error);
														bootbox.alert("WebRTC error... " + JSON.stringify(error));
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
												update: result["update"]
											}
											caller.send({message: processAnswer});
										}
									}
								},
								onlocalstream: function(stream) {
									// The callee is our fake peer, we don't display anything
								},
								onremotestream: function(stream) {
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
