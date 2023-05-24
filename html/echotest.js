// We import the settings.js file to know which address we should contact
// to talk to Janus, and optionally which STUN/TURN servers should be
// used as well. Specifically, that file defines the "server" and
// "iceServers" properties we'll pass when creating the Janus session.

/* global iceServers:readonly, Janus:readonly, server:readonly */

var janus = null;
var echotest = null;
var opaqueId = "echotest-"+Janus.randomString(12);

var localTracks = {}, localVideos = 0,
	remoteTracks = {}, remoteVideos = 0;
var bitrateTimer = null;
var spinner = null;

var audioenabled = false;
var videoenabled = false;

var doSimulcast = (getQueryStringValue("simulcast") === "yes" || getQueryStringValue("simulcast") === "true");
var doSvc = getQueryStringValue("svc");
if(doSvc === "")
	doSvc = null;
var acodec = (getQueryStringValue("acodec") !== "" ? getQueryStringValue("acodec") : null);
var vcodec = (getQueryStringValue("vcodec") !== "" ? getQueryStringValue("vcodec") : null);
var vprofile = (getQueryStringValue("vprofile") !== "" ? getQueryStringValue("vprofile") : null);
var stereo = false;
if(getQueryStringValue("stereo") !== "")
	stereo = (getQueryStringValue("stereo") === "true");
var doDtx = (getQueryStringValue("dtx") === "yes" || getQueryStringValue("dtx") === "true");
var doOpusred = (getQueryStringValue("opusred") === "yes" || getQueryStringValue("opusred") === "true");
var simulcastStarted = false, svcStarted = false;

// By default we talk to the "regular" EchoTest plugin
var echotestPluginBackend = "janus.plugin.echotest";
// We can use query string arguments to talk to the Lua or Duktape EchoTest
// demo scripts instead. Notice that this assumes that the Lua or Duktape
// plugins are configured to run the sample scripts that comes with the repo
if(getQueryStringValue("plugin") === "lua")
	echotestPluginBackend = "janus.plugin.echolua";
else if(getQueryStringValue("plugin") === "duktape")
	echotestPluginBackend = "janus.plugin.echojs";

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
						// Attach to EchoTest plugin
						janus.attach(
							{
								plugin: echotestPluginBackend,
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									echotest = pluginHandle;
									Janus.log("Plugin attached! (" + echotest.getPlugin() + ", id=" + echotest.getId() + ")");
									// Negotiate WebRTC
									let body = { audio: true, video: true };
									// We can try and force a specific codec, by telling the plugin what we'd prefer
									// For simplicity, you can set it via a query string (e.g., ?vcodec=vp9)
									if(acodec)
										body["audiocodec"] = acodec;
									if(vcodec)
										body["videocodec"] = vcodec;
									// For the codecs that support them (VP9 and H.264) you can specify a codec
									// profile as well (e.g., ?vprofile=2 for VP9, or ?vprofile=42e01f for H.264)
									if(vprofile)
										body["videoprofile"] = vprofile;
									// We can force RED for audio too, if supported by the browser
									if(doOpusred)
										body["opusred"] = true;
									Janus.debug("Sending message:", body);
									echotest.send({ message: body });
									Janus.debug("Trying a createOffer too (audio/video sendrecv)");
									echotest.createOffer(
										{
											// We want bidirectional audio and video, plus data channels
											tracks: [
												{ type: 'audio', capture: true, recv: true },
												{ type: 'video', capture: true, recv: true,
													// We may need to enable simulcast or SVC on the video track
													simulcast: doSimulcast,
													// We only support SVC for VP9 and (still WIP) AV1
													svc: ((vcodec === 'vp9' || vcodec === 'av1') && doSvc) ? doSvc : null
												},
												{ type: 'data' },
											],
											customizeSdp: function(jsep) {
												// If DTX is enabled, munge the SDP
												if(doDtx) {
													jsep.sdp = jsep.sdp
														.replace("useinbandfec=1", "useinbandfec=1;usedtx=1")
												}
												if(stereo && jsep.sdp.indexOf("stereo=1") == -1) {
													// Make sure that our offer contains stereo too
													jsep.sdp = jsep.sdp.replace("useinbandfec=1", "useinbandfec=1;stereo=1");
												}
											},
											success: function(jsep) {
												Janus.debug("Got SDP!", jsep);
												echotest.send({ message: body, jsep: jsep });
											},
											error: function(error) {
												Janus.error("WebRTC error:", error);
												bootbox.alert("WebRTC error... " + error.message);
											}
										});
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											if(bitrateTimer)
												clearInterval(bitrateTimer);
											bitrateTimer = null;
											janus.destroy();
										});
								},
								error: function(error) {
									console.error("  -- Error attaching plugin...", error);
									bootbox.alert("Error attaching plugin... " + error);
								},
								consentDialog: function(on) {
									Janus.debug("Consent dialog should be " + (on ? "on" : "off") + " now");
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
									Janus.log("ICE state changed to " + state);
								},
								mediaState: function(medium, on, mid) {
									Janus.log("Janus " + (on ? "started" : "stopped") + " receiving our " + medium + " (mid=" + mid + ")");
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
								},
								slowLink: function(uplink, lost, mid) {
									Janus.warn("Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on mid " + mid + " (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::", msg);
									if(jsep) {
										Janus.debug("Handling SDP as well...", jsep);
										echotest.handleRemoteJsep({ jsep: jsep });
									}
									let result = msg["result"];
									if(result) {
										if(result === "done") {
											// The plugin closed the echo test
											bootbox.alert("The Echo Test is over");
											if(spinner)
												spinner.stop();
											spinner = null;
											$('video').remove();
											$('#waitingvideo').remove();
											$('#toggleaudio').attr('disabled', true);
											$('#togglevideo').attr('disabled', true);
											$('#bitrate').attr('disabled', true);
											$('#curbitrate').hide();
											$('#curres').hide();
											return;
										}
										// Any loss?
										let status = result["status"];
										if(status === "slow_link") {
											toastr.warning("Janus apparently missed many packets we sent, maybe we should reduce the bitrate", "Packet loss?", {timeOut: 2000});
										}
									}
									// Is simulcast in place?
									let substream = msg["substream"];
									let temporal = msg["temporal"];
									if((substream !== null && substream !== undefined) || (temporal !== null && temporal !== undefined)) {
										if(!simulcastStarted) {
											simulcastStarted = true;
											addSimulcastSvcButtons(msg["videocodec"] === "vp8" || msg["videocodec"] === "vp9" || msg["videocodec"] === "av1");
										}
										// We just received notice that there's been a switch, update the buttons
										updateSimulcastSvcButtons(substream, temporal);
									}
									// Or maybe SVC?
									let spatial = msg["spatial_layer"];
									temporal = msg["temporal_layer"];
									if((spatial !== null && spatial !== undefined) || (temporal !== null && temporal !== undefined)) {
										if(!svcStarted) {
											svcStarted = true;
											addSimulcastSvcButtons(true);
										}
										// We just received notice that there's been a switch, update the buttons
										updateSimulcastSvcButtons(spatial, temporal);
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
										$('#videoleft').append('<video class="rounded centered" id="myvideo' + trackId + '" width="100%" height="100%" autoplay playsinline muted="muted"/>');
										Janus.attachMediaStream($('#myvideo' + trackId).get(0), stream);
									}
									if(echotest.webrtcStuff.pc.iceConnectionState !== "completed" &&
											echotest.webrtcStuff.pc.iceConnectionState !== "connected") {
										$("#videoleft").parent().block({
											message: '<b>Publishing...</b>',
											css: {
												border: 'none',
												backgroundColor: 'transparent',
												color: 'white'
											}
										});
									}
								},
								onremotetrack: function(track, mid, on, metadata) {
									Janus.debug(
										"Remote track (mid=" + mid + ") " +
										(on ? "added" : "removed") +
										(metadata ? " (" + metadata.reason + ") ": "") + ":", track
									);
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
									// If we're here, a new track was added
									let addButtons = false;
									if($('#videoright audio').length === 0 && $('#videoright video').length === 0) {
										addButtons = true;
										$('#videos').removeClass('hide').show();
									}
									if(track.kind === "audio") {
										// New audio track: create a stream out of it, and use a hidden <audio> element
										let stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote audio stream:", stream);
										if($('#peervideo'+mid).length === 0)
											$('#videoright').append('<audio class="hide" id="peervideo' + mid + '" autoplay playsinline/>');
										Janus.attachMediaStream($('#peervideo' + mid).get(0), stream);
										if(remoteVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videoright .no-video-container').length === 0) {
												$('#videoright').append(
													'<div class="no-video-container">' +
														'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
														'<span class="no-video-text">No webcam available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										remoteVideos++;
										$('#videoright .no-video-container').remove();
										let stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote video stream:", stream);
										if($('#peervideo'+mid).length === 0)
											$('#videoright').append('<video class="rounded centered" id="peervideo' + mid + '" width="100%" height="100%" autoplay playsinline/>');
										Janus.attachMediaStream($('#peervideo' + mid).get(0), stream);
										// FIXME we'll need this for additional videos too
										if(!bitrateTimer) {
											$('#curbitrate').removeClass('hide').show();
											bitrateTimer = setInterval(function() {
												if(!$("#peervideo" + mid).get(0))
													return;
												// Display updated bitrate, if supported
												let bitrate = echotest.getBitrate();
												//~ Janus.debug("Current bitrate is " + echotest.getBitrate());
												$('#curbitrate').text(bitrate);
												// Check if the resolution changed too
												let width = $("#peervideo" + mid).get(0).videoWidth;
												let height = $("#peervideo" + mid).get(0).videoHeight;
												if(width > 0 && height > 0)
													$('#curres').removeClass('hide').text(width+'x'+height).show();
											}, 1000);
										}
									}
									if(!addButtons)
										return;
									// Enable audio/video buttons and bitrate limiter
									audioenabled = true;
									videoenabled = true;
									$('#toggleaudio').click(
										function() {
											audioenabled = !audioenabled;
											if(audioenabled)
												$('#toggleaudio').html("Disable audio").removeClass("btn-success").addClass("btn-danger");
											else
												$('#toggleaudio').html("Enable audio").removeClass("btn-danger").addClass("btn-success");
											echotest.send({ message: { audio: audioenabled }});
										});
									$('#togglevideo').click(
										function() {
											videoenabled = !videoenabled;
											if(videoenabled)
												$('#togglevideo').html("Disable video").removeClass("btn-success").addClass("btn-danger");
											else
												$('#togglevideo').html("Enable video").removeClass("btn-danger").addClass("btn-success");
											echotest.send({ message: { video: videoenabled }});
										});
									$('#toggleaudio').parent().removeClass('hide').show();
									$('#bitrate a').click(function() {
										let id = $(this).attr("id");
										let bitrate = parseInt(id)*1000;
										if(bitrate === 0) {
											Janus.log("Not limiting bandwidth via REMB");
										} else {
											Janus.log("Capping bandwidth to " + bitrate + " via REMB");
										}
										$('#bitrateset').html($(this).html() + '<span class="caret"></span>').parent().removeClass('open');
										echotest.send({ message: { bitrate: bitrate }});
										return false;
									});
								},
								// eslint-disable-next-line no-unused-vars
								ondataopen: function(label, protocol) {
									Janus.log("The DataChannel is available!");
									$('#videos').removeClass('hide').show();
									$('#datasend').removeAttr('disabled');
								},
								ondata: function(data) {
									Janus.debug("We got data from the DataChannel!", data);
									$('#datarecv').val(data);
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									if(spinner)
										spinner.stop();
									spinner = null;
									if(bitrateTimer)
										clearInterval(bitrateTimer);
									bitrateTimer = null;
									$('video').remove();
									$('#waitingvideo').remove();
									$("#videoleft").empty().parent().unblock();
									$('#videoright').empty();
									$('#toggleaudio').attr('disabled', true);
									$('#togglevideo').attr('disabled', true);
									$('#bitrate').attr('disabled', true);
									$('#curbitrate').hide();
									$('#curres').hide();
									$('#datasend').attr('disabled', true);
									simulcastStarted = false;
									$('#simulcast').remove();
									localTracks = {};
									localVideos = 0;
									remoteTracks = {};
									remoteVideos = 0;
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

// eslint-disable-next-line no-unused-vars
function checkEnter(event) {
	let theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if(theCode == 13) {
		sendData();
		return false;
	} else {
		return true;
	}
}

function sendData() {
	let data = $('#datasend').val();
	if(data === "") {
		bootbox.alert('Insert a message to send on the DataChannel');
		return;
	}
	echotest.data({
		text: data,
		error: function(reason) { bootbox.alert(reason); },
		success: function() { $('#datasend').val(''); },
	});
}

// Helper to parse query string
function getQueryStringValue(name) {
	name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
	let regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
		results = regex.exec(location.search);
	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

// Helpers to create Simulcast- or SVC-related UI, if enabled
function addSimulcastSvcButtons(temporal) {
	let what = (simulcastStarted ? 'simulcast' : 'SVC');
	let layer = (simulcastStarted ? 'substream' : 'layer');
	$('#curres').parent().append(
		'<div id="simulcast" class="btn-group-vertical btn-group-vertical-xs pull-right">' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs" style="width: 100%">' +
		'			<button id="sl-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to higher quality" style="width: 33%">SL 2</button>' +
		'			<button id="sl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to normal quality" style="width: 33%">SL 1</button>' +
		'			<button id="sl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to lower quality" style="width: 34%">SL 0</button>' +
		'		</div>' +
		'	</div>' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs hide" style="width: 100%">' +
		'			<button id="tl-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 2" style="width: 34%">TL 2</button>' +
		'			<button id="tl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 1" style="width: 33%">TL 1</button>' +
		'			<button id="tl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 0" style="width: 33%">TL 0</button>' +
		'		</div>' +
		'	</div>' +
		'</div>');
	if(simulcastStarted && Janus.webRTCAdapter.browserDetails.browser !== "firefox") {
		// Chromium-based browsers only have two temporal layers, when doing simulcast
		$('#tl-2').remove();
		$('#tl-1').css('width', '50%');
		$('#tl-0').css('width', '50%');
	}
	// Enable the simulcast selection buttons
	$('#sl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching " + what + " " + layer + ", wait for it... (lower quality)", null, {timeOut: 2000});
			if(!$('#sl-2').hasClass('btn-success'))
				$('#sl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#sl-1').hasClass('btn-success'))
				$('#sl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(simulcastStarted)
				echotest.send({ message: { substream: 0 }});
			else
				echotest.send({ message: { spatial_layer: 0 }});
		});
	$('#sl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching " + what + " " + layer + ", wait for it... (normal quality)", null, {timeOut: 2000});
			if(!$('#sl-2').hasClass('btn-success'))
				$('#sl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#sl-0').hasClass('btn-success'))
				$('#sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(simulcastStarted)
				echotest.send({ message: { substream: 1 }});
			else
				echotest.send({ message: { spatial_layer: 1 }});
		});
	$('#sl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching " + what + " " + layer + ", wait for it... (higher quality)", null, {timeOut: 2000});
			$('#sl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#sl-1').hasClass('btn-success'))
				$('#sl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#sl-0').hasClass('btn-success'))
				$('#sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(simulcastStarted)
				echotest.send({ message: { substream: 2 }});
			else
				echotest.send({ message: { spatial_layer: 2 }});
		});
	if(!temporal)	// No temporal layer support
		return;
	$('#tl-0').parent().removeClass('hide');
	$('#tl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping " + what + " temporal layer, wait for it... (lowest FPS)", null, {timeOut: 2000});
			if(!$('#tl-2').hasClass('btn-success'))
				$('#tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#tl-1').hasClass('btn-success'))
				$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(simulcastStarted)
				echotest.send({ message: { temporal: 0 }});
			else
				echotest.send({ message: { temporal_layer: 0 }});
		});
	$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping " + what + " temporal layer, wait for it... (medium FPS)", null, {timeOut: 2000});
			if(!$('#tl-2').hasClass('btn-success'))
				$('#tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-info');
			if(!$('#tl-0').hasClass('btn-success'))
				$('#tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(simulcastStarted)
				echotest.send({ message: { temporal: 1 }});
			else
				echotest.send({ message: { temporal_layer: 1 }});
		});
	$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping " + what + " temporal layer, wait for it... (highest FPS)", null, {timeOut: 2000});
			$('#tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#tl-1').hasClass('btn-success'))
				$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#tl-0').hasClass('btn-success'))
				$('#tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(simulcastStarted)
				echotest.send({ message: { temporal: 2 }});
			else
				echotest.send({ message: { temporal_layer: 2 }});
		});
}

function updateSimulcastSvcButtons(substream, temporal) {
	// Check the substream
	let what = (simulcastStarted ? 'simulcast' : 'SVC');
	let layer = (simulcastStarted ? 'substream' : 'layer');
	if(substream === 0) {
		toastr.success("Switched " + what + " " + layer + "! (lower quality)", null, {timeOut: 2000});
		$('#sl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(substream === 1) {
		toastr.success("Switched " + what + " " + layer + "! (normal quality)", null, {timeOut: 2000});
		$('#sl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#sl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(substream === 2) {
		toastr.success("Switched " + what + " " + layer + "! (higher quality)", null, {timeOut: 2000});
		$('#sl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#sl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
	// Check the temporal layer
	if(temporal === 0) {
		toastr.success("Capped " + what + " temporal layer! (lowest FPS)", null, {timeOut: 2000});
		$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(temporal === 1) {
		toastr.success("Capped " + what + " temporal layer! (medium FPS)", null, {timeOut: 2000});
		$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(temporal === 2) {
		toastr.success("Capped " + what + " temporal layer! (highest FPS)", null, {timeOut: 2000});
		$('#tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
}
