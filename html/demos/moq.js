// We import the settings.js file to know which address we should contact
// to talk to Janus, and optionally which STUN/TURN servers should be
// used as well. Specifically, that file defines the "server" and
// "iceServers" properties we'll pass when creating the Janus session.

/* global iceServers:readonly, Janus:readonly, server:readonly */

var janus = null;
var moqjanus = null;
var opaqueId = "moqpub-"+Janus.randomString(12);

var role = (getQueryStringValue("role") !== "" ? getQueryStringValue("role") : null);
var port = (getQueryStringValue("port") !== "" ? parseInt(getQueryStringValue("port")) : 0);
var remote_host = (getQueryStringValue("remote_host") !== "" ? getQueryStringValue("remote_host") : null);
var remote_port = (getQueryStringValue("remote_port") !== "" ? parseInt(getQueryStringValue("remote_port")) : 0);
var wt = (getQueryStringValue("webtransport") !== "" ? (getQueryStringValue("webtransport") === "true") : true);
var path = (getQueryStringValue("path") !== "" ? getQueryStringValue("path") : "/");
var namespace = (getQueryStringValue("namespace") !== "" ? getQueryStringValue("namespace") : null);
var media = (getQueryStringValue("media") !== "" ? getQueryStringValue("media") : null);
var catalog = (media ? (media === 'usecatalog') : true);
var doAudio = (getQueryStringValue("audio") !== "" ? (getQueryStringValue("audio") === "true") : true);
var audio = (getQueryStringValue("audio_track") !== "" ? getQueryStringValue("audio_track") : null);
var doVideo = (getQueryStringValue("video") !== "" ? (getQueryStringValue("video") === "true") : true);
var video = (getQueryStringValue("video_track") !== "" ? getQueryStringValue("video_track") : null);
var vcodec = (getQueryStringValue("vcodec") !== "" ? getQueryStringValue("vcodec") : null);
var annexb = (getQueryStringValue("annexb") !== "" ? (getQueryStringValue("annexb") === "true") : false);
var auth = (getQueryStringValue("auth") !== "" ? getQueryStringValue("auth") : null);

var localTracks = {}, localVideos = 0;
var remoteTracks = {}, remoteVideos = 0;
var bitrateTimer = null;

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
						// Attach to MoQ plugin
						janus.attach(
							{
								plugin: 'janus.plugin.moq',
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									moqjanus = pluginHandle;
									Janus.log("Plugin attached! (" + moqjanus.getPlugin() + ", id=" + moqjanus.getId() + ")");
									$('#options').removeClass('hide');
									$('#choose').removeClass('hide');
									// Check if we passed anything from query string
									if(remote_host)
										$('#server').val(remote_host);
									if(remote_port)
										$('#port').val('' + remote_port);
									if(namespace)
										$('#ns').val(namespace);
									if(audio)
										$('#audio').val(audio);
									if(video)
										$('#video').val(video);
									// React to changes
									$('#audioenable').on('change', function() {
										if(this.checked)
											$('#audio').removeAttr('disabled');
										else
											$('#audio').attr('disabled', true);
									});
									$('#videoenable').on('change', function() {
										if(this.checked)
											$('#video').removeAttr('disabled');
										else
											$('#video').attr('disabled', true);
									});
									$('#rolelist a').unbind('click').click(function() {
										$('.dropdown-toggle').dropdown('hide');
										role = $(this).attr("id");
										$('#role').html($(this).html()).parent().removeClass('open');
										if(role === "publisher") {
											$('#usecatalog').parent().parent().addClass('hide');
											$('#audioenable').removeAttr('disabled');
											$('#audio').removeAttr('disabled');
											$('#videoenable').removeAttr('disabled');
											$('#video').removeAttr('disabled');
										} else {
											$('#usecatalog').parent().parent().removeClass('hide');
											if(media === "usecatalog") {
												catalog = true;
												$('#audioenable').attr('disabled', true);
												$('#audio').attr('disabled', true);
												$('#videoenable').attr('disabled', true);
												$('#video').attr('disabled', true);
											} else {
												catalog = false;
												$('#audioenable').removeAttr('disabled');
												$('#audio').removeAttr('disabled');
												$('#videoenable').removeAttr('disabled');
												$('#video').removeAttr('disabled');
											}
										}
										return false;
									});
									$('#cataloglist a').unbind('click').click(function() {
										$('.dropdown-toggle').dropdown('hide');
										media = $(this).attr("id");
										$('#usecatalog').html($(this).html()).parent().removeClass('open');
										if(media === "usecatalog") {
											catalog = true;
											$('#audioenable').attr('disabled', true);
											$('#audio').attr('disabled', true);
											$('#videoenable').attr('disabled', true);
											$('#video').attr('disabled', true);
										} else {
											catalog = false;
											$('#audioenable').removeAttr('disabled');
											$('#audio').removeAttr('disabled');
											$('#videoenable').removeAttr('disabled');
											$('#video').removeAttr('disabled');
										}
										return false;
									});
									if(role === 'publisher' || role === 'subscriber')
										$('#' + role).click();
									$('#audioenable').prop('checked', doAudio).trigger('change');
									$('#videoenable').prop('checked', doVideo).trigger('change');
									if(media === 'usecatalog' || media === 'nocatalog')
										$('#' + media).click();
									$('#connect').click(connectMoQ);
									$('#role').focus();
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											janus.destroy();
										});
								},
								error: function(error) {
									console.error("  -- Error attaching plugin...", error);
									bootbox.alert("Error attaching plugin... " + error);
								},
								iceState: function(state) {
									Janus.log("ICE state changed to " + state);
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videolocal").parent().unblock();
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::", msg);
									// Check if we got an error
									if(msg['error_space'] || msg['error_code'] || msg['error']) {
										let error_msg =
											(msg['error_space'] ? ('[' + msg['error_space'] + '] ') : '') +
												'Error ' + msg['error_code'] + ' (' + msg['error'] + ')';
										bootbox.alert(error_msg, function() {
											window.location.reload();
										});
										return;
									}
									// Check if we got an SDP
									if(jsep) {
										Janus.debug("Handling SDP as well...", jsep);
										if(role === 'publisher') {
											moqjanus.handleRemoteJsep({ jsep: jsep });
										} else {
											Janus.debug("Creating SDP answer...", jsep);
											moqjanus.createAnswer(
												{
													jsep: jsep,
													success: function(jsep) {
														Janus.debug("Got SDP!", jsep);
														let body = { request: "start" };
														moqjanus.send({ message: body, jsep: jsep });
													},
													error: function(error) {
														Janus.error("WebRTC error:", error);
														moqjanus.alert("WebRTC error... " + error.message);
													}
												});
										}
									}
									let result = msg["result"];
									if(result) {
										if(result.catalog) {
											let catalog = JSON.stringify(result.catalog, null, '\t');
											$('#catalog').text(catalog);
										}
										if(result === "done") {
											// The plugin closed the echo test
											bootbox.alert("The demo is over");
											return;
										}
									}
								},
								onlocaltrack: function(track, on) {
									// Publisher only
									Janus.debug("Local track " + (on ? "added" : "removed") + ":", track);
									$('#choose').addClass('hide');
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
											// eslint-disable-next-line no-unused-vars
											} catch(e) {}
										}
										if(track.kind === "video") {
											$('#myvideo' + trackId).remove();
											localVideos--;
											if(localVideos === 0) {
												// No video, at least for now: show a placeholder
												if($('#videolocal .no-video-container').length === 0) {
													$('#videolocal').append(
														'<div class="no-video-container">' +
															'<i class="fa-solid fa-video fa-xl no-video-icon"></i>' +
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
									if($('#videolocal video').length === 0) {
										$('#videos').removeClass('hide');
									}
									if(track.kind === "audio") {
										// We ignore local audio tracks, they'd generate echo anyway
										if(localVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videolocal .no-video-container').length === 0) {
												$('#videolocal').append(
													'<div class="no-video-container">' +
														'<i class="fa-solid fa-video fa-xl no-video-icon"></i>' +
														'<span class="no-video-text">No webcam available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										localVideos++;
										$('#videolocal .no-video-container').remove();
										let stream = new MediaStream([track]);
										localTracks[trackId] = stream;
										Janus.log("Created local stream:", stream);
										$('#videolocal').append('<video class="rounded centered" id="myvideo' + trackId + '" width="100%" height="100%" autoplay playsinline muted="muted"/>');
										Janus.attachMediaStream($('#myvideo' + trackId).get(0), stream);
									}
									if(moqjanus.webrtcStuff.pc.iceConnectionState !== "completed" &&
											moqjanus.webrtcStuff.pc.iceConnectionState !== "connected") {
										$("#videolocal").parent().block({
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
									// Subscriber only
									Janus.debug(
										"Remote track (mid=" + mid + ") " +
										(on ? "added" : "removed") +
										(metadata ? " (" + metadata.reason + ") ": "") + ":", track
									);
									$('#choose').addClass('hide');
									if(!on) {
										// Track removed, get rid of the stream and the rendering
										$('#peervideo' + mid).remove();
										if(track.kind === "video") {
											remoteVideos--;
											if(remoteVideos === 0) {
												// No video, at least for now: show a placeholder
												if($('#videoremote .no-video-container').length === 0) {
													$('#videoremote').append(
														'<div class="no-video-container">' +
															'<i class="fa-solid fa-video fa-xl no-video-icon"></i>' +
															'<span class="no-video-text">No remote video available</span>' +
														'</div>');
												}
											}
										}
										delete remoteTracks[mid];
										return;
									}
									// If we're here, a new track was added
									if($('#videoremote audio').length === 0 && $('#videoremote video').length === 0) {
										addButtons = true;
										$('#videos').removeClass('hide');
									}
									if(track.kind === "audio") {
										// New audio track: create a stream out of it, and use a hidden <audio> element
										let stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote audio stream:", stream);
										if($('#peervideo'+mid).length === 0)
											$('#videoremote').append('<audio class="hide" id="peervideo' + mid + '" autoplay playsinline/>');
										Janus.attachMediaStream($('#peervideo' + mid).get(0), stream);
										if(remoteVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videoremote .no-video-container').length === 0) {
												$('#videoremote').append(
													'<div class="no-video-container">' +
														'<i class="fa-solid fa-video fa-xl no-video-icon"></i>' +
														'<span class="no-video-text">No webcam available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										remoteVideos++;
										$('#videoremote .no-video-container').remove();
										let stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote video stream:", stream);
										if($('#peervideo'+mid).length === 0)
											$('#videoremote').append('<video class="rounded centered" id="peervideo' + mid + '" width="100%" height="100%" autoplay playsinline/>');
										Janus.attachMediaStream($('#peervideo' + mid).get(0), stream);
										if(!bitrateTimer) {
											$('#curbitrate').removeClass('hide');
											bitrateTimer = setInterval(function() {
												if(!$("#peervideo" + mid).get(0))
													return;
												// Display updated bitrate, if supported
												let bitrate = moqjanus.getBitrate();
												//~ Janus.debug("Current bitrate is " + moqjanus.getBitrate());
												$('#curbitrate').text(bitrate);
												// Check if the resolution changed too
												let width = $("#peervideo" + mid).get(0).videoWidth;
												let height = $("#peervideo" + mid).get(0).videoHeight;
												if(width > 0 && height > 0)
													$('#curres').removeClass('hide').text(width+'x'+height).removeClass('hide');
											}, 1000);
										}
									}
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									$('videos').empty();
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

function checkEnter(field, event) {
	let theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if(theCode == 13) {
		connectMoQ();
		return false;
	} else {
		return true;
	}
}

// Create a gatewaying session
function connectMoQ() {
	$('#connect').attr('disabled', true);
	if(role === null || $('#server').val() === '' ||
			$('#port').val() === '' || parseInt($('#port').val()) === isNaN ||
			parseInt($('#port').val()) < 0 || $('#namespace').val() === '') {
		$('#connect').removeAttr('disabled');
		bootbox.alert('Invalid details');
		return;
	}
	remote_host = $('#server').val();
	remote_port = parseInt($('#port').val());
	namespace = $('#ns').val();
	audio = $('#audioenable').prop('checked') ? $('#audio').val() : '';
	video = $('#videoenable').prop('checked') ? $('#video').val() : '';
	if(role === 'publisher') {
		// Connect as a publisher
		if((audio === '' && video === '') ||
				($('#audioenable').prop('checked') && audio === '') ||
				($('#videoenable').prop('checked') && video === '')) {
			$('#connect').removeAttr('disabled');
			bootbox.alert('Invalid details');
			return;
		}
		publishMoq();
	} else {
		// Connect as a subscriber
		if(media === '' || (!catalog &&
				((audio === '' && video === '') ||
				($('#audioenable').prop('checked') && audio === '') ||
				($('#videoenable').prop('checked') && video === '')))) {
			$('#connect').removeAttr('disabled');
			bootbox.alert('Invalid details');
			return;
		}
		subscribeMoq();
	}
}

// Connect as a publisher
function publishMoq() {
	// Update UI
	$('#videos').html(
		'<div class="row">' +
		'	<div class="col-md-6">' +
		'		<div class="card">' +
		'			<div class="card-header">' +
		'				<span class="card-title">Local video</span>' +
		'			</div>' +
		'			<div class="card-body" id="videolocal"></div>' +
		'		</div>' +
		'	</div>' +
		'	<div class="col-md-6">' +
		'		<div class="card">' +
		'			<div class="card-header">' +
		'				<span class="card-title">Catalog <span class="badge bg-primary hide" id="tns"></span>' +
		'			</div>' +
		'			<div class="card-body">' +
		'				<pre id="catalog"></pre>' +
		'			</div>' +
		'		</div>' +
		'	</div>' +
		'</div>');
	// Create offer
	moqjanus.createOffer(
		{
			// We only need to send audio and video, not receive it
			tracks: [
				{ type: 'audio', capture: true, recv: false },
				{ type: 'video', capture: 'hires', recv: false }
			],
			success: function(jsep) {
				Janus.debug("Got SDP!", jsep);
				let msg = {
					request: 'bridge',
					port: port,
					remote_host: remote_host,
					remote_port: remote_port,
					webtransport: wt,
					path: path ? path : '/',
					role: 'publisher',
					namespace: namespace,
					//~ auth_info: auth,
				};
				if($('#audioenable').prop('checked'))
					msg.audio_track = audio;
				if($('#videoenable').prop('checked')) {
					msg.video_track = video;
					if(vcodec)
						msg.video_codec = vcodec;
					if((!vcodec || vcodec === 'h264') && annexb)
						msg.annexb = true;
				}
				moqjanus.send({ message: msg, jsep: jsep });
			},
			error: function(error) {
				Janus.error("WebRTC error:", error);
				bootbox.alert("WebRTC error... " + error.message);
			}
		});
}

// Connect as a subscriber
function subscribeMoq() {
	// Update UI
	$('#videos').html(
		'<div class="row">' +
		'	<div class="col-md-6">' +
		'		<div class="card">' +
		'			<div class="card-header">' +
		'				<span class="card-title">Catalog <span class="badge bg-primary hide" id="tns"></span>' +
		'			</div>' +
		'			<div class="card-body">' +
		'				<pre id="catalog"></pre>' +
		'			</div>' +
		'		</div>' +
		'	</div>' +
		'	<div class="col-md-6">' +
		'		<div class="card">' +
		'			<div class="card-header">' +
		'				<span class="card-title">Remote video <span class="badge bg-primary hide" id="curres"></span> <span class="badge bg-info hide" id="curbitrate"></span></span>' +
		'			</div>' +
		'			<div class="card-body" id="videoremote"></div>' +
		'		</div>' +
		'	</div>' +
		'</div>');
	// Subscribe
	let msg = {
		request: 'bridge',
		port: port,
		remote_host: remote_host,
		remote_port: remote_port,
		webtransport: wt,
		path: path ? path : '/',
		role: 'subscriber',
		namespace: namespace,
		//~ auth_info: auth,
	}
	if(!catalog) {
		msg.use_catalog = false;
		if($('#audioenable').prop('checked'))
			msg.audio_track = audio;
		if($('#videoenable').prop('checked')) {
			msg.video_track = video;
			if(vcodec)
				msg.video_codec = vcodec;
			if((!vcodec || vcodec === 'h264') && annexb)
				msg.annexb = true;
		}
	}
	moqjanus.send({ message: msg });
}

// Helper to parse query string
function getQueryStringValue(name) {
	name = name.replace(/[[]/, "\\[").replace(/[\]]/, "\\]");
	let regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
		results = regex.exec(location.search);
	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}
