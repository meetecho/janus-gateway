// We import the settings.js file to know which address we should contact
// to talk to Janus, and optionally which STUN/TURN servers should be
// used as well. Specifically, that file defines the "server" and
// "iceServers" properties we'll pass when creating the Janus session.

/* global iceServers:readonly, Janus:readonly, server:readonly */

var janus = null;
var recordplay = null;
var opaqueId = "recordplaytest-"+Janus.randomString(12);

var localTracks = {}, localVideos = 0,
	remoteTracks = {}, remoteVideos = 0;
var spinner = null;
var bandwidth = 1024 * 1024;

var myname = null;
var recording = false;
var playing = false;
var recordingId = null;
var selectedRecording = null;
var selectedRecordingInfo = null;

var acodec = (getQueryStringValue("acodec") !== "" ? getQueryStringValue("acodec") : null);
var vcodec = (getQueryStringValue("vcodec") !== "" ? getQueryStringValue("vcodec") : null);
var vprofile = (getQueryStringValue("vprofile") !== "" ? getQueryStringValue("vprofile") : null);
var doSimulcast = (getQueryStringValue("simulcast") === "yes" || getQueryStringValue("simulcast") === "true");
var doOpusred = (getQueryStringValue("opusred") === "yes" || getQueryStringValue("opusred") === "true");
var recordData = (getQueryStringValue("data") !== "" ? getQueryStringValue("data") : null);
if(recordData !== "text" && recordData !== "binary")
	recordData = null;

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
						// Attach to Record&Play plugin
						janus.attach(
							{
								plugin: "janus.plugin.recordplay",
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									recordplay = pluginHandle;
									Janus.log("Plugin attached! (" + recordplay.getPlugin() + ", id=" + recordplay.getId() + ")");
									// Prepare the name prompt
									$('#recordplay').removeClass('hide').show();
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											janus.destroy();
										});
									updateRecsList();
								},
								error: function(error) {
									Janus.error("  -- Error attaching plugin...", error);
									bootbox.alert("  -- Error attaching plugin... " + error);
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
									$("#videobox").parent().unblock();
								},
								slowLink: function(uplink, lost, mid) {
									Janus.warn("Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on mid " + mid + " (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::", msg);
									let result = msg["result"];
									if(result) {
										if(result["status"]) {
											let event = result["status"];
											if(event === 'preparing' || event === 'refreshing') {
												Janus.log("Preparing the recording playout");
												recordplay.createAnswer(
													{
														jsep: jsep,
														// We only specify data channels here, as this way in
														// case they were offered we'll enable them. Since we
														// don't mention audio or video tracks, we autoaccept them
														// as recvonly (since we won't capture anything ourselves)
														tracks: [
															{ type: 'data' }
														],
														success: function(jsep) {
															Janus.debug("Got SDP!", jsep);
															let body = { request: "start" };
															recordplay.send({ message: body, jsep: jsep });
														},
														error: function(error) {
															Janus.error("WebRTC error:", error);
															bootbox.alert("WebRTC error... " + error.message);
														}
													});
												if(result["warning"])
													bootbox.alert(result["warning"]);
											} else if(event === 'recording') {
												// Got an ANSWER to our recording OFFER
												if(jsep)
													recordplay.handleRemoteJsep({ jsep: jsep });
												let id = result["id"];
												if(id) {
													Janus.log("The ID of the current recording is " + id);
													recordingId = id;
												}
											} else if(event === 'playing') {
												Janus.log("Playout has started!");
											} else if(event === 'stopped') {
												Janus.log("Session has stopped!");
												let id = result["id"];
												if(recordingId) {
													if(recordingId !== id) {
														Janus.warn("Not a stop to our recording?");
														return;
													}
													bootbox.alert("Recording completed! Check the list of recordings to replay it.");
												}
												if(selectedRecording) {
													if(selectedRecording !== id) {
														Janus.warn("Not a stop to our playout?");
														return;
													}
												}
												// FIXME Reset status
												$('#videobox').empty();
												$('#video').hide();
												recordingId = null;
												recording = false;
												playing = false;
												recordplay.hangup();
												$('#record').removeAttr('disabled').click(startRecording);
												$('#play').removeAttr('disabled').click(startPlayout);
												$('#list').removeAttr('disabled').click(updateRecsList);
												$('#recset').removeAttr('disabled');
												$('#recslist').removeAttr('disabled');
												updateRecsList();
											}
										}
									} else {
										// FIXME Error?
										let error = msg["error"];
										bootbox.alert(error);
										// FIXME Reset status
										$('#videobox').empty();
										$('#video').hide();
										recording = false;
										playing = false;
										recordplay.hangup();
										$('#record').removeAttr('disabled').click(startRecording);
										$('#play').removeAttr('disabled').click(startPlayout);
										$('#list').removeAttr('disabled').click(updateRecsList);
										$('#recset').removeAttr('disabled');
										$('#recslist').removeAttr('disabled');
										updateRecsList();
									}
								},
								onlocaltrack: function(track, on) {
									if(playing === true)
										return;
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
											$('#thevideo' + trackId).remove();
											localVideos--;
											if(localVideos === 0) {
												// No video, at least for now: show a placeholder
												if($('#videobox .no-video-container').length === 0) {
													$('#videobox').append(
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
									$('#videotitle').html("Recording...");
									$('#stop').unbind('click').click(stopRecPlay);
									$('#video').removeClass('hide').show();
									if($('#videobox video').length === 0) {
										$('#videos').removeClass('hide').show();
									}
									if(track.kind === "audio") {
										// We ignore local audio tracks, they'd generate echo anyway
										if(localVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videobox .no-video-container').length === 0) {
												$('#videobox').append(
													'<div class="no-video-container">' +
														'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
														'<span class="no-video-text">No webcam available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										localVideos++;
										$('#videobox .no-video-container').remove();
										let stream = new MediaStream([track]);
										localTracks[trackId] = stream;
										Janus.log("Created local stream:", stream);
										$('#videobox').append('<video class="rounded centered" id="thevideo' + trackId + '" width="100%" height="100%" autoplay playsinline muted="muted"/>');
										Janus.attachMediaStream($('#thevideo' + trackId).get(0), stream);
									}
									if(recordplay.webrtcStuff.pc.iceConnectionState !== "completed" &&
											recordplay.webrtcStuff.pc.iceConnectionState !== "connected") {
										$("#videobox").parent().block({
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
									if(playing === false)
										return;
									Janus.debug(
										"Remote track (mid=" + mid + ") " +
										(on ? "added" : "removed") +
										(metadata? " (" + metadata.reason + ") ": "") + ":", track
									);
									if(!on) {
										// Track removed, get rid of the stream and the rendering
										$('#thevideo' + mid).remove();
										if(track.kind === "video") {
											remoteVideos--;
											if(remoteVideos === 0) {
												// No video, at least for now: show a placeholder
												if($('#videobox .no-video-container').length === 0) {
													$('#videobox').append(
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
									if($('#thevideo' + mid).length > 0)
										return;
									// If we're here, a new track was added
									if($('#videobox audio').length === 0 && $('#videobox video').length === 0) {
										$('#videotitle').html(selectedRecordingInfo);
										$('#stop').unbind('click').click(stopRecPlay);
										$('#video').removeClass('hide').show();
									}
									if(track.kind === "audio") {
										// New audio track: create a stream out of it, and use a hidden <audio> element
										let stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote audio stream:", stream);
										$('#videobox').append('<audio class="hide" id="thevideo' + mid + '" autoplay playsinline/>');
										Janus.attachMediaStream($('#thevideo' + mid).get(0), stream);
										if(remoteVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videobox .no-video-container').length === 0) {
												$('#videobox').append(
													'<div class="no-video-container">' +
														'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
														'<span class="no-video-text">No remote video available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										remoteVideos++;
										$('#videobox .no-video-container').remove();
										let stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote video stream:", stream);
										$('#videobox').append('<video class="rounded centered" id="thevideo' + mid + '" width="100%" height="100%" autoplay playsinline/>');
										Janus.attachMediaStream($('#thevideo' + mid).get(0), stream);
										if($('#curres').length === 0) {
											$('#videobox').append(
												'<span class="label label-primary" id="curres' +'" style="position: absolute; bottom: 0px; left: 0px; margin: 15px;"></span>' +
												'<span class="label label-info" id="curbw' +'" style="position: absolute; bottom: 0px; right: 0px; margin: 15px;"></span>');
											$('#thevideo' + mid).bind("playing", function () {
												let width = this.videoWidth;
												let height = this.videoHeight;
												$('#curres').text(width + 'x' + height);
											});
											recordplay.bitrateTimer = setInterval(function() {
												// Display updated bitrate, if supported
												let bitrate = recordplay.getBitrate();
												$('#curbw').text(bitrate);
												let video = $('video').get(0);
												let width = video.videoWidth;
												let height = video.videoHeight;
												if(width > 0 && height > 0)
													$('#curres').text(width + 'x' + height);
											}, 1000);
										}
									}
								},
								// eslint-disable-next-line no-unused-vars
								ondataopen: function(label, protocol) {
									Janus.log("The DataChannel is available!");
									$('#datafield').parent().removeClass('hide');
									if(playing === false) {
										// We're recording, use this field to send data
										$('#datafield').attr('placeholder', 'Write a message to record');
										$('#datafield').removeAttr('disabled');
									}
								},
								ondata: function(data) {
									Janus.debug("We got data from the DataChannel!", data);
									if(playing === true)
										$('#datafield').val(data);
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									// FIXME Reset status
									$('#waitingvideo').remove();
									if(spinner)
										spinner.stop();
									spinner = null;
									if(recordplay.bitrateTimer)
										clearInterval(recordplay.bitrateTimer);
									delete recordplay.bitrateTimer;
									$('#videobox').empty();
									$("#videobox").parent().unblock();
									$('#video').hide();
									$('#datafield').attr('disabled', true).attr('placeholder', '').val('');
									$('#datafield').parent().addClass('hide');
									recording = false;
									playing = false;
									$('#record').removeAttr('disabled').click(startRecording);
									$('#play').removeAttr('disabled').click(startPlayout);
									$('#list').removeAttr('disabled').click(updateRecsList);
									$('#recset').removeAttr('disabled');
									$('#recslist').removeAttr('disabled');
									localTracks = {};
									localVideos = 0;
									remoteTracks = {};
									remoteVideos = 0;
									updateRecsList();
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
	let data = $('#datafield').val();
	if(data === "") {
		bootbox.alert('Insert a message to send on the DataChannel');
		return;
	}
	recordplay.data({
		text: data,
		error: function(reason) { bootbox.alert(reason); },
		success: function() { $('#datafield').val(''); },
	});
}

function updateRecsList() {
	$('#list').unbind('click');
	$('#update-list').addClass('fa-spin');
	let body = { request: "list" };
	Janus.debug("Sending message:", body);
	recordplay.send({ message: body, success: function(result) {
		setTimeout(function() {
			$('#list').click(updateRecsList);
			$('#update-list').removeClass('fa-spin');
		}, 500);
		if(!result) {
			bootbox.alert("Got no response to our query for available recordings");
			return;
		}
		if(result["list"]) {
			$('#recslist').empty();
			$('#record').removeAttr('disabled').click(startRecording);
			$('#list').removeAttr('disabled').click(updateRecsList);
			let list = result["list"];
			list.sort(function(a, b) {return (a["date"] < b["date"]) ? 1 : ((b["date"] < a["date"]) ? -1 : 0);} );
			Janus.debug("Got a list of available recordings:", list);
			for(let mp in list) {
				Janus.debug("  >> [" + list[mp]["id"] + "] " + list[mp]["name"] + " (" + list[mp]["date"] + ")");
				$('#recslist').append("<li><a href='#' id='" + list[mp]["id"] + "'>" + escapeXmlTags(list[mp]["name"]) + " [" + list[mp]["date"] + "]" + "</a></li>");
			}
			$('#recslist a').unbind('click').click(function() {
				selectedRecording = $(this).attr("id");
				selectedRecordingInfo = escapeXmlTags($(this).text());
				$('#recset').html($(this).html()).parent().removeClass('open');
				$('#play').removeAttr('disabled').click(startPlayout);
				return false;
			});
		}
	}});
}

function startRecording() {
	if(recording)
		return;
	// Start a recording
	recording = true;
	playing = false;
	bootbox.prompt("Insert a name for the recording (e.g., John Smith says hello)", function(result) {
		if(!result) {
			recording = false;
			return;
		}
		myname = result;
		$('#record').unbind('click').attr('disabled', true);
		$('#play').unbind('click').attr('disabled', true);
		$('#list').unbind('click').attr('disabled', true);
		$('#recset').attr('disabled', true);
		$('#recslist').attr('disabled', true);
		$('#pause-resume').removeClass('hide');

		// bitrate and keyframe interval can be set at any time:
		// before, after, during recording
		recordplay.send({
			message: {
				request: 'configure',
				'video-bitrate-max': bandwidth,		// a quarter megabit
				'video-keyframe-interval': 15000	// 15 seconds
			}
		});

		recordplay.createOffer(
			{
				// We want sendonly audio and video, since we'll just send
				// media to Janus and not receive any back in this scenario
				// (uncomment the data track if you want to also record data
				// channels, even though there's no UI for that in the demo)
				tracks: [
					{ type: 'audio', capture: true, recv: false },
					{ type: 'video', capture: true, recv: false, simulcast: doSimulcast },
					//~ { type: 'data' },
				],
				success: function(jsep) {
					Janus.debug("Got SDP!", jsep);
					let body = { request: "record", name: myname };
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
					// You can use RED for Opus, if the browser supports it
					if(doOpusred)
						body["opusred"] = true;
					// If we're going to send binary data, let's tell the plugin
					if(recordData === "binary")
						body["textdata"] = false;
					recordplay.send({ message: body, jsep: jsep });
				},
				error: function(error) {
					Janus.error("WebRTC error...", error);
					bootbox.alert("WebRTC error... " + error.message);
					recordplay.hangup();
				}
			});
		$('#pause-resume').unbind('click').on('click', function() {
			if($(this).text() === 'Pause') {
				recordplay.send({message: {request: 'pause'}});
				$(this).text('Resume');
			} else {
				recordplay.send({message: {request: 'resume'}});
				$(this).text('Pause');
			}
		});
	});
}

function startPlayout() {
	if(playing)
		return;
	// Start a playout
	recording = false;
	playing = true;
	if(!selectedRecording) {
		playing = false;
		return;
	}
	$('#record').unbind('click').attr('disabled', true);
	$('#play').unbind('click').attr('disabled', true);
	$('#list').unbind('click').attr('disabled', true);
	$('#recset').attr('disabled', true);
	$('#recslist').attr('disabled', true);
	$('#pause-resume').addClass('hide');
	let play = { request: "play", id: parseInt(selectedRecording) };
	recordplay.send({ message: play });
}

function stopRecPlay() {
	// Stop a recording/playout
	$('#stop').unbind('click');
	let stop = { request: "stop" };
	recordplay.send({ message: stop });
	recordplay.hangup();
}

// Helper to parse query string
function getQueryStringValue(name) {
	name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
	let regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
		results = regex.exec(location.search);
	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

// Helper to escape XML tags
function escapeXmlTags(value) {
	if(value) {
		let escapedValue = value.replace(new RegExp('<', 'g'), '&lt');
		escapedValue = escapedValue.replace(new RegExp('>', 'g'), '&gt');
		return escapedValue;
	}
}
