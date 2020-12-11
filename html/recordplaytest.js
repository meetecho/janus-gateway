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
var recordplay = null;
var opaqueId = "recordplaytest-"+Janus.randomString(12);

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
var doSimulcast2 = (getQueryStringValue("simulcast2") === "yes" || getQueryStringValue("simulcast2") === "true");
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
								mediaState: function(medium, on) {
									Janus.log("Janus " + (on ? "started" : "stopped") + " receiving our " + medium);
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videobox").parent().unblock();
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::", msg);
									var result = msg["result"];
									if(result) {
										if(result["status"]) {
											var event = result["status"];
											if(event === 'preparing' || event === 'refreshing') {
												Janus.log("Preparing the recording playout");
												recordplay.createAnswer(
													{
														jsep: jsep,
														media: { audioSend: false, videoSend: false, data: true },	// We want recvonly audio/video
														success: function(jsep) {
															Janus.debug("Got SDP!", jsep);
															var body = { request: "start" };
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
												var id = result["id"];
												if(id) {
													Janus.log("The ID of the current recording is " + id);
													recordingId = id;
												}
											} else if(event === 'slow_link') {
												var uplink = result["uplink"];
												if(uplink !== 0) {
													// Janus detected issues when receiving our media, let's slow down
													bandwidth = parseInt(bandwidth / 1.5);
													recordplay.send({
														message: {
															request: 'configure',
															'video-bitrate-max': bandwidth,		// Reduce the bitrate
															'video-keyframe-interval': 15000	// Keep the 15 seconds key frame interval
														}
													});
												}
											} else if(event === 'playing') {
												Janus.log("Playout has started!");
											} else if(event === 'stopped') {
												Janus.log("Session has stopped!");
												var id = result["id"];
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
										var error = msg["error"];
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
								onlocalstream: function(stream) {
									if(playing === true)
										return;
									Janus.debug(" ::: Got a local stream :::", stream);
									$('#videotitle').html("Recording...");
									$('#stop').unbind('click').click(stop);
									$('#video').removeClass('hide').show();
									if($('#thevideo').length === 0)
										$('#videobox').append('<video class="rounded centered" id="thevideo" width="100%" height="100%" autoplay playsinline muted="muted"/>');
									Janus.attachMediaStream($('#thevideo').get(0), stream);
									$("#thevideo").get(0).muted = "muted";
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
									var videoTracks = stream.getVideoTracks();
									if(!videoTracks || videoTracks.length === 0) {
										// No remote video
										$('#thevideo').hide();
										if($('#videobox .no-video-container').length === 0) {
											$('#videobox').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
													'<span class="no-video-text">No remote video available</span>' +
												'</div>');
										}
									} else {
										$('#videobox .no-video-container').remove();
										$('#thevideo').removeClass('hide').show();
									}
								},
								onremotestream: function(stream) {
									if(playing === false)
										return;
									Janus.debug(" ::: Got a remote stream :::", stream);
									if($('#thevideo').length === 0) {
										$('#videotitle').html(selectedRecordingInfo);
										$('#stop').unbind('click').click(stop);
										$('#video').removeClass('hide').show();
										$('#videobox').append('<video class="rounded centered hide" id="thevideo" width="100%" height="100%" autoplay playsinline/>');
										// No remote video yet
										$('#videobox').append('<video class="rounded centered" id="waitingvideo" width="100%" height="100%" />');
										if(spinner == null) {
											var target = document.getElementById('videobox');
											spinner = new Spinner({top:100}).spin(target);
										} else {
											spinner.spin();
										}
										// Show the video, hide the spinner and show the resolution when we get a playing event
										$("#thevideo").bind("playing", function () {
											$('#waitingvideo').remove();
											$('#thevideo').removeClass('hide');
											if(spinner)
												spinner.stop();
											spinner = null;
										});
									}
									Janus.attachMediaStream($('#thevideo').get(0), stream);
									var videoTracks = stream.getVideoTracks();
									if(!videoTracks || videoTracks.length === 0) {
										// No remote video
										$('#thevideo').hide();
										if($('#videobox .no-video-container').length === 0) {
											$('#videobox').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
													'<span class="no-video-text">No remote video available</span>' +
												'</div>');
										}
									} else {
										$('#videobox .no-video-container').remove();
										$('#thevideo').removeClass('hide').show();
									}
								},
								ondataopen: function(data) {
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

function checkEnter(event) {
	var theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if(theCode == 13) {
		sendData();
		return false;
	} else {
		return true;
	}
}

function sendData() {
	var data = $('#datafield').val();
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
	var body = { request: "list" };
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
			var list = result["list"];
			list.sort(function(a, b) {return (a["date"] < b["date"]) ? 1 : ((b["date"] < a["date"]) ? -1 : 0);} );
			Janus.debug("Got a list of available recordings:", list);
			for(var mp in list) {
				Janus.debug("  >> [" + list[mp]["id"] + "] " + list[mp]["name"] + " (" + list[mp]["date"] + ")");
				$('#recslist').append("<li><a href='#' id='" + list[mp]["id"] + "'>" + list[mp]["name"] + " [" + list[mp]["date"] + "]" + "</a></li>");
			}
			$('#recslist a').unbind('click').click(function() {
				selectedRecording = $(this).attr("id");
				selectedRecordingInfo = $(this).text();
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
				// By default, it's sendrecv for audio and video... no datachannels,
				// unless we've passed the query string argument to record those too
				media: { data: (recordData != null) },
				// If you want to test simulcasting (Chrome and Firefox only), then
				// pass a ?simulcast=true when opening this demo page: it will turn
				// the following 'simulcast' property to pass to janus.js to true
				simulcast: doSimulcast,
				success: function(jsep) {
					Janus.debug("Got SDP!", jsep);
					var body = { request: "record", name: myname };
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
	var play = { request: "play", id: parseInt(selectedRecording) };
	recordplay.send({ message: play });
}

function stop() {
	// Stop a recording/playout
	$('#stop').unbind('click');
	var stop = { request: "stop" };
	recordplay.send({ message: stop });
	recordplay.hangup();
}

// Helper to parse query string
function getQueryStringValue(name) {
	name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
	var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
		results = regex.exec(location.search);
	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}
