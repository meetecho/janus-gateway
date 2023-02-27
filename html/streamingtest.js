// We import the settings.js file to know which address we should contact
// to talk to Janus, and optionally which STUN/TURN servers should be
// used as well. Specifically, that file defines the "server" and
// "iceServers" properties we'll pass when creating the Janus session.

/* global iceServers:readonly, Janus:readonly, server:readonly */

var janus = null;
var streaming = null;
var opaqueId = "streamingtest-"+Janus.randomString(12);

var remoteTracks = {}, remoteVideos = 0, dataMid = null;
var bitrateTimer = {};
var spinner = {};

var simulcastStarted = {}, svcStarted = {};

var streamsList = {};
var selectedStream = null;


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
						// Attach to Streaming plugin
						janus.attach(
							{
								plugin: "janus.plugin.streaming",
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									streaming = pluginHandle;
									Janus.log("Plugin attached! (" + streaming.getPlugin() + ", id=" + streaming.getId() + ")");
									// Setup streaming session
									$('#update-streams').click(updateStreamsList);
									updateStreamsList();
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											for(let i in bitrateTimer)
												clearInterval(bitrateTimer[i]);
											bitrateTimer = {};
											janus.destroy();
											$('#streamslist').attr('disabled', true);
											$('#watch').attr('disabled', true).unbind('click');
											$('#start').attr('disabled', true).html("Bye").unbind('click');
										});
								},
								error: function(error) {
									Janus.error("  -- Error attaching plugin... ", error);
									bootbox.alert("Error attaching plugin... " + error);
								},
								iceState: function(state) {
									Janus.log("ICE state changed to " + state);
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
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
											let status = result["status"];
											if(status === 'starting')
												$('#status').removeClass('hide').text("Starting, please wait...").show();
											else if(status === 'started')
												$('#status').removeClass('hide').text("Started").show();
											else if(status === 'stopped')
												stopStream();
										} else if(msg["streaming"] === "event") {
											// Does this event refer to a mid in particular?
											let mid = result["mid"] ? result["mid"] : "0";
											// Is simulcast in place?
											let substream = result["substream"];
											let temporal = result["temporal"];
											if((substream !== null && substream !== undefined) || (temporal !== null && temporal !== undefined)) {
												if(!simulcastStarted[mid]) {
													simulcastStarted[mid] = true;
													addSimulcastButtons(mid);
												}
												// We just received notice that there's been a switch, update the buttons
												updateSimulcastButtons(mid, substream, temporal);
											}
											// Is VP9/SVC in place?
											let spatial = result["spatial_layer"];
											temporal = result["temporal_layer"];
											if((spatial !== null && spatial !== undefined) || (temporal !== null && temporal !== undefined)) {
												if(!svcStarted[mid]) {
													svcStarted[mid] = true;
													addSvcButtons(mid);
												}
												// We just received notice that there's been a switch, update the buttons
												updateSvcButtons(mid, spatial, temporal);
											}
										}
									} else if(msg["error"]) {
										bootbox.alert(msg["error"]);
										stopStream();
										return;
									}
									if(jsep) {
										Janus.debug("Handling SDP as well...", jsep);
										let stereo = (jsep.sdp.indexOf("stereo=1") !== -1);
										// Offer from the plugin, let's answer
										streaming.createAnswer(
											{
												jsep: jsep,
												// We only specify data channels here, as this way in
												// case they were offered we'll enable them. Since we
												// don't mention audio or video tracks, we autoaccept them
												// as recvonly (since we won't capture anything ourselves)
												tracks: [
													{ type: 'data' }
												],
												customizeSdp: function(jsep) {
													if(stereo && jsep.sdp.indexOf("stereo=1") == -1) {
														// Make sure that our offer contains stereo too
														jsep.sdp = jsep.sdp.replace("useinbandfec=1", "useinbandfec=1;stereo=1");
													}
												},
												success: function(jsep) {
													Janus.debug("Got SDP!", jsep);
													let body = { request: "start" };
													streaming.send({ message: body, jsep: jsep });
													$('#watch').html("Stop").removeAttr('disabled').unbind('click').click(stopStream);
												},
												error: function(error) {
													Janus.error("WebRTC error:", error);
													bootbox.alert("WebRTC error... " + error.message);
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
									let mstreamId = "mstream"+mid;
									if(streamsList[selectedStream] && streamsList[selectedStream].legacy)
										mstreamId = "mstream0";
									if(!on) {
										// Track removed, get rid of the stream and the rendering
										$('#remotevideo' + mid).remove();
										if(track.kind === "video") {
											remoteVideos--;
											if(remoteVideos === 0) {
												// No video, at least for now: show a placeholder
												if($('#'+mstreamId+' .no-video-container').length === 0) {
													$('#'+mstreamId).append(
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
									if($('#remotevideo' + mid).length > 0)
										return;
									// If we're here, a new track was added
									let stream = null;
									if(track.kind === "audio") {
										// New audio track: create a stream out of it, and use a hidden <audio> element
										stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote audio stream:", stream);
										$('#'+mstreamId).append('<audio class="hide" id="remotevideo' + mid + '" playsinline/>');
										$('#remotevideo'+mid).get(0).volume = 0;
										if(remoteVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#'+mstreamId+' .no-video-container').length === 0) {
												$('#'+mstreamId).append(
													'<div class="no-video-container audioonly">' +
														'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
														'<span class="no-video-text">No webcam available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										remoteVideos++;
										$('.no-video-container').remove();
										stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote video stream:", stream);
										$('#'+mstreamId).append('<video class="rounded centered hide" id="remotevideo' + mid + '" width="100%" height="100%" playsinline/>');
										$('#remotevideo'+mid).get(0).volume = 0;
										// Use a custom timer for this stream
										if(!bitrateTimer[mid]) {
											$('#curbitrate'+mid).removeClass('hide').show();
											bitrateTimer[mid] = setInterval(function() {
												if(!$("#remotevideo" + mid).get(0))
													return;
												// Display updated bitrate, if supported
												let bitrate = streaming.getBitrate(mid);
												$('#curbitrate'+mid).text(bitrate);
												// Check if the resolution changed too
												let width = $("#remotevideo" + mid).get(0).videoWidth;
												let height = $("#remotevideo" + mid).get(0).videoHeight;
												if(width > 0 && height > 0)
													$('#curres'+mid).removeClass('hide').text(width+'x'+height).show();
											}, 1000);
										}
									}
									// Play the stream and hide the spinner when we get a playing event
									$("#remotevideo" + mid).bind("playing", function (ev) {
										$('.waitingvideo').remove();
										if(spinner[mid])
											spinner[mid].stop();
										spinner[mid] = null;
										if(!this.videoWidth)
											return;
										$('#'+ev.target.id).removeClass('hide').show();
										let width = this.videoWidth;
										let height = this.videoHeight;
										$('#curres'+mid).removeClass('hide').text(width+'x'+height).show();
										if(Janus.webRTCAdapter.browserDetails.browser === "firefox") {
											// Firefox Stable has a bug: width and height are not immediately available after a playing
											setTimeout(function() {
												let width = $('#'+ev.target.id).get(0).videoWidth;
												let height = $('#'+ev.target.id).get(0).videoHeight;
												$('#curres'+mid).removeClass('hide').text(width+'x'+height).show();
											}, 2000);
										}
									});
									Janus.attachMediaStream($('#remotevideo' + mid).get(0), stream);
									$('#remotevideo' + mid).get(0).play();
									$('#remotevideo' + mid).get(0).volume = 1;
								},
								// eslint-disable-next-line no-unused-vars
								ondataopen: function(label, protocol) {
									Janus.log("The DataChannel is available!");
									$('.waitingvideo').remove();
									$('#mstream' + dataMid).append(
										'<input class="form-control" type="text" id="datarecv" disabled></input>'
									);
									for(let i in spinner) {
										if(spinner[i])
											spinner[i].stop();
									}
									spinner = {};
								},
								ondata: function(data) {
									Janus.debug("We got data from the DataChannel!", data);
									$('#datarecv').val(data);
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									$('#videos').empty();
									for(let i in bitrateTimer)
										clearInterval(bitrateTimer[i]);
									bitrateTimer = {};
									for(let i in spinner) {
										if(spinner[i])
											spinner[i].stop();
									}
									spinner = {};
									simulcastStarted = false;
									remoteTracks = {};
									remoteVideos = 0;
									dataMid = null;
									$('#streamset').removeAttr('disabled');
									$('#streamslist').removeAttr('disabled');
									$('#watch').html("Watch or Listen").removeAttr('disabled')
										.unbind('click').click(startStream);
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

function updateStreamsList() {
	$('#update-streams').unbind('click').addClass('fa-spin');
	let body = { request: "list" };
	Janus.debug("Sending message:", body);
	streaming.send({ message: body, success: function(result) {
		setTimeout(function() {
			$('#update-streams').removeClass('fa-spin').unbind('click').click(updateStreamsList);
		}, 500);
		if(!result) {
			bootbox.alert("Got no response to our query for available streams");
			return;
		}
		if(result["list"]) {
			$('#streams').removeClass('hide').show();
			$('#streamslist').empty();
			$('#watch').attr('disabled', true).unbind('click');
			let list = result["list"];
			if(list && Array.isArray(list)) {
				list.sort(function(a, b) {
					if(!a || a.id < (b ? b.id : 0))
						return -1;
					if(!b || b.id < (a ? a.id : 0))
						return 1;
					return 0;
				});
			}
			Janus.log("Got a list of available streams:", list);
			streamsList = {};
			for(let mp in list) {
				Janus.debug("  >> [" + list[mp]["id"] + "] " + list[mp]["description"] + " (" + list[mp]["type"] + ")");
				$('#streamslist').append("<li><a href='#' id='" + list[mp]["id"] + "'>" + escapeXmlTags(list[mp]["description"]) + " (" + list[mp]["type"] + ")" + "</a></li>");
				// Check the nature of the available streams, and if there are some multistream ones
				list[mp].legacy = true;
				if(list[mp].media) {
					let audios = 0, videos = 0;
					for(let mi in list[mp].media) {
						if(!list[mp].media[mi])
							continue;
						if(list[mp].media[mi].type === "audio")
							audios++;
						else if(list[mp].media[mi].type === "video")
							videos++;
						if(audios > 1 || videos > 1) {
							list[mp].legacy = false;
							break;
						}
					}
				}
				// Keep track of all the available streams
				streamsList[list[mp]["id"]] = list[mp];
			}
			$('#streamslist a').unbind('click').click(function() {
				selectedStream = $(this).attr("id");
				$('#streamset').html($(this).html()).parent().removeClass('open');
				$('#list .dropdown-backdrop').remove();
				return false;

			});
			$('#watch').removeAttr('disabled').unbind('click').click(startStream);
		}
	}});
}

function getStreamInfo() {
	$('#metadata').empty();
	$('#info').addClass('hide').hide();
	if(!selectedStream || !streamsList[selectedStream])
		return;
	// Send a request for more info on the mountpoint we subscribed to
	let body = { request: "info", id: parseInt(selectedStream) || selectedStream };
	streaming.send({ message: body, success: function(result) {
		if(result && result.info && result.info.metadata) {
			$('#metadata').html(escapeXmlTags(result.info.metadata));
			$('#info').removeClass('hide').show();
		}
	}});
}

function startStream() {
	Janus.log("Selected video id #" + selectedStream);
	if(!selectedStream || !streamsList[selectedStream]) {
		bootbox.alert("Select a stream from the list");
		return;
	}
	$('#streamset').attr('disabled', true);
	$('#streamslist').attr('disabled', true);
	$('#watch').attr('disabled', true).unbind('click');
	// Add some panels to host the remote streams
	if(streamsList[selectedStream].legacy) {
		// At max 1-audio/1-video, so use a single panel
		let mid = null;
		for(let mi in streamsList[selectedStream].media) {
			// Add a new panel
			let type = streamsList[selectedStream].media[mi].type;
			if(type === "video") {
				mid = streamsList[selectedStream].media[mi].mid;
				break;
			}
		}
		if($('#mstream0').length === 0) {
			addPanel("0", mid);
			// No remote video yet
			$('#mstream0').append('<video class="rounded centered waitingvideo" id="waitingvideo0" width="100%" height="100%" />');
		}
		if(mid) {
			if(spinner[mid] == null) {
				let target = document.getElementById('mstream0');
				spinner[mid] = new Spinner({top:100}).spin(target);
			} else {
				spinner[mid].spin();
			}
		}
		dataMid = "0";
	} else {
		// Multistream mountpoint, create a panel for each stream
		for(let mi in streamsList[selectedStream].media) {
			// Add a new panel
			let type = streamsList[selectedStream].media[mi].type;
			let mid = streamsList[selectedStream].media[mi].mid;
			let label = streamsList[selectedStream].media[mi].label;
			if($('#mstream'+mid).length === 0) {
				addPanel(mid, mid, label);
				// No remote media yet
				$('#mstream'+mid).append('<video class="rounded centered waitingvideo" id="waitingvideo'+mid+'" width="100%" height="100%" />');
			}
			if(spinner[mid] == null) {
				let target = document.getElementById('mstream'+mid);
				spinner[mid] = new Spinner({top:100}).spin(target);
			} else {
				spinner[mid].spin();
			}
			if(type === 'data')
				dataMid = mid;
		}
	}
	// Prepare the request to start streaming and send it
	let body = { request: "watch", id: parseInt(selectedStream) || selectedStream };
	// Notice that, for RTP mountpoints, you can subscribe to a subset
	// of the mountpoint media, rather than them all, by adding a "stream"
	// array containing the list of stream mids you're interested in, e.g.:
	//
	//		body.streams = [ "0", "2" ];
	//
	// to only subscribe to the first and third stream, and skip the second
	// (assuming those are the mids you got from a "list" or "info" request).
	// By default, you always subscribe to all the streams in a mountpoint
	streaming.send({ message: body });
	// Get some more info for the mountpoint to display, if any
	getStreamInfo();
}

function stopStream() {
	$('#watch').attr('disabled', true).unbind('click');
	let body = { request: "stop" };
	streaming.send({ message: body });
	streaming.hangup();
}

// Helper to escape XML tags
function escapeXmlTags(value) {
	if(value) {
		let escapedValue = value.replace(new RegExp('<', 'g'), '&lt');
		escapedValue = escapedValue.replace(new RegExp('>', 'g'), '&gt');
		return escapedValue;
	}
}

// Helper to add a new panel to the 'videos' div
function addPanel(panelId, mid, desc) {
	$('#videos').append(
		'<div class="row" id="panel' + panelId + '">' +
		'	<div class="panel panel-default">' +
		'		<div class="panel-heading">' +
		'			<h3 class="panel-title">' + (desc ? desc : "Stream") +
		'				<span class="label label-info hide" id="status' + mid + '"></span>' +
		'				<span class="label label-primary hide" id="curres' + mid + '"></span>' +
		'				<span class="label label-info hide" id="curbitrate' + mid + '"></span>' +
		'			</h3>' +
		'		</div>' +
		'		<div class="panel-body" id="mstream' + panelId + '"></div>' +
		'	</div>' +
		'</div>'
	);
}

// Helpers to create Simulcast-related UI, if enabled
function addSimulcastButtons(mid) {
	$('#curres'+mid).parent().append(
		'<div id="simulcast'+mid+'" class="btn-group-vertical btn-group-vertical-xs pull-right">' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs" style="width: 100%">' +
		'			<button id="m-'+mid+'-sl-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to higher quality" style="width: 33%">SL 2</button>' +
		'			<button id="m-'+mid+'-sl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to normal quality" style="width: 33%">SL 1</button>' +
		'			<button id="m-'+mid+'-sl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to lower quality" style="width: 34%">SL 0</button>' +
		'		</div>' +
		'	</div>' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs hide" style="width: 100%">' +
		'			<button id="m-'+mid+'-tl-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 2" style="width: 34%">TL 2</button>' +
		'			<button id="m-'+mid+'-tl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 1" style="width: 33%">TL 1</button>' +
		'			<button id="m-'+mid+'-tl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 0" style="width: 33%">TL 0</button>' +
		'		</div>' +
		'	</div>' +
		'</div>');
	// Enable the simulcast selection buttons
	$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching simulcast substream, wait for it... (lower quality)", null, {timeOut: 2000});
			if(!$('#m-'+mid+'-sl-2').hasClass('btn-success'))
				$('#m-'+mid+'-sl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#m-'+mid+'-sl-1').hasClass('btn-success'))
				$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			streaming.send({ message: { request: "configure", mid: mid, substream: 0 }});
		});
	$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching simulcast substream, wait for it... (normal quality)", null, {timeOut: 2000});
			if(!$('#m-'+mid+'-sl-2').hasClass('btn-success'))
				$('#m-'+mid+'-sl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#m-'+mid+'-sl-0').hasClass('btn-success'))
				$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({ message: { request: "configure", mid: mid, substream: 1 }});
		});
	$('#m-'+mid+'-sl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching simulcast substream, wait for it... (higher quality)", null, {timeOut: 2000});
			$('#m-'+mid+'-sl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#m-'+mid+'-sl-1').hasClass('btn-success'))
				$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#m-'+mid+'-sl-0').hasClass('btn-success'))
				$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({ message: { request: "configure", mid: mid, substream: 2 }});
		});
	// We always add temporal layer buttons too, even though these will only work with vP8
	$('#m-'+mid+'-tl-0').parent().removeClass('hide');
	$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping simulcast temporal layer, wait for it... (lowest FPS)", null, {timeOut: 2000});
			if(!$('#m-'+mid+'-tl-2').hasClass('btn-success'))
				$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#m-'+mid+'-tl-1').hasClass('btn-success'))
				$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			streaming.send({ message: { request: "configure", mid: mid, temporal: 0 }});
		});
	$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping simulcast temporal layer, wait for it... (medium FPS)", null, {timeOut: 2000});
			if(!$('#m-'+mid+'-tl-2').hasClass('btn-success'))
				$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-info').addClass('btn-info');
			if(!$('#m-'+mid+'-tl-0').hasClass('btn-success'))
				$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({ message: { request: "configure", mid: mid, temporal: 1 }});
		});
	$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping simulcast temporal layer, wait for it... (highest FPS)", null, {timeOut: 2000});
			$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#m-'+mid+'-tl-1').hasClass('btn-success'))
				$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#m-'+mid+'-tl-0').hasClass('btn-success'))
				$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({ message: { request: "configure", mid: mid, temporal: 2 }});
		});
}

function updateSimulcastButtons(mid, substream, temporal) {
	// Check the substream
	if(substream === 0) {
		toastr.success("Switched simulcast substream! (lower quality)", null, {timeOut: 2000});
		$('#m-'+mid+'-sl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(substream === 1) {
		toastr.success("Switched simulcast substream! (normal quality)", null, {timeOut: 2000});
		$('#m-'+mid+'-sl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(substream === 2) {
		toastr.success("Switched simulcast substream! (higher quality)", null, {timeOut: 2000});
		$('#m-'+mid+'-sl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
	// Check the temporal layer
	if(temporal === 0) {
		toastr.success("Capped simulcast temporal layer! (lowest FPS)", null, {timeOut: 2000});
		$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(temporal === 1) {
		toastr.success("Capped simulcast temporal layer! (medium FPS)", null, {timeOut: 2000});
		$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(temporal === 2) {
		toastr.success("Capped simulcast temporal layer! (highest FPS)", null, {timeOut: 2000});
		$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
}

// Helpers to create SVC-related UI for a new viewer
function addSvcButtons(mid) {
	if($('#svc').length > 0)
		return;
	$('#curres'+mid).parent().append(
		'<div id="svc'+mid+'" class="btn-group-vertical btn-group-vertical-xs pull-right">' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs" style="width: 100%">' +
		'			<button id="m-'+mid+'-sl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to normal resolution" style="width: 50%">SL 1</button>' +
		'			<button id="m-'+mid+'-sl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to low resolution" style="width: 50%">SL 0</button>' +
		'		</div>' +
		'	</div>' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs" style="width: 100%">' +
		'			<button id="m-'+mid+'-tl-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 2 (high FPS)" style="width: 34%">TL 2</button>' +
		'			<button id="m-'+mid+'-tl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 1 (medium FPS)" style="width: 33%">TL 1</button>' +
		'			<button id="m-'+mid+'-tl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 0 (low FPS)" style="width: 33%">TL 0</button>' +
		'		</div>' +
		'	</div>' +
		'</div>'
	);
	// Enable the SVC selection buttons
	$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching SVC spatial layer, wait for it... (low resolution)", null, {timeOut: 2000});
			if(!$('#m-'+mid+'-sl-1').hasClass('btn-success'))
				$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			streaming.send({ message: { request: "configure", mid: mid, spatial_layer: 0 }});
		});
	$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching SVC spatial layer, wait for it... (normal resolution)", null, {timeOut: 2000});
			$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#m-'+mid+'-sl-0').hasClass('btn-success'))
				$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({ message: { request: "configure", mid: mid, spatial_layer: 1 }});
		});
	$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping SVC temporal layer, wait for it... (lowest FPS)", null, {timeOut: 2000});
			if(!$('#m-'+mid+'-tl-2').hasClass('btn-success'))
				$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#m-'+mid+'-tl-1').hasClass('btn-success'))
				$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			streaming.send({ message: { request: "configure", mid: mid, temporal_layer: 0 }});
		});
	$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping SVC temporal layer, wait for it... (medium FPS)", null, {timeOut: 2000});
			if(!$('#m-'+mid+'-tl-2').hasClass('btn-success'))
				$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-info').addClass('btn-info');
			if(!$('#m-'+mid+'-tl-0').hasClass('btn-success'))
				$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({ message: { request: "configure", mid: mid, temporal_layer: 1 }});
		});
	$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping SVC temporal layer, wait for it... (highest FPS)", null, {timeOut: 2000});
			$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#m-'+mid+'-tl-1').hasClass('btn-success'))
				$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#m-'+mid+'-tl-0').hasClass('btn-success'))
				$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({ message: { request: "configure", mid: mid, temporal_layer: 2 }});
		});
}

function updateSvcButtons(mid, spatial, temporal) {
	// Check the spatial layer
	if(spatial === 0) {
		toastr.success("Switched SVC spatial layer! (lower resolution)", null, {timeOut: 2000});
		$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(spatial === 1) {
		toastr.success("Switched SVC spatial layer! (normal resolution)", null, {timeOut: 2000});
		$('#m-'+mid+'-sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#m-'+mid+'-sl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
	// Check the temporal layer
	if(temporal === 0) {
		toastr.success("Capped SVC temporal layer! (lowest FPS)", null, {timeOut: 2000});
		$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(temporal === 1) {
		toastr.success("Capped SVC temporal layer! (medium FPS)", null, {timeOut: 2000});
		$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(temporal === 2) {
		toastr.success("Capped SVC temporal layer! (highest FPS)", null, {timeOut: 2000});
		$('#m-'+mid+'-tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#m-'+mid+'-tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#m-'+mid+'-tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
}
