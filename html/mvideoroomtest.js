// We import the settings.js file to know which address we should contact
// to talk to Janus, and optionally which STUN/TURN servers should be
// used as well. Specifically, that file defines the "server" and
// "iceServers" properties we'll pass when creating the Janus session.

/* global iceServers:readonly, Janus:readonly, server:readonly */

var janus = null;
var sfutest = null;
var opaqueId = "videoroomtest-"+Janus.randomString(12);

var myroom = 1234;	// Demo room
if(getQueryStringValue("room") !== "")
	myroom = parseInt(getQueryStringValue("room"));
var myusername = null;
var myid = null;
var mystream = null;
// We use this other ID just to map our subscriptions to us
var mypvtid = null;

var remoteFeed = null;
var feeds = {}, feedStreams = {}, subStreams = {}, slots = {}, mids = {}, subscriptions = {};
var localTracks = {}, localVideos = 0, remoteTracks = {};
var bitrateTimer = [], simulcastStarted = {}, svcStarted = {};

var doSimulcast = (getQueryStringValue("simulcast") === "yes" || getQueryStringValue("simulcast") === "true");
var doSvc = getQueryStringValue("svc");
if(doSvc === "")
	doSvc = null;
var acodec = (getQueryStringValue("acodec") !== "" ? getQueryStringValue("acodec") : null);
var vcodec = (getQueryStringValue("vcodec") !== "" ? getQueryStringValue("vcodec") : null);
var subscriber_mode = (getQueryStringValue("subscriber-mode") === "yes" || getQueryStringValue("subscriber-mode") === "true");
var use_msid = (getQueryStringValue("msid") === "yes" || getQueryStringValue("msid") === "true");

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
						// Attach to video room test plugin
						janus.attach(
							{
								plugin: "janus.plugin.videoroom",
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									sfutest = pluginHandle;
									Janus.log("Plugin attached! (" + sfutest.getPlugin() + ", id=" + sfutest.getId() + ")");
									Janus.log("  -- This is a publisher/manager");
									// Prepare the username registration
									$('#videojoin').removeClass('hide').show();
									$('#registernow').removeClass('hide').show();
									$('#register').click(registerUsername);
									$('#username').focus();
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											janus.destroy();
										});
								},
								error: function(error) {
									Janus.error("  -- Error attaching plugin...", error);
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
									$("#videolocal").parent().parent().unblock();
									if(!on)
										return;
									$('#publish').remove();
									// This controls allows us to override the global room bitrate cap
									$('#bitrate').parent().parent().removeClass('hide').show();
									$('#bitrate a').click(function() {
										let id = $(this).attr("id");
										let bitrate = parseInt(id)*1000;
										if(bitrate === 0) {
											Janus.log("Not limiting bandwidth via REMB");
										} else {
											Janus.log("Capping bandwidth to " + bitrate + " via REMB");
										}
										$('#bitrateset').html($(this).html() + '<span class="caret"></span>').parent().removeClass('open');
										sfutest.send({ message: { request: "configure", bitrate: bitrate }});
										return false;
									});
								},
								slowLink: function(uplink, lost, mid) {
									Janus.warn("Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on mid " + mid + " (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message (publisher) :::", msg);
									let event = msg["videoroom"];
									Janus.debug("Event: " + event);
									if(event != undefined && event != null) {
										if(event === "joined") {
											// Publisher/manager created, negotiate WebRTC and attach to existing feeds, if any
											myid = msg["id"];
											mypvtid = msg["private_id"];
											Janus.log("Successfully joined room " + msg["room"] + " with ID " + myid);
											if(subscriber_mode) {
												$('#videojoin').hide();
												$('#videos').removeClass('hide').show();
											} else {
												publishOwnFeed(true);
											}
											// Any new feed to attach to?
											if(msg["publishers"]) {
												let list = msg["publishers"];
												Janus.debug("Got a list of available publishers/feeds:", list);
												let sources = null;
												for(let f in list) {
													if(list[f]["dummy"])
														continue;
													let id = list[f]["id"];
													let display = list[f]["display"];
													let streams = list[f]["streams"];
													for(let i in streams) {
														let stream = streams[i];
														stream["id"] = id;
														stream["display"] = display;
													}
													let slot = feedStreams[id] ? feedStreams[id].slot : null;
													let remoteVideos = feedStreams[id] ? feedStreams[id].remoteVideos : 0;
													feedStreams[id] = {
														id: id,
														display: display,
														streams: streams,
														slot: slot,
														remoteVideos: remoteVideos
													}
													Janus.debug("  >> [" + id + "] " + display + ":", streams);
													if(!sources)
														sources = [];
													sources.push(streams);
												}
												if(sources)
													subscribeTo(sources);
											}
										} else if(event === "destroyed") {
											// The room has been destroyed
											Janus.warn("The room has been destroyed!");
											bootbox.alert("The room has been destroyed", function() {
												window.location.reload();
											});
										} else if(event === "event") {
											// Any info on our streams or a new feed to attach to?
											if(msg["streams"]) {
												let streams = msg["streams"];
												for(let i in streams) {
													let stream = streams[i];
													stream["id"] = myid;
													stream["display"] = myusername;
												}
												feedStreams[myid] = {
													id: myid,
													display: myusername,
													streams: streams
												}
											} else if(msg["publishers"]) {
												let list = msg["publishers"];
												Janus.debug("Got a list of available publishers/feeds:", list);
												let sources = null;
												for(let f in list) {
													if(list[f]["dummy"])
														continue;
													let id = list[f]["id"];
													let display = list[f]["display"];
													let streams = list[f]["streams"];
													for(let i in streams) {
														let stream = streams[i];
														stream["id"] = id;
														stream["display"] = display;
													}
													let slot = feedStreams[id] ? feedStreams[id].slot : null;
													let remoteVideos = feedStreams[id] ? feedStreams[id].remoteVideos : 0;
													feedStreams[id] = {
														id: id,
														display: display,
														streams: streams,
														slot: slot,
														remoteVideos: remoteVideos
													}
													Janus.debug("  >> [" + id + "] " + display + ":", streams);
													if(!sources)
														sources = [];
													sources.push(streams);
												}
												if(sources)
													subscribeTo(sources);
											} else if(msg["leaving"]) {
												// One of the publishers has gone away?
												let leaving = msg["leaving"];
												Janus.log("Publisher left: " + leaving);
												unsubscribeFrom(leaving);
											} else if(msg["unpublished"]) {
												// One of the publishers has unpublished?
												let unpublished = msg["unpublished"];
												Janus.log("Publisher left: " + unpublished);
												if(unpublished === 'ok') {
													// That's us
													sfutest.hangup();
													return;
												}
												unsubscribeFrom(unpublished);
											} else if(msg["error"]) {
												if(msg["error_code"] === 426) {
													// This is a "no such room" error: give a more meaningful description
													bootbox.alert(
														"<p>Apparently room <code>" + myroom + "</code> (the one this demo uses as a test room) " +
														"does not exist...</p><p>Do you have an updated <code>janus.plugin.videoroom.cfg</code> " +
														"configuration file? If not, make sure you copy the details of room <code>" + myroom + "</code> " +
														"from that sample in your current configuration file, then restart Janus and try again."
													);
												} else {
													bootbox.alert(msg["error"]);
												}
											}
										}
									}
									if(jsep) {
										Janus.debug("Handling SDP as well...", jsep);
										sfutest.handleRemoteJsep({ jsep: jsep });
										// Check if any of the media we wanted to publish has
										// been rejected (e.g., wrong or unsupported codec)
										let audio = msg["audio_codec"];
										if(mystream && mystream.getAudioTracks() && mystream.getAudioTracks().length > 0 && !audio) {
											// Audio has been rejected
											toastr.warning("Our audio stream has been rejected, viewers won't hear us");
										}
										let video = msg["video_codec"];
										if(mystream && mystream.getVideoTracks() && mystream.getVideoTracks().length > 0 && !video) {
											// Video has been rejected
											toastr.warning("Our video stream has been rejected, viewers won't see us");
											// Hide the webcam video
											$('#myvideo').hide();
											$('#videolocal').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon" style="height: 100%;"></i>' +
													'<span class="no-video-text" style="font-size: 16px;">Video rejected, no webcam</span>' +
												'</div>');
										}
									}
								},
								onlocaltrack: function(track, on) {
									Janus.debug(" ::: Got a local track event :::");
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
												if($('#videolocal .no-video-container').length === 0) {
													$('#videolocal').append(
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
									$('#videos').removeClass('hide').show();
									if($('#mute').length === 0) {
										// Add a 'mute' button
										$('#videolocal').append('<button class="btn btn-warning btn-xs" id="mute" style="position: absolute; bottom: 0px; left: 0px; margin: 15px;">Mute</button>');
										$('#mute').click(toggleMute);
										// Add an 'unpublish' button
										$('#videolocal').append('<button class="btn btn-warning btn-xs" id="unpublish" style="position: absolute; bottom: 0px; right: 0px; margin: 15px;">Unpublish</button>');
										$('#unpublish').click(unpublishOwnFeed);
									}
									if(track.kind === "audio") {
										// We ignore local audio tracks, they'd generate echo anyway
										if(localVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videolocal .no-video-container').length === 0) {
												$('#videolocal').append(
													'<div class="no-video-container">' +
														'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
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
										Janus.log(stream.getTracks());
										Janus.log(stream.getVideoTracks());
										$('#videolocal').append('<video class="rounded centered" id="myvideo' + trackId + '" width=100% autoplay playsinline muted="muted"/>');
										Janus.attachMediaStream($('#myvideo' + trackId).get(0), stream);
									}
									if(sfutest.webrtcStuff.pc.iceConnectionState !== "completed" &&
											sfutest.webrtcStuff.pc.iceConnectionState !== "connected") {
										$("#videolocal").parent().parent().block({
											message: '<b>Publishing...</b>',
											css: {
												border: 'none',
												backgroundColor: 'transparent',
												color: 'white'
											}
										});
									}
								},
								// eslint-disable-next-line no-unused-vars
								onremotetrack: function(track, mid, on) {
									// The publisher stream is sendonly, we don't expect anything here
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification: we are unpublished now :::");
									mystream = null;
									delete feedStreams[myid];
									$('#videolocal').html('<button id="publish" class="btn btn-primary">Publish</button>');
									$('#publish').click(function() { publishOwnFeed(true); });
									$("#videolocal").parent().parent().unblock();
									$('#bitrate').parent().parent().addClass('hide');
									$('#bitrate a').unbind('click');
									localTracks = {};
									localVideos = 0;
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
function checkEnter(field, event) {
	let theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if(theCode == 13) {
		registerUsername();
		return false;
	} else {
		return true;
	}
}

function registerUsername() {
	if($('#username').length === 0) {
		// Create fields to register
		$('#register').click(registerUsername);
		$('#username').focus();
	} else {
		// Try a registration
		$('#username').attr('disabled', true);
		$('#register').attr('disabled', true).unbind('click');
		let username = $('#username').val();
		if(username === "") {
			$('#you')
				.removeClass().addClass('label label-warning')
				.html("Insert your display name (e.g., pippo)");
			$('#username').removeAttr('disabled');
			$('#register').removeAttr('disabled').click(registerUsername);
			return;
		}
		if(/[^a-zA-Z0-9]/.test(username)) {
			$('#you')
				.removeClass().addClass('label label-warning')
				.html('Input is not alphanumeric');
			$('#username').removeAttr('disabled').val("");
			$('#register').removeAttr('disabled').click(registerUsername);
			return;
		}
		let register = {
			request: "join",
			room: myroom,
			ptype: "publisher",
			display: username
		};
		myusername = escapeXmlTags(username);
		sfutest.send({ message: register });
	}
}

function publishOwnFeed(useAudio) {
	// Publish our stream
	$('#publish').attr('disabled', true).unbind('click');

	// We want sendonly audio and video (uncomment the data track
	// too if you want to publish via datachannels as well)
	let tracks = [];
	if(useAudio)
		tracks.push({ type: 'audio', capture: true, recv: false });
	tracks.push({ type: 'video', capture: true, recv: false,
		// We may need to enable simulcast or SVC on the video track
		simulcast: doSimulcast,
		// We only support SVC for VP9 and (still WIP) AV1
		svc: ((vcodec === 'vp9' || vcodec === 'av1') && doSvc) ? doSvc : null
	});
	//~ tracks.push({ type: 'data' });

	sfutest.createOffer(
		{
			tracks: tracks,
			success: function(jsep) {
				Janus.debug("Got publisher SDP!");
				Janus.debug(jsep);
				let publish = { request: "configure", audio: useAudio, video: true };
				// You can force a specific codec to use when publishing by using the
				// audiocodec and videocodec properties, for instance:
				// 		publish["audiocodec"] = "opus"
				// to force Opus as the audio codec to use, or:
				// 		publish["videocodec"] = "vp9"
				// to force VP9 as the videocodec to use. In both case, though, forcing
				// a codec will only work if: (1) the codec is actually in the SDP (and
				// so the browser supports it), and (2) the codec is in the list of
				// allowed codecs in a room. With respect to the point (2) above,
				// refer to the text in janus.plugin.videoroom.cfg for more details
				if(acodec)
					publish["audiocodec"] = acodec;
				if(vcodec)
					publish["videocodec"] = vcodec;
				sfutest.send({ message: publish, jsep: jsep });
			},
			error: function(error) {
				Janus.error("WebRTC error:", error);
				if (useAudio) {
					publishOwnFeed(false);
				} else {
					bootbox.alert("WebRTC error... " + error.message);
					$('#publish').removeAttr('disabled').click(function() { publishOwnFeed(true); });
				}
			}
		});
}

function toggleMute() {
	let muted = sfutest.isAudioMuted();
	Janus.log((muted ? "Unmuting" : "Muting") + " local stream...");
	if(muted)
		sfutest.unmuteAudio();
	else
		sfutest.muteAudio();
	muted = sfutest.isAudioMuted();
	$('#mute').html(muted ? "Unmute" : "Mute");
}

function unpublishOwnFeed() {
	// Unpublish our stream
	$('#unpublish').attr('disabled', true).unbind('click');
	let unpublish = { request: "unpublish" };
	sfutest.send({ message: unpublish });
}

var creatingSubscription = false;
function subscribeTo(sources) {
	// Check if we're still creating the subscription handle
	if(creatingSubscription) {
		// Still working on the handle, send this request later when it's ready
		setTimeout(function() {
			subscribeTo(sources);
		}, 500);
		return;
	}
	// If we already have a working subscription handle, just update that one
	if(remoteFeed) {
		// Prepare the streams to subscribe to, as an array: we have the list of
		// streams the feeds are publishing, so we can choose what to pick or skip
		let added = null, removed = null;
		for(let s in sources) {
			let streams = sources[s];
			for(let i in streams) {
				let stream = streams[i];
				// If the publisher is VP8/VP9 and this is an older Safari, let's avoid video
				if(stream.type === "video" && Janus.webRTCAdapter.browserDetails.browser === "safari" &&
						((stream.codec === "vp9" && !Janus.safariVp9) || (stream.codec === "vp8" && !Janus.safariVp8))) {
					toastr.warning("Publisher is using " + stream.codec.toUpperCase +
						", but Safari doesn't support it: disabling video stream #" + stream.mindex);
					continue;
				}
				if(stream.disabled) {
					Janus.log("Disabled stream:", stream);
					// Unsubscribe
					if(!removed)
						removed = [];
					removed.push({
						feed: stream.id,	// This is mandatory
						mid: stream.mid		// This is optional (all streams, if missing)
					});
					delete subscriptions[stream.id][stream.mid];
					continue;
				}
				if(subscriptions[stream.id] && subscriptions[stream.id][stream.mid]) {
					Janus.log("Already subscribed to stream, skipping:", stream);
					continue;
				}
				// Find an empty slot in the UI for each new source
				if(!feedStreams[stream.id].slot) {
					let slot;
					for(let i=1;i<6;i++) {
						if(!feeds[i]) {
							slot = i;
							feeds[slot] = stream.id;
							feedStreams[stream.id].slot = slot;
							feedStreams[stream.id].remoteVideos = 0;
							$('#remote' + slot).removeClass('hide').html(escapeXmlTags(stream.display)).show();
							break;
						}
					}
				}
				// Subscribe
				if(!added)
					added = [];
				added.push({
					feed: stream.id,	// This is mandatory
					mid: stream.mid		// This is optional (all streams, if missing)
				});
				if(!subscriptions[stream.id])
					subscriptions[stream.id] = {};
				subscriptions[stream.id][stream.mid] = true;
			}
		}
		if((!added || added.length === 0) && (!removed || removed.length === 0)) {
			// Nothing to do
			return;
		}
		let update = { request: 'update' };
		if(added)
			update.subscribe = added;
		if(removed)
			update.unsubscribe = removed;
		remoteFeed.send({ message: update });
		// Nothing else we need to do
		return;
	}
	// If we got here, we're creating a new handle for the subscriptions (we only need one)
	creatingSubscription = true;
	janus.attach(
		{
			plugin: "janus.plugin.videoroom",
			opaqueId: opaqueId,
			success: function(pluginHandle) {
				remoteFeed = pluginHandle;
				remoteTracks = {};
				Janus.log("Plugin attached! (" + remoteFeed.getPlugin() + ", id=" + remoteFeed.getId() + ")");
				Janus.log("  -- This is a multistream subscriber");
				// Prepare the streams to subscribe to, as an array: we have the list of
				// streams the feed is publishing, so we can choose what to pick or skip
				let subscription = [];
				for(let s in sources) {
					let streams = sources[s];
					for(let i in streams) {
						let stream = streams[i];
						// If the publisher is VP8/VP9 and this is an older Safari, let's avoid video
						if(stream.type === "video" && Janus.webRTCAdapter.browserDetails.browser === "safari" &&
								((stream.codec === "vp9" && !Janus.safariVp9) || (stream.codec === "vp8" && !Janus.safariVp8))) {
							toastr.warning("Publisher is using " + stream.codec.toUpperCase +
								", but Safari doesn't support it: disabling video stream #" + stream.mindex);
							continue;
						}
						if(stream.disabled) {
							Janus.log("Disabled stream:", stream);
							// TODO Skipping for now, we should unsubscribe
							continue;
						}
						Janus.log("Subscribed to " + stream.id + "/" + stream.mid + "?", subscriptions);
						if(subscriptions[stream.id] && subscriptions[stream.id][stream.mid]) {
							Janus.log("Already subscribed to stream, skipping:", stream);
							continue;
						}
						// Find an empty slot in the UI for each new source
						if(!feedStreams[stream.id].slot) {
							let slot;
							for(let i=1;i<6;i++) {
								if(!feeds[i]) {
									slot = i;
									feeds[slot] = stream.id;
									feedStreams[stream.id].slot = slot;
									feedStreams[stream.id].remoteVideos = 0;
									$('#remote' + slot).removeClass('hide').html(escapeXmlTags(stream.display)).show();
									break;
								}
							}
						}
						subscription.push({
							feed: stream.id,	// This is mandatory
							mid: stream.mid		// This is optional (all streams, if missing)
						});
						if(!subscriptions[stream.id])
							subscriptions[stream.id] = {};
						subscriptions[stream.id][stream.mid] = true;
					}
				}
				// We wait for the plugin to send us an offer
				let subscribe = {
					request: "join",
					room: myroom,
					ptype: "subscriber",
					streams: subscription,
					use_msid: use_msid,
					private_id: mypvtid
				};
				remoteFeed.send({ message: subscribe });
			},
			error: function(error) {
				Janus.error("  -- Error attaching plugin...", error);
				bootbox.alert("Error attaching plugin... " + error);
			},
			iceState: function(state) {
				Janus.log("ICE state (remote feed) changed to " + state);
			},
			webrtcState: function(on) {
				Janus.log("Janus says this WebRTC PeerConnection (remote feed) is " + (on ? "up" : "down") + " now");
			},
			slowLink: function(uplink, lost, mid) {
				Janus.warn("Janus reports problems " + (uplink ? "sending" : "receiving") +
					" packets on mid " + mid + " (" + lost + " lost packets)");
			},
			onmessage: function(msg, jsep) {
				Janus.debug(" ::: Got a message (subscriber) :::", msg);
				let event = msg["videoroom"];
				Janus.debug("Event: " + event);
				if(msg["error"]) {
					bootbox.alert(msg["error"]);
				} else if(event) {
					if(event === "attached") {
						// Now we have a working subscription, next requests will update this one
						creatingSubscription = false;
						Janus.log("Successfully attached to feed in room " + msg["room"]);
					} else if(event === "event") {
						// Check if we got an event on a simulcast-related event from this publisher
						let mid = msg["mid"];
						let substream = msg["substream"];
						let temporal = msg["temporal"];
						if((substream !== null && substream !== undefined) || (temporal !== null && temporal !== undefined)) {
							// Check which this feed this refers to
							let slot = slots[mid];
							if(!simulcastStarted[slot]) {
								simulcastStarted[slot] = true;
								// Add some new buttons
								addSimulcastSvcButtons(slot, true);
							}
							// We just received notice that there's been a switch, update the buttons
							updateSimulcastSvcButtons(slot, substream, temporal);
						}
						// Or maybe SVC?
						let spatial = msg["spatial_layer"];
						temporal = msg["temporal_layer"];
						if((spatial !== null && spatial !== undefined) || (temporal !== null && temporal !== undefined)) {
							let slot = slots[mid];
							if(!svcStarted[slot]) {
								svcStarted[slot] = true;
								// Add some new buttons
								addSimulcastSvcButtons(slot, true);
							}
							// We just received notice that there's been a switch, update the buttons
							updateSimulcastSvcButtons(slot, spatial, temporal);
						}
					} else {
						// What has just happened?
					}
				}
				if(msg["streams"]) {
					// Update map of subscriptions by mid
					for(let i in msg["streams"]) {
						let mid = msg["streams"][i]["mid"];
						subStreams[mid] = msg["streams"][i];
						let feed = feedStreams[msg["streams"][i]["feed_id"]];
						if(feed && feed.slot) {
							slots[mid] = feed.slot;
							mids[feed.slot] = mid;
						}
					}
				}
				if(jsep) {
					Janus.debug("Handling SDP as well...", jsep);
					// Answer and attach
					remoteFeed.createAnswer(
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
								Janus.debug("Got SDP!");
								Janus.debug(jsep);
								let body = { request: "start", room: myroom };
								remoteFeed.send({ message: body, jsep: jsep });
							},
							error: function(error) {
								Janus.error("WebRTC error:", error);
								bootbox.alert("WebRTC error... " + error.message);
							}
						});
				}
			},
			// eslint-disable-next-line no-unused-vars
			onlocaltrack: function(track, on) {
				// The subscriber stream is recvonly, we don't expect anything here
			},
			onremotetrack: function(track, mid, on, metadata) {
				Janus.debug(
					"Remote track (mid=" + mid + ") " +
					(on ? "added" : "removed") +
					(metadata ? " (" + metadata.reason + ") ": "") + ":", track
				);
				// Which publisher are we getting on this mid?
				let sub = subStreams[mid];
				let feed = feedStreams[sub.feed_id];
				Janus.debug(" >> This track is coming from feed " + sub.feed_id + ":", feed);
				let slot = slots[mid];
				if(feed && !slot) {
					slot = feed.slot;
					slots[mid] = feed.slot;
					mids[feed.slot] = mid;
				}
				Janus.debug(" >> mid " + mid + " is in slot " + slot);
				if(!on) {
					// Track removed, get rid of the stream and the rendering
					$('#remotevideo' + slot + '-' + mid).remove();
					if(track.kind === "video" && feed) {
						feed.remoteVideos--;
						if(feed.remoteVideos === 0) {
							// No video, at least for now: show a placeholder
							if($('#videoremote' + slot + ' .no-video-container').length === 0) {
								$('#videoremote' + slot).append(
									'<div class="no-video-container">' +
										'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
										'<span class="no-video-text">No remote video available</span>' +
									'</div>');
							}
						}
					}
					delete remoteTracks[mid];
					delete slots[mid];
					delete mids[slot];
					return;
				}
				// If we're here, a new track was added
				if(feed.spinner) {
					feed.spinner.stop();
					feed.spinner = null;
				}
				if($('#remotevideo' + slot + '-' + mid).length > 0)
					return;
				if(track.kind === "audio") {
					// New audio track: create a stream out of it, and use a hidden <audio> element
					let stream = new MediaStream([track]);
					remoteTracks[mid] = stream;
					Janus.log("Created remote audio stream:", stream);
					$('#videoremote' + slot).append('<audio class="hide" id="remotevideo' + slot + '-' + mid + '" autoplay playsinline/>');
					Janus.attachMediaStream($('#remotevideo' + slot + '-' + mid).get(0), stream);
					if(feed.remoteVideos === 0) {
						// No video, at least for now: show a placeholder
						if($('#videoremote' + slot + ' .no-video-container').length === 0) {
							$('#videoremote' + slot).append(
								'<div class="no-video-container">' +
									'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
									'<span class="no-video-text">No remote video available</span>' +
								'</div>');
						}
					}
				} else {
					// New video track: create a stream out of it
					feed.remoteVideos++;
					$('#videoremote' + slot + ' .no-video-container').remove();
					let stream = new MediaStream([track]);
					remoteTracks[mid] = stream;
					Janus.log("Created remote video stream:", stream);
					$('#videoremote' + slot).append('<video class="rounded centered" id="remotevideo' + slot + '-' + mid + '" width=100% autoplay playsinline/>');
					$('#videoremote' + slot).append(
						'<span class="label label-primary hide" id="curres'+slot+'" style="position: absolute; bottom: 0px; left: 0px; margin: 15px;"></span>' +
						'<span class="label label-info hide" id="curbitrate'+slot+'" style="position: absolute; bottom: 0px; right: 0px; margin: 15px;"></span>');
					Janus.attachMediaStream($('#remotevideo' + slot + '-' + mid).get(0), stream);
					// Note: we'll need this for additional videos too
					if(!bitrateTimer[slot]) {
						$('#curbitrate' + slot).removeClass('hide').show();
						bitrateTimer[slot] = setInterval(function() {
							if(!$("#videoremote" + slot + ' video').get(0))
								return;
							// Display updated bitrate, if supported
							let bitrate = remoteFeed.getBitrate(mid);
							$('#curbitrate' + slot).text(bitrate);
							// Check if the resolution changed too
							let width = $("#videoremote" + slot + ' video').get(0).videoWidth;
							let height = $("#videoremote" + slot + ' video').get(0).videoHeight;
							if(width > 0 && height > 0) {
								let res = width + 'x' + height;
								if(simulcastStarted[slot])
									res += ' (simulcast)';
								else if(svcStarted[slot])
									res += ' (SVC)';
								$('#curres' + slot).removeClass('hide').text(res).show();
							}
						}, 1000);
					}
				}
			},
			oncleanup: function() {
				Janus.log(" ::: Got a cleanup notification (remote feed) :::");
				for(let i=1;i<6;i++) {
					$('#videoremote'+i).empty();
					if(bitrateTimer[i])
						clearInterval(bitrateTimer[i]);
					bitrateTimer[i] = null;
					feedStreams[i].simulcastStarted = false;
					feedStreams[i].svcStarted = false;
					feedStreams[i].remoteVideos = 0;
					$('#simulcast'+i).remove();
				}
				remoteTracks = {};
			}
		});
}

function unsubscribeFrom(id) {
	// Unsubscribe from this publisher
	let feed = feedStreams[id];
	if(!feed)
		return;
	Janus.debug("Feed " + id + " (" + feed.display + ") has left the room, detaching");
	if(bitrateTimer[feed.slot])
		clearInterval(bitrateTimer[feed.slot]);
	bitrateTimer[feed.slot] = null;
	$('#remote' + feed.slot).empty().hide();
	$('#videoremote' + feed.slot).empty();
	delete simulcastStarted[feed.slot];
	delete svcStarted[feed.slot];
	$('#simulcast' + feed.slot).remove();
	delete feeds[feed.slot];
	feeds.slot = 0;
	delete feedStreams[id];
	// Send an unsubscribe request
	let unsubscribe = {
		request: "unsubscribe",
		streams: [{ feed: id }]
	};
	if(remoteFeed != null)
		remoteFeed.send({ message: unsubscribe });
	delete subscriptions[id];
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

// Helpers to create Simulcast- or SVC-related UI, if enabled
function addSimulcastSvcButtons(feed, temporal) {
	let index = feed;
	let simulcast = simulcastStarted[index];
	let what = (simulcast ? 'simulcast' : 'SVC');
	let layer = (simulcast ? 'substream' : 'layer');
	$('#remote'+index).parent().append(
		'<div id="simulcast'+index+'" class="btn-group-vertical btn-group-vertical-xs pull-right">' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs" style="width: 100%">' +
		'			<button id="sl'+index+'-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to higher quality" style="width: 33%">SL 2</button>' +
		'			<button id="sl'+index+'-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to normal quality" style="width: 33%">SL 1</button>' +
		'			<button id="sl'+index+'-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to lower quality" style="width: 34%">SL 0</button>' +
		'		</div>' +
		'	</div>' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs hide" style="width: 100%">' +
		'			<button id="tl'+index+'-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 2" style="width: 34%">TL 2</button>' +
		'			<button id="tl'+index+'-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 1" style="width: 33%">TL 1</button>' +
		'			<button id="tl'+index+'-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 0" style="width: 33%">TL 0</button>' +
		'		</div>' +
		'	</div>' +
		'</div>'
	);
	// Enable the simulcast selection buttons
	$('#sl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			let index = $(this).attr('id').split('sl')[1].split('-')[0];
			toastr.info("Switching " + what + " " + layer + " (mid=" + mids[index] + "), wait for it... (lower quality)", null, {timeOut: 2000});
			if(!$('#sl' + index + '-2').hasClass('btn-success'))
				$('#sl' + index + '-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#sl' + index + '-1').hasClass('btn-success'))
				$('#sl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl' + index + '-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(simulcastStarted[index])
				remoteFeed.send({ message: { request: "configure", mid: mids[index], substream: 0 }});
			else
				remoteFeed.send({ message: { request: "configure", mid: mids[index], spatial_layer: 0 }});
		});
	$('#sl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			let index = $(this).attr('id').split('sl')[1].split('-')[0];
			toastr.info("Switching " + what + " " + layer + " (mid=" + mids[index] + "), wait for it... (normal quality)", null, {timeOut: 2000});
			if(!$('#sl' + index + '-2').hasClass('btn-success'))
				$('#sl' + index + '-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl' + index + '-1').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#sl' + index + '-0').hasClass('btn-success'))
				$('#sl' + index + '-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(simulcastStarted[index])
				remoteFeed.send({ message: { request: "configure", mid: mids[index], substream: 1 }});
			else
				remoteFeed.send({ message: { request: "configure", mid: mids[index], spatial_layer: 1 }});
		});
	$('#sl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			let index = $(this).attr('id').split('sl')[1].split('-')[0];
			toastr.info("Switching " + what + " " + layer + " (mid=" + mids[index] + "), wait for it... (higher quality)", null, {timeOut: 2000});
			$('#sl' + index + '-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#sl' + index + '-1').hasClass('btn-success'))
				$('#sl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#sl' + index + '-0').hasClass('btn-success'))
				$('#sl' + index + '-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(simulcastStarted[index])
				remoteFeed.send({ message: { request: "configure", mid: mids[index], substream: 2 }});
			else
				remoteFeed.send({ message: { request: "configure", mid: mids[index], spatial_layer: 2 }});
		});
	if(!temporal)	// No temporal layer support
		return;
	$('#tl' + index + '-0').parent().removeClass('hide');
	$('#tl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			let index = $(this).attr('id').split('tl')[1].split('-')[0];
			toastr.info("Capping " + what + " temporal layer (mid=" + mids[index] + "), wait for it... (lowest FPS)", null, {timeOut: 2000});
			if(!$('#tl' + index + '-2').hasClass('btn-success'))
				$('#tl' + index + '-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#tl' + index + '-1').hasClass('btn-success'))
				$('#tl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl' + index + '-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(simulcastStarted[index])
				remoteFeed.send({ message: { request: "configure", mid: mids[index], temporal: 0 }});
			else
				remoteFeed.send({ message: { request: "configure", mid: mids[index], temporal_layer: 0 }});
		});
	$('#tl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			let index = $(this).attr('id').split('tl')[1].split('-')[0];
			toastr.info("Capping " + what + " temporal layer (mid=" + mids[index] + "), wait for it... (medium FPS)", null, {timeOut: 2000});
			if(!$('#tl' + index + '-2').hasClass('btn-success'))
				$('#tl' + index + '-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-info');
			if(!$('#tl' + index + '-0').hasClass('btn-success'))
				$('#tl' + index + '-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(simulcastStarted[index])
				remoteFeed.send({ message: { request: "configure", mid: mids[index], temporal: 1 }});
			else
				remoteFeed.send({ message: { request: "configure", mid: mids[index], temporal_layer: 1 }});
		});
	$('#tl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			let index = $(this).attr('id').split('tl')[1].split('-')[0];
			toastr.info("Capping " + what + " temporal layer (mid=" + mids[index] + "), wait for it... (highest FPS)", null, {timeOut: 2000});
			$('#tl' + index + '-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#tl' + index + '-1').hasClass('btn-success'))
				$('#tl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#tl' + index + '-0').hasClass('btn-success'))
				$('#tl' + index + '-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(simulcastStarted[index])
				remoteFeed.send({ message: { request: "configure", mid: mids[index], temporal: 2 }});
			else
				remoteFeed.send({ message: { request: "configure", mid: mids[index], temporal_layer: 2 }});
		});
}

function updateSimulcastSvcButtons(feed, substream, temporal) {
	// Check the substream
	let index = feed;
	let simulcast = simulcastStarted[index];
	let what = (simulcast ? 'simulcast' : 'SVC');
	let layer = (simulcast ? 'substream' : 'layer');
	if(substream === 0) {
		toastr.success("Switched " + what + " " + layer + "! (lower quality)", null, {timeOut: 2000});
		$('#sl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl' + index + '-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(substream === 1) {
		toastr.success("Switched " + what + " " + layer + "! (normal quality)", null, {timeOut: 2000});
		$('#sl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl' + index + '-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#sl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(substream === 2) {
		toastr.success("Switched " + what + " " + layer + "! (higher quality)", null, {timeOut: 2000});
		$('#sl' + index + '-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#sl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
	// Check the temporal layer
	if(temporal === 0) {
		toastr.success("Capped " + what + " temporal layer! (lowest FPS)", null, {timeOut: 2000});
		$('#tl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl' + index + '-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(temporal === 1) {
		toastr.success("Capped " + what + " temporal layer! (medium FPS)", null, {timeOut: 2000});
		$('#tl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl' + index + '-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(temporal === 2) {
		toastr.success("Capped " + what + " temporal layer! (highest FPS)", null, {timeOut: 2000});
		$('#tl' + index + '-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
}
