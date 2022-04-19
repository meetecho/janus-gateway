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
//		var server = "/janus";
//
// which will take care of this on its own.
//
//
// If you want to use the WebSockets frontend to Janus, instead, you'll
// have to pass a different kind of address, e.g.:
//
//		var server = "ws://" + window.location.hostname + ":8188";
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
var localFeed = null;
var opaqueId = "videoroomtest-" + Janus.randomString(12);
var myroom = 1234; // Demo room
if (getQueryStringValue("room") !== "")
	myroom = parseInt(getQueryStringValue("room"));
var myusername = null;
var myid = null;
var mystream = null;
// We use this other ID just to map our subscriptions to us
var mypvtid = null;
var remoteFeed = null;
var feeds = {},
		feedStreams = {},
		subStreams = {},
		slots = {},
		mids = {},
		subscriptions = {};
var localTracks = {},
		localVideos = 0,
		remoteTracks = {};
var bitrateTimer = [],
		simulcastStarted = {};
var doSimulcast = (getQueryStringValue("simulcast") === "yes" || getQueryStringValue("simulcast") === "true");
var acodec = (getQueryStringValue("acodec") !== "" ? getQueryStringValue("acodec") : null);
var vcodec = (getQueryStringValue("vcodec") !== "" ? getQueryStringValue("vcodec") : null);
var subscriber_mode = (getQueryStringValue("subscriber-mode") === "yes" || getQueryStringValue("subscriber-mode") === "true");
$(document).ready(function() {
	// Initialize the library (all console debuggers enabled)
	Janus.init({debug: "all",	callback: function() {
		// Use a button to start the demo
		domWaitForStart(function () {
			// Make sure the browser supports WebRTC
			if (!Janus.isWebrtcSupported()) {
				bootbox.alert("No WebRTC support... ");
				return;
			}
			// Create session
			janus = new Janus(
				{
					server: server,
					success: function() {
						// Attach to video room test plugin
						janus.attach(
							{
								plugin: "janus.plugin.videoroom",
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									localFeed = pluginHandle;
									domNewAttachSuccess(janus);
								},
								error: function(error) {
									Janus.error("	 -- Error attaching plugin...", error);
									bootbox.alert("Error attaching plugin... " + error);
								},
								consentDialog: on => domConsentDialog(on),
								iceState: function(state) {
									Janus.log("ICE state changed to " + state);
								},
								mediaState: function(medium, on, mid) {
									Janus.log("Janus " + (on ? "started" : "stopped") + " receiving our " + medium + " (mid=" + mid + ")");
								},
								webrtcState: on => domWebrtcState(on),
								slowLink: (uplink,lost,mid) => domSlowLink(uplink,lost,mid),
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message (publisher) :::", msg);
									var event = msg["videoroom"];
									Janus.debug("Event: " + event);
									if (event != undefined && event != null) {
										if (event === "joined") {
											// Publisher/manager created, negotiate WebRTC and attach to existing feeds, if any
											myid = msg["id"];
											mypvtid = msg["private_id"];
											Janus.log("Successfully joined room " + msg["room"] + " with ID " + myid);
											if (subscriber_mode) {
												domSubscriberModeOn();
											} else {
												publishOwnFeed(true);
											}
											// Any new feed to attach to?
											if (msg["publishers"]) {
												var list1 = msg["publishers"];
												Janus.debug("Got a list of available publishers/feeds:", list1);
												var sources1 = null;
												for (var f1 in list1) {
													var id1 = list1[f1]["id"];
													var display1 = list1[f1]["display"];
													var streams1 = list1[f1]["streams"];
													for (var i1 in streams1) {
														var stream1 = streams1[i1];
														stream1["id"] = id1;
														stream1["display"] = display1;
													}
													feedStreams[id1] = {
														id: id1,
														display: display1,
														streams: streams1
													};
													Janus.debug("	 >> [" + id1 + "] " + display1 + ":", streams1);
													if (!sources1)
														sources1 = [];
													sources1.push(streams1);
												}
												if (sources1)
													subscribeTo(sources1);
											}
										} else if (event === "destroyed") {
											// The room has been destroyed
											Janus.warn("The room has been destroyed!");
											bootbox.alert("The room has been destroyed", function() {
												window.location.reload();
											});
										} else if (event === "event") {
											// Any info on our streams or a new feed to attach to?
											if (msg["streams"]) {
												var streams2 = msg["streams"];
												for (var i2 in streams2) {
													var stream2 = streams2[i2];
													stream2["id"] = myid;
													stream2["display"] = myusername;
												}
												feedStreams[myid] = {
													id: myid,
													display: myusername,
													streams: streams2
												};
											} else if (msg["publishers"]) {
												var list2 = msg["publishers"];
												Janus.debug("Got a list of available publishers/feeds:", list2);
												var sources2 = null;
												for (var f2 in list2) {
													var id2 = list2[f2]["id"];
													var display2 = list2[f2]["display"];
													var streams3 = list2[f2]["streams"];
													for (var i3 in streams3) {
														var stream3 = streams3[i3];
														stream3["id"] = id2;
														stream3["display"] = display2;
													}
													feedStreams[id2] = {
														id: id2,
														display: display2,
														streams: streams3
													};
													Janus.debug("	 >> [" + id2 + "] " + display2 + ":", streams3);
													if (!sources2)
														sources2 = [];
													sources2.push(streams3);
												}
												if (sources2)
													subscribeTo(sources2);
											} else if (msg["leaving"]) {
												// One of the publishers has gone away?
												var leaving = msg["leaving"];
												Janus.log("Publisher left: " + leaving);
												unsubscribeFrom(leaving);
											} else if (msg["unpublished"]) {
												// One of the publishers has unpublished?
												var unpublished = msg["unpublished"];
												Janus.log("Publisher left: " + unpublished);
												if (unpublished === 'ok') {
													// That's us
													localFeed.hangup();
													return;
												}
												unsubscribeFrom(unpublished);
											} else if (msg["error"]) {
												if (msg["error_code"] === 426) {
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
									} // if (event != undefined)
									if (jsep) {
										Janus.debug("Handling SDP as well...", jsep);
										localFeed.handleRemoteJsep({
											jsep: jsep
										});
										// Check if any of the media we wanted to publish has
										// been rejected (e.g., wrong or unsupported codec)
										var audio = msg["audio_codec"];
										if (mystream && mystream.getAudioTracks() && mystream.getAudioTracks().length > 0 && !audio) {
											// Audio has been rejected
											toastr.warning("Our audio stream has been rejected, viewers won't hear us");
										}
										var video = msg["video_codec"];
										if (mystream && mystream.getVideoTracks() && mystream.getVideoTracks().length > 0 && !video) {
											// Video has been rejected
											toastr.warning("Our video stream has been rejected, viewers won't see us");
											// Hide the webcam video
											domRemoteVideoRejected();
										}
									}
								}, // end onmessage
								onlocaltrack: function(track, on) {
									Janus.debug(" ::: Got a local track event :::");
									Janus.debug("Local track " + (on ? "added" : "removed") + ":", track);
									// We use the track ID as name of the element, but it may contain invalid characters
									var trackId = track.id.replace(/[{}]/g, "");
									if (!on) {
										// Track removed, get rid of the stream and the rendering
										var stream = localTracks[trackId];
										if (stream) {
											try {
												var tracks = stream.getTracks();
												for (var i in tracks) {
													var mst = tracks[i];
													if (mst)
														mst.stop();
												}
											} catch (e) {domDoNothing();}
										}
										if (track.kind === "video") {
											domRemoveLocalTrack(trackId);
											localVideos--;
											if (localVideos === 0) {
												// No video, at least for now: show a placeholder
												domLocalVideoPlaceholder();
											}
										}
										delete localTracks[trackId];
										return;
									}
									// If we're here, a new track was added
									var stream4 = localTracks[trackId];
									if (stream4) {
										// We've been here already
										return;
									}
									domAddMuteButton();
									if (track.kind === "audio") {
										domLocalAudioTrack(localVideos);
									} else {
										// New video track: create a stream out of it
										localVideos++;

										stream4 = new MediaStream();
										stream4.addTrack(track.clone());
										localTracks[trackId] = stream4;
										Janus.log("Created local stream:", stream4);
										Janus.log(stream4.getTracks());
										Janus.log(stream4.getVideoTracks());
										const place1 = domLocalVideoTrack(trackId);
										Janus.attachMediaStream(place1, stream);
									}
									if (localFeed.webrtcStuff.pc.iceConnectionState !== "completed" &&
											localFeed.webrtcStuff.pc.iceConnectionState !== "connected") {
										domBlockLocalVideo();
									}
								}, // end onlocaltrack
								onremotetrack: function() {
									// The publisher stream is sendonly, we don't expect anything here
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification: we are unpublished now :::");
									mystream = null;
									delete feedStreams[myid];
									domCleanupLocalVideo();
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

function checkEnter(field, event) {																						 //- This is not used
	var theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if (theCode == 13) {
		domRegisterUsername();
		return false;
	} else {
		return true;
	}
}

function publishOwnFeed(useAudio) {
	// Publish our stream
	domDisablePublish();
	localFeed.createOffer(
		{
			// Add data:true here if you want to publish datachannels as well
			media: {
				audioRecv: false,
				videoRecv: false,
				audioSend: useAudio,
				videoSend: true
			}, // Publishers are sendonly
			// If you want to test simulcasting (Chrome and Firefox only), then
			// pass a ?simulcast=true when opening this demo page: it will turn
			// the following 'simulcast' property to pass to janus.js to true
			simulcast: doSimulcast,
			success: function(jsep) {
				Janus.debug("Got publisher SDP!");
				Janus.debug(jsep);
				var publish = {
					request: "configure",
					audio: useAudio,
					video: true
				};
				// You can force a specific codec to use when publishing by using the
				// audiocodec and videocodec properties, for instance:
				//		 publish["audiocodec"] = "opus"
				// to force Opus as the audio codec to use, or:
				//		 publish["videocodec"] = "vp9"
				// to force VP9 as the videocodec to use. In both case, though, forcing
				// a codec will only work if: (1) the codec is actually in the SDP (and
				// so the browser supports it), and (2) the codec is in the list of
				// allowed codecs in a room. With respect to the point (2) above,
				// refer to the text in janus.plugin.videoroom.cfg for more details
				if (acodec)
					publish["audiocodec"] = acodec;
				if (vcodec)
					publish["videocodec"] = vcodec;
				localFeed.send({
					message: publish,
					jsep: jsep
				});
			},
			error: function(error) {
				Janus.error("WebRTC error:", error);
				if (useAudio) {
					publishOwnFeed(false);
				} else {
					bootbox.alert("WebRTC error... " + error.message);
					domEnablePublish();
				}
			}
		});
}

function toggleMute() {
	var muted = localFeed.isAudioMuted();
	Janus.log((muted ? "Unmuting" : "Muting") + " local stream...");
	if (muted)
		localFeed.unmuteAudio();
	else
		localFeed.muteAudio();
	muted = localFeed.isAudioMuted();
	domToggleMute(muted) ;
}

function unpublishOwnFeed() {
	// Unpublish our stream
	domUnpublishOwnFeed();
	var unpublish = {
		request: "unpublish"
	};
	localFeed.send({
		message: unpublish
	});
}
var creatingFeed = false;
function subscribeTo(sources) {
	// New feeds are available, do we need create a new plugin handle first?
	if (remoteFeed) {
		// Prepare the streams to subscribe to, as an array: we have the list of
		// streams the feeds are publishing, so we can choose what to pick or skip
		var subscription = [];
		for (var s in sources) {
			var streams = sources[s];
			for (var i in streams) {
				var stream = streams[i];
				// If the publisher is VP8/VP9 and this is an older Safari, let's avoid video
				if (stream.type === "video" && Janus.webRTCAdapter.browserDetails.browser === "safari" &&
						(stream.codec === "vp9" || (stream.codec === "vp8" && !Janus.safariVp8))) {
					toastr.warning("Publisher is using " + stream.codec.toUpperCase +
												 ", but Safari doesn't support it: disabling video stream #" + stream.mindex);
					continue;
				}
				if (stream.disabled) {
					Janus.log("Disabled stream:", stream);
					// TODO Skipping for now, we should unsubscribe
					continue;
				}
				if (subscriptions[stream.id] && subscriptions[stream.id][stream.mid]) {
					Janus.log("Already subscribed to stream, skipping:", stream);
					continue;
				}
				// Find an empty slot in the UI for each new source
				if (!feedStreams[stream.id].slot) {
					var slot;
					for (var i4 = 1; i4 < 6; i4++) {
						if (!feeds[i4]) {
							slot = i4;
							feeds[slot] = stream.id;
							feedStreams[stream.id].slot = slot;
							feedStreams[stream.id].remoteVideos = 0;
							domShowEmptySlot(slot,stream);
							break;
						}
					}
				}
				subscription.push({
					feed: stream.id, // This is mandatory
					mid: stream.mid // This is optional (all streams, if missing)
				});
				if (!subscriptions[stream.id])
					subscriptions[stream.id] = {};
				subscriptions[stream.id][stream.mid] = true;
			}
		}
		if (subscription.length === 0) {
			// Nothing to do
			return;
		}
		remoteFeed.send({
			message: {
				request: "subscribe",
				streams: subscription
			}
		});
		return;
	}
	// We don't have a handle yet, but we may be creating one already
	if (creatingFeed) {
		// Still working on the handle
		setTimeout(function() {
			subscribeTo(sources);
		}, 500);
		return;
	}
	creatingFeed = true;
	janus.attach(
		{
			plugin: "janus.plugin.videoroom",
			opaqueId: opaqueId,
			success: function(pluginHandle) {
				remoteFeed = pluginHandle;
				remoteTracks = {};
				Janus.log("Plugin attached! (" + remoteFeed.getPlugin() + ", id=" + remoteFeed.getId() + ")");
				Janus.log("	 -- This is a multistream subscriber");
				// Prepare the streams to subscribe to, as an array: we have the list of
				// streams the feed is publishing, so we can choose what to pick or skip
				var subscription = [];
				for(var s in sources) {
					var streams = sources[s];
					for(var i in streams) {
						var stream = streams[i];
						// If the publisher is VP8/VP9 and this is an older Safari, let's avoid video
						if(stream.type === "video" && Janus.webRTCAdapter.browserDetails.browser === "safari" &&
							 (stream.codec === "vp9" || (stream.codec === "vp8" && !Janus.safariVp8))) {
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
							var slot;
							for(var i5=1;i<6;i++) {
								if(!feeds[i5]) {
									slot = i5;
									feeds[slot] = stream.id;
									feedStreams[stream.id].slot = slot;
									feedStreams[stream.id].remoteVideos = 0;
									domShowEmptySlot(slot,stream);
									break;
								}
							}
						}
						subscription.push({
							feed: stream.id,	// This is mandatory
							mid: stream.mid		 // This is optional (all streams, if missing)
						});
						if(!subscriptions[stream.id])
							subscriptions[stream.id] = {};
						subscriptions[stream.id][stream.mid] = true;
					}
				}
				// We wait for the plugin to send us an offer
				var subscribe = {
					request: "join",
					room: myroom,
					ptype: "subscriber",
					streams: subscription,
					private_id: mypvtid
				};
				remoteFeed.send({ message: subscribe });
			},
			error: function(error) {
				Janus.error("	 -- Error attaching plugin...", error);
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
				var event = msg["videoroom"];
				Janus.debug("Event: " + event);
				if(msg["error"]) {
					bootbox.alert(msg["error"]);
				} else if(event) {
					if(event === "attached") {
						creatingFeed = false;
						Janus.log("Successfully attached to feed in room " + msg["room"]);
					} else if(event === "event") {
						// Check if we got an event on a simulcast-related event from this publisher
						var mid1 = msg["mid"];
						var substream = msg["substream"];
						var temporal = msg["temporal"];
						if((substream !== null && substream !== undefined) || (temporal !== null && temporal !== undefined)) {
							// Check which this feed this refers to
							// var sub = subStreams[mid1]; this is unused!!
							// var feed1 = feedStreams[sub.feed_id]; this is unused!!
							var slot = slots[mid1];
							if(!simulcastStarted[slot]) {
								simulcastStarted[slot] = true;
								// Add some new buttons
								domAddSimulcastButtons(slot, true);
							}
							// We just received notice that there's been a switch, update the buttons
							domUpdateSimulcastButtons(slot, substream, temporal);
						}
					} else {
						// What has just happened?
					}
				}
				if(msg["streams"]) {
					// Update map of subscriptions by mid
					for(var i6 in msg["streams"]) {
						var mid2 = msg["streams"][i6]["mid"];
						subStreams[mid2] = msg["streams"][i];
						var feed2 = feedStreams[msg["streams"][i]["feed_id"]];
						if(feed2 && feed2.slot) {
							slots[mid2] = feed2.slot;
							mids[feed2.slot] = mid2;
						}
					}
				}
				if(jsep) {
					Janus.debug("Handling SDP as well...", jsep);
					// Answer and attach
					remoteFeed.createAnswer(
						{
							jsep: jsep,
							// Add data:true here if you want to subscribe to datachannels as well
							// (obviously only works if the publisher offered them in the first place)
							media: { audioSend: false, videoSend: false },	// We want recvonly audio/video
							success: function(jsep) {
								Janus.debug("Got SDP!");
								Janus.debug(jsep);
								var body = { request: "start", room: myroom };
								remoteFeed.send({ message: body, jsep: jsep });
							},
							error: function(error) {
								Janus.error("WebRTC error:", error);
								bootbox.alert("WebRTC error... " + error.message);
							}
						});
				}
			},
			onlocaltrack: function() {
				// The subscriber stream is recvonly, we don't expect anything here
			},
			onremotetrack: function(track, mid, on) {
				Janus.debug("Remote track (mid=" + mid + ") " + (on ? "added" : "removed") + ":", track);
				// Which publisher are we getting on this mid?
				var sub = subStreams[mid];
				var feed3 = feedStreams[sub.feed_id];
				Janus.debug(" >> This track is coming from feed " + sub.feed_id + ":", feed3);
				var slot = slots[mid];
				if(feed3 && !slot) {
					slot = feed3.slot;
					slots[mid] = feed3.slot;
					mids[feed3.slot] = mid;
				}
				Janus.debug(" >> mid " + mid + " is in slot " + slot);
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
						} catch(e) {domDoNothing();}
					}
					domRemoveRemoteVideo(slot,mid);
					if(track.kind === "video" && feed3) {
						feed3.remoteVideos--;
						if(feed3.remoteVideos === 0) {
							// No video, at least for now: show a placeholder
							domRemoteVideoPlaceholder(slot);
						}
					}
					delete remoteTracks[mid];
					delete slots[mid];
					delete mids[slot];
					return;
				}
				// If we're here, a new track was added
				if(feed3.spinner) {
					feed3.spinner.stop();
					feed3.spinner = null;
				}
				if(domHaveRemoteVideo(slot,mid))
					return;
				if(track.kind === "audio") {
					// New audio track: create a stream out of it, and use a hidden <audio> element
					stream = new MediaStream();
					stream.addTrack(track.clone());
					remoteTracks[mid] = stream;
					Janus.log("Created remote audio stream:", stream);
					const place2 = domRemoteAudioTrack(slot, mid);
					Janus.attachMediaStream(place2, stream);
					if(feed3.remoteVideos === 0) {
						domRemoteVideoPlaceholder(slot);
					}
				} else {
					// New video track: create a stream out of it
					feed3.remoteVideos++;
					stream = new MediaStream();
					stream.addTrack(track.clone());
					remoteTracks[mid] = stream;
					Janus.log("Created remote video stream:", stream);
					var domRemoteVideoSlotPlace = domRemoteVideoSlot(slot,mid);
					Janus.attachMediaStream(domRemoteVideoSlotPlace, stream);
					// Note: we'll need this for additional videos too
					if(!bitrateTimer[slot]) {
						var domBitrateTimerGet = domBitrateTimer(slot);
						bitrateTimer[slot] = setInterval(function() {
							if(!domBitrateTimerGet)
								return;
							// Display updated bitrate, if supported
							var bitrate = remoteFeed.getBitrate(mid);
							domBitrateHeightWidth(slot, bitrate);
						}, 1000);
					}
				}
			},
			oncleanup: function() {
				Janus.log(" ::: Got a cleanup notification (remote feed) :::");
				for(var i=1;i<6;i++) {
					if(bitrateTimer[i])
						clearInterval(bitrateTimer[i]);
					bitrateTimer[i] = null;
					feedStreams[i].simulcastStarted = false;
					feedStreams[i].remoteVideos = 0;
				}
				domCleanup();
				remoteTracks = {};
			}
		});
}

function unsubscribeFrom(id) {
	// Unsubscribe from this publisher
	var feed4 = feedStreams[id];
	if (!feed4)
		return;
	Janus.debug("Feed " + id + " (" + feed4.display + ") has left the room, detaching");
	if (bitrateTimer[feed4.slot])
		clearInterval(bitrateTimer[feed4.slot]);
	bitrateTimer[feed4.slot] = null;
	domUnsubscribeFrom(feed4);
	delete simulcastStarted[feed4.slot];
	delete feeds[feed4.slot];
	feeds.slot = 0;
	delete feedStreams[id];
	// Send an unsubscribe request
	var unsubscribe = {
		request: "unsubscribe",
		streams: [{
			feed: id
		}]
	};
	if (remoteFeed != null)
		remoteFeed.send({
			message: unsubscribe
		});
	delete subscriptions[id];
}
// Helper to parse query string
function getQueryStringValue(name) {
	name = name.replace(/[[]/, "\\[").replace(/[\]]/, "\\]");
	var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
			results = regex.exec(location.search);
	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}
// Helper to escape XML tags
function escapeXmlTags(value) {
	if (value) {
		var escapedValue = value.replace(new RegExp('<', 'g'), '&lt');
		escapedValue = escapedValue.replace(new RegExp('>', 'g'), '&gt');
		return escapedValue;
	}
}


////////////////////////////////////////////////////////////////////////
//						 dom code starts here																	//
////////////////////////////////////////////////////////////////////////

function domDoNothing() {}

function domWaitForStart(f) {
	$('#start').one('click', function() {
		$(this).attr('disabled', true).unbind('click');
		f();
	});
}

function domNewAttachSuccess(janus) {
	$('#details').remove();
	Janus.log("Plugin attached! (" + localFeed.getPlugin() + ", id=" +
						localFeed.getId() + ")");
	Janus.log("	 -- This is a publisher/manager");
	// Prepare the username registration
	$('#videojoin').removeClass('hide').show();
	$('#registernow').removeClass('hide').show();
	$('#register').click(domRegisterUsername);
	$('#username').focus();
	$('#start').removeAttr('disabled').html("Stop")
		.click(function() {
			$(this).attr('disabled', true);
			janus.destroy();
		});
}

function domConsentDialog(on) {
	Janus.debug(
		"Consent dialog should be " +
			(on ? "on" : "off") + " now");
	if (on) {
		// Darken screen and show hint
		$.blockUI({
			message: '<div><img src="up_arrow.png"/></div>',
			css: {
				border: 'none',
				padding: '15px',
				backgroundColor: 'transparent',
				color: '#aaa',
				top: '10px',
				left: (navigator
							 .mozGetUserMedia ?
							 '-100px' :
							 '300px')
			}
		});
	} else {
		// Restore screen
		$.unblockUI();
	}
}

function domRegisterUsername() {
	if ($('#username').length === 0) {
		// Create fields to register
		$('#register').click(domRegisterUsername);
		$('#username').focus();
	} else {
		// Try a registration
		$('#username').attr('disabled', true);
		$('#register').attr('disabled', true).unbind('click');
		var username = $('#username').val();
		if (username === "") {
			$('#you')
				.removeClass().addClass('label label-warning')
				.html("Insert your display name (e.g., pippo)");
			$('#username').removeAttr('disabled');
			$('#register').removeAttr('disabled').click(domRegisterUsername);
			return;
		}
		if (/[^a-zA-Z0-9]/.test(username)) {
			$('#you')
				.removeClass().addClass('label label-warning')
				.html('Input is not alphanumeric');
			$('#username').removeAttr('disabled').val("");
			$('#register').removeAttr('disabled').click(domRegisterUsername);
			return;
		}
		var register = {
			request: "join",
			room: myroom,
			ptype: "publisher",
			display: username
		};
		myusername = escapeXmlTags(username);
		localFeed.send({
			message: register
		});
	}
}

function domWebrtcState(on) {
	Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
	$("#videolocal").parent().parent().unblock();
	if (!on)
		return;
	$('#publish').remove();
	// This controls allows us to override the global room bitrate cap
	$('#bitrate').parent().parent().removeClass('hide').show();
	$('#bitrate a').click(function() {
		var id = $(this).attr("id");
		var bitrate = parseInt(id) * 1000;
		if (bitrate === 0) {
			Janus.log("Not limiting bandwidth via REMB");
		} else {
			Janus.log("Capping bandwidth to " + bitrate + " via REMB");
		}
		$('#bitrateset').html($(this).html() + '<span class="caret"></span>').parent().removeClass('open');
		localFeed.send({
			message: {
				request: "configure",
				bitrate: bitrate
			}
		});
		return false;
	});
}

function domSlowLink(uplink, lost, mid) {
	Janus.warn("Janus reports problems " + (uplink ? "sending" : "receiving") +
						 " packets on mid " + mid + " (" + lost + " lost packets)");
}

function domSubscriberModeOn () {
	$('#videojoin').hide();
	$('#videos').removeClass('hide').show();
}

function domUnsubscribeFrom (feed) {
	$('#remote' + feed.slot).empty().hide();
	$('#videoremote' + feed.slot).empty();
	$('#simulcast' + feed.slot).remove();
}

function domRemoteVideoRejected () {
	$('#myvideo').hide();
	$('#videolocal').append(
		'<div class="no-video-container">' +
			'<i class="fa fa-video-camera fa-5 no-video-icon" style="height: 100%;"></i>' +
			'<span class="no-video-text" style="font-size: 16px;">Video rejected, no webcam</span>' +
			'</div>');
}

function domLocalVideoPlaceholder() {
	if ($('#videolocal .no-video-container').length === 0) {
		$('#videolocal').append(
			'<div class="no-video-container">' +
				'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
				'<span class="no-video-text">No webcam available</span>' +
				'</div>');
	}
}

function domRemoveLocalTrack(trackId) {
	$('#myvideo' + trackId).remove();
}

function domAddMuteButton() {
	$('#videos').removeClass('hide').show();
	if ($('#mute').length === 0) {
		// Add a 'mute' button
		$('#videolocal').append('<button class="btn btn-warning btn-xs" id="mute" style="position: absolute; bottom: 0px; left: 0px; margin: 15px;">Mute</button>');
		$('#mute').click(toggleMute);
		// Add an 'unpublish' button
		$('#videolocal').append('<button class="btn btn-warning btn-xs" id="unpublish" style="position: absolute; bottom: 0px; right: 0px; margin: 15px;">Unpublish</button>');
		$('#unpublish').click(unpublishOwnFeed);
	}
}

function domLocalAudioTrack(localVideos) {
	// We ignore local audio tracks, they'd generate echo anyway
	if (localVideos === 0) {
		// No video, at least for now: show a placeholder
		if ($('#videolocal .no-video-container').length === 0) {
			$('#videolocal').append(
				'<div class="no-video-container">' +
					'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
					'<span class="no-video-text">No webcam available</span>' +
					'</div>');
		}
	}
}

function domLocalVideoTrack(trackId) {
	$('#videolocal .no-video-container').remove();
	$('#videolocal').append('<video class="rounded centered" id="myvideo' + trackId + '" width=100% autoplay playsinline muted="muted"/>');
	return $('#myvideo' + trackId).get(0);
}

function domBlockLocalVideo() {
	$("#videolocal").parent().parent().block({
		message: '<b>Publishing...</b>',
		css: {
			border: 'none',
			backgroundColor: 'transparent',
			color: 'white'
		}
	});
}

function domCleanupLocalVideo() {
	$('#videolocal').html('<button id="publish" class="btn btn-primary">Publish</button>');
	$('#publish').click(function() {
		publishOwnFeed(true);
	});
	$("#videolocal").parent().parent().unblock();
	$('#bitrate').parent().parent().addClass('hide');
	$('#bitrate a').unbind('click');
}

function domDisablePublish() {
	$('#publish').attr('disabled', true).unbind('click');
}

function domEnablePublish() {
	$('#publish').removeAttr('disabled').click(function() {
		publishOwnFeed(true);
	});
}

function domToggleMute(muted) {
	$('#mute').html(muted ? "Unmute" : "Mute");
}

function domUnpublishOwnFeed() {
	$('#unpublish').attr('disabled', true).unbind('click');
}

function domShowEmptySlot(slot,stream) {
	$('#remote' + slot).removeClass('hide').html(escapeXmlTags(stream.display)).show();
}

function domRemoteVideoPlaceholder(slot) {
	// No video, at least for now: show a placeholder
	if ($('#videoremote' + slot + ' .no-video-container').length === 0) {
		$('#videoremote' + slot).append(
			'<div class="no-video-container">' +
				'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
				'<span class="no-video-text">No remote video available</span>' +
				'</div>');
	}
}

function domSlotMidToVideoElement(slot,mid) {
	return $('#remotevideo' + slot + '-' + mid);
}

function domRemoveRemoteVideo(slot,mid) {
	domSlotMidToVideoElement(slot,mid).remove();
}

function domHaveRemoteVideo(slot,mid) {
	return (domSlotMidToVideoElement(slot,mid).length > 0);
}

function domRemoteAudioTrack(slot, mid) {
	$('#videoremote' + slot).append('<audio class="hide" id="remotevideo' + slot + '-' + mid + '" autoplay playsinline/>');
	return domSlotMidToVideoElement(slot,mid).get(0);
}

function domRemoteVideoSlot(slot, mid) {
	$('#videoremote' + slot + ' .no-video-container').remove();
	$('#videoremote' + slot).append('<video class="rounded centered" id="remotevideo' + slot + '-' + mid + '" width=100% autoplay playsinline/>');
	$('#videoremote' + slot).append(
		'<span class="label label-primary hide" id="curres' + slot + '" style="position: absolute; bottom: 0px; left: 0px; margin: 15px;"></span>' +
			'<span class="label label-info hide" id="curbitrate' + slot + '" style="position: absolute; bottom: 0px; right: 0px; margin: 15px;"></span>');
	return domSlotMidToVideoElement(slot,mid).get(0);

}

function domBitrateTimer(slot) {
	$('#curbitrate' + slot).removeClass('hide').show();
	return $("#videoremote" + slot + ' video').get(0);
}

function domBitrateHeightWidth(slot, bitrate) {
	$('#curbitrate' + slot).text(bitrate);
	// Check if the resolution changed too
	var width = $("#videoremote" + slot + ' video').get(0).videoWidth;
	var height = $("#videoremote" + slot + ' video').get(0).videoHeight;
	if (width > 0 && height > 0)
		$('#curres' + slot).removeClass('hide').text(width + 'x' + height).show();
}

function domCleanup() {
	$("[id^=remotevideo]").remove();
	$("[id^=waitingvideo]").remove();
	$("[id^=novideo]").remove();
	$("[id^=curbitrate]").remove();
	$("[id^=curres]").remove();
	$("[id^=simulcast]").remove();
}

// Helpers to create Simulcast-related UI, if enabled
function domAddSimulcastButtons(feed, temporal) {
	var index = feed;
	$('#remote' + index).parent().append(
		'<div id="simulcast' + index + '" class="btn-group-vertical btn-group-vertical-xs pull-right">' +
			'	 <div class"row">' +
			'		 <div class="btn-group btn-group-xs" style="width: 100%">' +
			'			 <button id="sl' + index + '-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to higher quality" style="width: 33%">SL 2</button>' +
			'			 <button id="sl' + index + '-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to normal quality" style="width: 33%">SL 1</button>' +
			'			 <button id="sl' + index + '-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to lower quality" style="width: 34%">SL 0</button>' +
			'		 </div>' +
			'	 </div>' +
			'	 <div class"row">' +
			'		 <div class="btn-group btn-group-xs hide" style="width: 100%">' +
			'			 <button id="tl' + index + '-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 2" style="width: 34%">TL 2</button>' +
			'			 <button id="tl' + index + '-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 1" style="width: 33%">TL 1</button>' +
			'			 <button id="tl' + index + '-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 0" style="width: 33%">TL 0</button>' +
			'		 </div>' +
			'	 </div>' +
			'</div>'
	);
	// Enable the simulcast selection buttons
	$('#sl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			var index = $(this).attr('id').split('sl')[1].split('-')[0];
			toastr.info("Switching simulcast substream (mid=" + mids[index] + "), wait for it... (lower quality)", null, {
				timeOut: 2000
			});
			if (!$('#sl' + index + '-2').hasClass('btn-success'))
				$('#sl' + index + '-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if (!$('#sl' + index + '-1').hasClass('btn-success'))
				$('#sl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl' + index + '-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			remoteFeed.send({
				message: {
					request: "configure",
					mid: mids[index],
					substream: 0
				}
			});
		});
	$('#sl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			var index = $(this).attr('id').split('sl')[1].split('-')[0];
			toastr.info("Switching simulcast substream (mid=" + mids[index] + "), wait for it... (normal quality)", null, {
				timeOut: 2000
			});
			if (!$('#sl' + index + '-2').hasClass('btn-success'))
				$('#sl' + index + '-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl' + index + '-1').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if (!$('#sl' + index + '-0').hasClass('btn-success'))
				$('#sl' + index + '-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			remoteFeed.send({
				message: {
					request: "configure",
					mid: mids[index],
					substream: 1
				}
			});
		});
	$('#sl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			var index = $(this).attr('id').split('sl')[1].split('-')[0];
			toastr.info("Switching simulcast substream (mid=" + mids[index] + "), wait for it... (higher quality)", null, {
				timeOut: 2000
			});
			$('#sl' + index + '-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if (!$('#sl' + index + '-1').hasClass('btn-success'))
				$('#sl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if (!$('#sl' + index + '-0').hasClass('btn-success'))
				$('#sl' + index + '-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			remoteFeed.send({
				message: {
					request: "configure",
					mid: mids[index],
					substream: 2
				}
			});
		});
	if (!temporal) // No temporal layer support
		return;
	$('#tl' + index + '-0').parent().removeClass('hide');
	$('#tl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			var index = $(this).attr('id').split('tl')[1].split('-')[0];
			toastr.info("Capping simulcast temporal layer (mid=" + mids[index] + "), wait for it... (lowest FPS)", null, {
				timeOut: 2000
			});
			if (!$('#tl' + index + '-2').hasClass('btn-success'))
				$('#tl' + index + '-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if (!$('#tl' + index + '-1').hasClass('btn-success'))
				$('#tl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl' + index + '-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			remoteFeed.send({
				message: {
					request: "configure",
					mid: mids[index],
					temporal: 0
				}
			});
		});
	$('#tl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			var index = $(this).attr('id').split('tl')[1].split('-')[0];
			toastr.info("Capping simulcast temporal layer (mid=" + mids[index] + "), wait for it... (medium FPS)", null, {
				timeOut: 2000
			});
			if (!$('#tl' + index + '-2').hasClass('btn-success'))
				$('#tl' + index + '-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-info');
			if (!$('#tl' + index + '-0').hasClass('btn-success'))
				$('#tl' + index + '-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			remoteFeed.send({
				message: {
					request: "configure",
					mid: mids[index],
					temporal: 1
				}
			});
		});
	$('#tl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			var index = $(this).attr('id').split('tl')[1].split('-')[0];
			toastr.info("Capping simulcast temporal layer (mid=" + mids[index] + "), wait for it... (highest FPS)", null, {
				timeOut: 2000
			});
			$('#tl' + index + '-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if (!$('#tl' + index + '-1').hasClass('btn-success'))
				$('#tl' + index + '-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if (!$('#tl' + index + '-0').hasClass('btn-success'))
				$('#tl' + index + '-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			remoteFeed.send({
				message: {
					request: "configure",
					mid: mids[index],
					temporal: 2
				}
			});
		});
}

function domUpdateSimulcastButtons(feed, substream, temporal) {
	// Check the substream
	var index = feed;
	if (substream === 0) {
		toastr.success("Switched simulcast substream! (lower quality)", null, {
			timeOut: 2000
		});
		$('#sl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl' + index + '-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if (substream === 1) {
		toastr.success("Switched simulcast substream! (normal quality)", null, {
			timeOut: 2000
		});
		$('#sl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl' + index + '-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#sl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if (substream === 2) {
		toastr.success("Switched simulcast substream! (higher quality)", null, {
			timeOut: 2000
		});
		$('#sl' + index + '-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#sl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
	// Check the temporal layer
	if (temporal === 0) {
		toastr.success("Capped simulcast temporal layer! (lowest FPS)", null, {
			timeOut: 2000
		});
		$('#tl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl' + index + '-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if (temporal === 1) {
		toastr.success("Capped simulcast temporal layer! (medium FPS)", null, {
			timeOut: 2000
		});
		$('#tl' + index + '-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl' + index + '-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if (temporal === 2) {
		toastr.success("Capped simulcast temporal layer! (highest FPS)", null, {
			timeOut: 2000
		});
		$('#tl' + index + '-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl' + index + '-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl' + index + '-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
}
