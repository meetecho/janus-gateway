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
// when compiling the gateway. WebSockets support has not been tested
// as much as the REST API, so handle with care!
//
//
// If you have multiple options available, and want to let the library
// autodetect the best way to contact your gateway (or pool of gateways),
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
var mcutest = null;
var started = false;

var myusername = null;
var myid = null;
var mystream = null;
var muted = false;

var feeds = [];
var bitrateTimer = [];


$(document).ready(function() {
	// Initialize the library (console debug enabled)
	Janus.init({debug: true, callback: function() {
		// Use a button to start the demo
		$('#start').click(function() {
			if(started)
				return;
			started = true;
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
						// Attach to video MCU test plugin
						janus.attach(
							{
								plugin: "janus.plugin.videoroom",
								success: function(pluginHandle) {
									$('#details').remove();
									mcutest = pluginHandle;
									console.log("Plugin attached! (" + mcutest.getPlugin() + ", id=" + mcutest.getId() + ")");
									console.log("  -- This is a publisher/manager");
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
									console.log("  -- Error attaching plugin... " + error);
									bootbox.alert("Error attaching plugin... " + error);
								},
								consentDialog: function(on) {
									console.log("Consent dialog should be " + (on ? "on" : "off") + " now");
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
								onmessage: function(msg, jsep) {
									console.log(" ::: Got a message (publisher) :::");
									console.log(JSON.stringify(msg));
									var event = msg["videoroom"];
									console.log("Event: " + event);
									if(event != undefined && event != null) {
										if(event === "joined") {
											// Publisher/manager created, negotiate WebRTC and attach to existing feeds, if any
											myid = msg["id"];
											console.log("Successfully joined room " + msg["room"] + " with ID " + myid);
											publishOwnFeed(true);
											// Any new feed to attach to?
											if(msg["publishers"] !== undefined && msg["publishers"] !== null) {
												var list = msg["publishers"];
												console.log("Got a list of available publishers/feeds:");
												console.log(list);
												for(var f in list) {
													var id = list[f]["id"];
													var display = list[f]["display"];
													console.log("  >> [" + id + "] " + display);
													newRemoteFeed(id, display)
												}
											}
										} else if(event === "destroyed") {
											// The room has been destroyed
											console.log("The room has been destroyed!");
											bootbox.alert(error, function() {
												window.location.reload();
											});
										} else if(event === "event") {
											// Any new feed to attach to?
											if(msg["publishers"] !== undefined && msg["publishers"] !== null) {
												var list = msg["publishers"];
												console.log("Got a list of available publishers/feeds:");
												console.log(list);
												for(var f in list) {
													var id = list[f]["id"];
													var display = list[f]["display"];
													console.log("  >> [" + id + "] " + display);
													newRemoteFeed(id, display)
												}
											} else if(msg["leaving"] !== undefined && msg["leaving"] !== null) {
												// One of the publishers has gone away?
												var leaving = msg["leaving"];
												console.log("Publisher left: " + leaving);
												var remoteFeed = null;
												for(var i=1; i<6; i++) {
													if(feeds[i] != null && feeds[i] != undefined && feeds[i].rfid == leaving) {
														remoteFeed = feeds[i];
														break;
													}
												}
												if(remoteFeed != null) {
													console.log("Feed " + remoteFeed.rfid + " (" + remoteFeed.rfdisplay + ") has left the room, detaching");
													$('#remote'+remoteFeed.rfindex).empty().hide();
													$('#videoremote'+remoteFeed.rfindex).empty();
													feeds[remoteFeed.rfindex] = null;
													remoteFeed.detach();
												}
											} else if(msg["unpublished"] !== undefined && msg["unpublished"] !== null) {
												// One of the publishers has unpublished?
												var unpublished = msg["unpublished"];
												console.log("Publisher left: " + unpublished);
												var remoteFeed = null;
												for(var i=1; i<6; i++) {
													if(feeds[i] != null && feeds[i] != undefined && feeds[i].rfid == unpublished) {
														remoteFeed = feeds[i];
														break;
													}
												}
												if(remoteFeed != null) {
													console.log("Feed " + remoteFeed.rfid + " (" + remoteFeed.rfdisplay + ") has left the room, detaching");
													$('#remote'+remoteFeed.rfindex).empty().hide();
													$('#videoremote'+remoteFeed.rfindex).empty();
													feeds[remoteFeed.rfindex] = null;
													remoteFeed.detach();
												}
											} else if(msg["error"] !== undefined && msg["error"] !== null) {
												bootbox.alert(msg["error"]);
											}
										}
									}
									if(jsep !== undefined && jsep !== null) {
										console.log("Handling SDP as well...");
										console.log(jsep);
										mcutest.handleRemoteJsep({jsep: jsep});
									}
								},
								onlocalstream: function(stream) {
									console.log(" ::: Got a local stream :::");
									mystream = stream;
									console.log(JSON.stringify(stream));
									$('#videolocal').empty();
									$('#videojoin').hide();
									$('#videos').removeClass('hide').show();
									if($('#myvideo').length === 0) {
										$('#videolocal').append('<video class="rounded centered" id="myvideo" width="100%" height="100%" autoplay muted="muted"/>');
										// Add a 'mute' button
										$('#videolocal').append('<button class="btn btn-warning btn-xs" id="mute" style="position: absolute; bottom: 0px; left: 0px; margin: 15px;">Mute</button>');
										$('#mute').click(toggleMute);
										// Add an 'unpublish' button
										$('#videolocal').append('<button class="btn btn-warning btn-xs" id="unpublish" style="position: absolute; bottom: 0px; right: 0px; margin: 15px;">Unpublish</button>');
										$('#unpublish').click(unpublishOwnFeed);
									}
									$('#publisher').removeClass('hide').html(myusername).show();
									attachMediaStream($('#myvideo').get(0), stream);
									$("#myvideo").get(0).muted = "muted";
									var videoTracks = stream.getVideoTracks();
									if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
										// No webcam
										$('#myvideo').hide();
										$('#videolocal').append(
											'<div class="no-video-container">' +
												'<i class="fa fa-video-camera fa-5 no-video-icon" style="height: 100%;"></i>' +
												'<span class="no-video-text" style="font-size: 16px;">No webcam available</span>' +
											'</div>');
									}
								},
								onremotestream: function(stream) {
									// The publisher stream is sendonly, we don't expect anything here
								},
								oncleanup: function() {
									console.log(" ::: Got a cleanup notification: we are unpublished now :::");
									mystream = null;
									muted = false;
									$('#videolocal').html('<button id="publish" class="btn btn-primary">Publish</button>');
									$('#publish').click(function() { publishOwnFeed(true); });
								}
							});
					},
					error: function(error) {
						console.log(error);
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
	var theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
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
		var username = $('#username').val();
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
		var register = { "request": "join", "room": 1234, "ptype": "publisher", "display": username };
		myusername = username;
		mcutest.send({"message": register});
	}
}

function publishOwnFeed(useAudio) {
	// Publish our stream
	$('#publish').attr('disabled', true).unbind('click');
	mcutest.createOffer(
		{
			media: { audioRecv: false, videoRecv: false, audioSend: useAudio, videoSend: true},	// Publishers are sendonly
			success: function(jsep) {
				console.log("Got publisher SDP!");
				console.log(jsep);
				var publish = { "request": "configure", "audio": useAudio, "video": true };
				mcutest.send({"message": publish, "jsep": jsep});
			},
			error: function(error) {
				console.log("WebRTC error:");
				console.log(error);
				if (useAudio) {
					 publishOwnFeed(false);
				} else {
					bootbox.alert("WebRTC error... " + JSON.stringify(error));
					$('#publish').removeAttr('disabled').click(function() { publishOwnFeed(true); });
				}
			}
		});
}

function toggleMute() {
	if(mystream === null || mystream === undefined) {
		console.log("Cannot " + (muted ? "unmute" : "mute") + ", there's no local stream");
		return;
	}
	if(mystream.getAudioTracks() === null || mystream.getAudioTracks() === undefined) {
		console.log("Cannot " + (muted ? "unmute" : "mute") + ", there's no audio track");
		return;
	}
	if(mystream.getAudioTracks()[0] === null || mystream.getAudioTracks()[0] === undefined) {
		console.log("Cannot " + (muted ? "unmute" : "mute") + ", there's no audio track");
		return;
	}
	console.log((muted ? "Unmuting" : "Muting") + " local stream...");
	mystream.getAudioTracks()[0].enabled = muted;
	muted = !muted;
	$('#mute').html(muted ? "Unmute" : "Mute");
}

function unpublishOwnFeed() {
	// Unpublish our stream
	$('#unpublish').attr('disabled', true).unbind('click');
	var unpublish = { "request": "unpublish" };
	mcutest.send({"message": unpublish});
}

function newRemoteFeed(id, display) {
	// A new feed has been published, create a new plugin handle and attach to it as a listener
	var remoteFeed = null;
	janus.attach(
		{
			plugin: "janus.plugin.videoroom",
			success: function(pluginHandle) {
				remoteFeed = pluginHandle;
				console.log("Plugin attached! (" + remoteFeed.getPlugin() + ", id=" + remoteFeed.getId() + ")");
				console.log("  -- This is a subscriber");
				// We wait for the plugin to send us an offer
				var listen = { "request": "join", "room": 1234, "ptype": "listener", "feed": id };
				remoteFeed.send({"message": listen});
			},
			error: function(error) {
				console.log("  -- Error attaching plugin... " + error);
				bootbox.alert("Error attaching plugin... " + error);
			},
			onmessage: function(msg, jsep) {
				console.log(" ::: Got a message (listener) :::");
				console.log(JSON.stringify(msg));
				var event = msg["videoroom"];
				console.log("Event: " + event);
				if(event != undefined && event != null) {
					if(event === "attached") {
						// Subscriber created and attached
						for(var i=1;i<6;i++) {
							if(feeds[i] === undefined || feeds[i] === null) {
								feeds[i] = remoteFeed;
								remoteFeed.rfindex = i;
								break;
							}
						}
						remoteFeed.rfid = msg["id"];
						remoteFeed.rfdisplay = msg["display"];
						if(remoteFeed.spinner === undefined || remoteFeed.spinner === null) {
							var target = document.getElementById('videoremote'+remoteFeed.rfindex);
							remoteFeed.spinner = new Spinner({top:100}).spin(target);
						} else {
							remoteFeed.spinner.spin();
						}
						console.log("Successfully attached to feed " + remoteFeed.rfid + " (" + remoteFeed.rfdisplay + ") in room " + msg["room"]);
						$('#remote'+remoteFeed.rfindex).removeClass('hide').html(remoteFeed.rfdisplay).show();
					} else {
						// What has just happened?
					}
				}
				if(jsep !== undefined && jsep !== null) {
					console.log("Handling SDP as well...");
					console.log(jsep);
					// Answer and attach
					remoteFeed.createAnswer(
						{
							jsep: jsep,
							media: { audioSend: false, videoSend: false },	// We want recvonly audio/video
							success: function(jsep) {
								console.log("Got SDP!");
								console.log(jsep);
								var body = { "request": "start", "room": 1234 };
								remoteFeed.send({"message": body, "jsep": jsep});
							},
							error: function(error) {
								console.log("WebRTC error:");
								console.log(error);
								bootbox.alert("WebRTC error... " + JSON.stringify(error));
							}
						});
				}
			},
			onlocalstream: function(stream) {
				// The subscriber stream is recvonly, we don't expect anything here
			},
			onremotestream: function(stream) {
				console.log("Remote feed #" + remoteFeed.rfindex);
				if($('#remotevideo'+remoteFeed.rfindex).length === 0) {
					// No remote video yet
					$('#videoremote'+remoteFeed.rfindex).append('<video class="rounded centered" id="waitingvideo' + remoteFeed.rfindex + '" width=320 height=240 />');
					$('#videoremote'+remoteFeed.rfindex).append('<video class="rounded centered relative hide" id="remotevideo' + remoteFeed.rfindex + '" width="100%" height="100%" autoplay/>');
				}
				$('#videoremote'+remoteFeed.rfindex).append(
					'<span class="label label-primary hide" id="curres'+remoteFeed.rfindex+'" style="position: absolute; bottom: 0px; left: 0px; margin: 15px;"></span>' +
					'<span class="label label-info hide" id="curbitrate'+remoteFeed.rfindex+'" style="position: absolute; bottom: 0px; right: 0px; margin: 15px;"></span>');
				// Show the video, hide the spinner and show the resolution when we get a playing event
				$("#remotevideo"+remoteFeed.rfindex).bind("playing", function () {
					if(remoteFeed.spinner !== undefined && remoteFeed.spinner !== null)
						remoteFeed.spinner.stop();
					remoteFeed.spinner = null;
					$('#waitingvideo'+remoteFeed.rfindex).remove();
					$('#remotevideo'+remoteFeed.rfindex).removeClass('hide');
					var width = this.videoWidth;
					var height = this.videoHeight;
					$('#curres'+remoteFeed.rfindex).removeClass('hide').text(width+'x'+height).show();
					if(webrtcDetectedBrowser == "firefox") {
						// Firefox Stable has a bug: width and height are not immediately available after a playing
						setTimeout(function() {
							var width = $("#remotevideo"+remoteFeed.rfindex).get(0).videoWidth;
							var height = $("#remotevideo"+remoteFeed.rfindex).get(0).videoHeight;
							$('#curres'+remoteFeed.rfindex).removeClass('hide').text(width+'x'+height).show();
						}, 2000);
					}
				});
				attachMediaStream($('#remotevideo'+remoteFeed.rfindex).get(0), stream);
				var videoTracks = stream.getVideoTracks();
				if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0 || videoTracks[0].muted) {
					// No remote video
					$('#remotevideo'+remoteFeed.rfindex).hide();
					$('#videoremote'+remoteFeed.rfindex).append(
						'<div class="no-video-container">' +
							'<i class="fa fa-video-camera fa-5 no-video-icon" style="height: 100%;"></i>' +
							'<span class="no-video-text" style="font-size: 16px;">No remote video available</span>' +
						'</div>');
				}
				if(webrtcDetectedBrowser == "chrome") {
					$('#curbitrate'+remoteFeed.rfindex).removeClass('hide').show();
					bitrateTimer[remoteFeed.rfindex] = setInterval(function() {
						// Display updated bitrate, if supported
						var bitrate = remoteFeed.getBitrate();
						$('#curbitrate'+remoteFeed.rfindex).text(bitrate);
					}, 1000);
				}
			},
			oncleanup: function() {
				console.log(" ::: Got a cleanup notification (remote feed " + id + ") :::");
				if(remoteFeed.spinner !== undefined && remoteFeed.spinner !== null)
					remoteFeed.spinner.stop();
				remoteFeed.spinner = null;
				$('#waitingvideo'+remoteFeed.rfindex).remove();
				$('#curbitrate'+remoteFeed.rfindex).remove();
				$('#curres'+remoteFeed.rfindex).remove();
				if(bitrateTimer[remoteFeed.rfindex] !== null && bitrateTimer[remoteFeed.rfindex] !== null) 
					clearInterval(bitrateTimer[remoteFeed.rfindex]);
				bitrateTimer[remoteFeed.rfindex] = null;
			}
		});
}
