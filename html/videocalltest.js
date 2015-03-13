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
var videocall = null;
var started = false;
var bitrateTimer = null;
var spinner = null;

var audioenabled = false;
var videoenabled = false;

var myusername = null;
var yourusername = null;	

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
						// Attach to echo test plugin
						janus.attach(
							{
								plugin: "janus.plugin.videocall",
								success: function(pluginHandle) {
									$('#details').remove();
									videocall = pluginHandle;
									console.log("Plugin attached! (" + videocall.getPlugin() + ", id=" + videocall.getId() + ")");
									// Prepare the username registration
									$('#videocall').removeClass('hide').show();
									$('#login').removeClass('hide').show();
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
									bootbox.alert("  -- Error attaching plugin... " + error);
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
									console.log(" ::: Got a message :::");
									console.log(JSON.stringify(msg));
									var result = msg["result"];
									if(result !== null && result !== undefined) {
										if(result["list"] !== undefined && result["list"] !== null) {
											var list = result["list"];
											console.log("Got a list of registered peers:");
											console.log(list);
											for(var mp in list) {
												console.log("  >> [" + list[mp] + "]");
											}
										} else if(result["event"] !== undefined && result["event"] !== null) {
											var event = result["event"];
											if(event === 'registered') {
												myusername = result["username"];
												console.log("Successfully registered as " + myusername + "!");
												$('#youok').removeClass('hide').show().html("Registered as '" + myusername + "'");
												// Get a list of available peers, just for fun
												videocall.send({"message": { "request": "list" }});
												// TODO Enable buttons to call now
												$('#phone').removeClass('hide').show();
												$('#call').unbind('click').click(doCall);
												$('#peer').focus();
											} else if(event === 'calling') {
												console.log("Waiting for the peer to answer...");
												// TODO Any ringtone?
											} else if(event === 'incomingcall') {
												console.log("Incoming call from " + result["username"] + "!");
												$('#peer').val(result["username"]).attr('disabled');
												yourusername = result["username"];
												// TODO Enable buttons to answer
												videocall.createAnswer(
													{
														jsep: jsep,
														// No media provided: by default, it's sendrecv for audio and video
														media: { data: true },	// Let's negotiate data channels as well
														success: function(jsep) {
															console.log("Got SDP!");
															console.log(jsep);
															var body = { "request": "accept" };
															videocall.send({"message": body, "jsep": jsep});
															$('#peer').attr('disabled', true);
															$('#call').removeAttr('disabled').html('Hangup')
																.removeClass("btn-success").addClass("btn-danger")
																.unbind('click').click(doHangup);
														},
														error: function(error) {
															console.log("WebRTC error:");
															console.log(error);
															bootbox.alert("WebRTC error... " + JSON.stringify(error));
														}
													});
											} else if(event === 'accepted') {
												var peer = result["username"];
												if(peer === null || peer === undefined) {
													console.log("Call started!");
												} else {
													console.log(peer + " accepted the call!");
													yourusername = peer;
												}
												// TODO Video call can start
												if(jsep !== null && jsep !== undefined)
													videocall.handleRemoteJsep({jsep: jsep});
												$('#call').removeAttr('disabled').html('Hangup')
													.removeClass("btn-success").addClass("btn-danger")
													.unbind('click').click(doHangup);
											} else if(event === 'hangup') {
												console.log("Call hung up by " + result["username"] + " (" + result["reason"] + ")!");
												// TODO Reset status
												videocall.hangup();
												if(spinner !== null && spinner !== undefined)
													spinner.stop();
												$('#waitingvideo').remove();
												$('#videos').hide();
												$('#peer').removeAttr('disabled').val('');
												$('#call').removeAttr('disabled').html('Call')
													.removeClass("btn-danger").addClass("btn-success")
													.unbind('click').click(doCall);
												$('#toggleaudio').attr('disabled', true);
												$('#togglevideo').attr('disabled', true);
												$('#bitrate').attr('disabled', true);
												$('#curbitrate').hide();
												$('#curres').hide();
											}
										}
									} else {
										// FIXME Error?
										var error = msg["error"];
										bootbox.alert(error);
										if(error.indexOf("already taken") > 0) {
											// FIXME Use status codes...
											$('#username').removeAttr('disabled').val("");
											$('#register').removeAttr('disabled').unbind('click').click(registerUsername);
										}
										// TODO Reset status
										videocall.hangup();
										if(spinner !== null && spinner !== undefined)
											spinner.stop();
										$('#waitingvideo').remove();
										$('#videos').hide();
										$('#peer').removeAttr('disabled').val('');
										$('#call').removeAttr('disabled').html('Call')
											.removeClass("btn-danger").addClass("btn-success")
											.unbind('click').click(doCall);
										$('#toggleaudio').attr('disabled', true);
										$('#togglevideo').attr('disabled', true);
										$('#bitrate').attr('disabled', true);
										$('#curbitrate').hide();
										$('#curres').hide();
										if(bitrateTimer !== null && bitrateTimer !== null) 
											clearInterval(bitrateTimer);
										bitrateTimer = null;
									}
								},
								onlocalstream: function(stream) {
									console.log(" ::: Got a local stream :::");
									console.log(JSON.stringify(stream));
									$('#videos').removeClass('hide').show();
									if($('#myvideo').length === 0)
										$('#videoleft').append('<video class="rounded centered" id="myvideo" width=320 height=240 autoplay muted="muted"/>');
									attachMediaStream($('#myvideo').get(0), stream);
									$("#myvideo").get(0).muted = "muted";
									// No remote video yet
									$('#videoright').append('<video class="rounded centered" id="waitingvideo" width=320 height=240 />');
									if(spinner == null) {
										var target = document.getElementById('videoright');
										spinner = new Spinner({top:100}).spin(target);
									} else {
										spinner.spin();
									}
									var videoTracks = stream.getVideoTracks();
									if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
										// No webcam
										$('#myvideo').hide();
										$('#videoleft').append(
											'<div class="no-video-container">' +
												'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
												'<span class="no-video-text">No webcam available</span>' +
											'</div>');
									}
								},
								onremotestream: function(stream) {
									console.log(" ::: Got a remote stream :::");
									console.log(JSON.stringify(stream));
									if($('#remotevideo').length === 0)
										$('#videoright').append('<video class="rounded centered hide" id="remotevideo" width=320 height=240 autoplay/>');
									// Show the video, hide the spinner and show the resolution when we get a playing event
									$("#remotevideo").bind("playing", function () {
										$('#waitingvideo').remove();
										$('#remotevideo').removeClass('hide');
										if(spinner !== null && spinner !== undefined)
											spinner.stop();
										spinner = null;
										var width = this.videoWidth;
										var height = this.videoHeight;
										$('#curres').removeClass('hide').text(width+'x'+height).show();
										if(webrtcDetectedBrowser == "firefox") {
											// Firefox Stable has a bug: width and height are not immediately available after a playing
											setTimeout(function() {
												var width = $("#remotevideo").get(0).videoWidth;
												var height = $("#remotevideo").get(0).videoHeight;
												$('#curres').removeClass('hide').text(width+'x'+height).show();
											}, 2000);
										}
									});
									attachMediaStream($('#remotevideo').get(0), stream);
									var videoTracks = stream.getVideoTracks();
									if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0 || videoTracks[0].muted) {
										// No remote video
										$('#remotevideo').hide();
										$('#videoright').append(
											'<div class="no-video-container">' +
												'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
												'<span class="no-video-text">No remote video available</span>' +
											'</div>');
									}
									$('#callee').removeClass('hide').html(yourusername).show();
									// Enable audio/video buttons and bitrate limiter
									audioenabled = true;
									videoenabled = true;
									$('#toggleaudio').html("Disable audio").removeClass("btn-success").addClass("btn-danger")
											.unbind('click').removeAttr('disabled').click(
										function() {
											audioenabled = !audioenabled;
											if(audioenabled)
												$('#toggleaudio').html("Disable audio").removeClass("btn-success").addClass("btn-danger");
											else
												$('#toggleaudio').html("Enable audio").removeClass("btn-danger").addClass("btn-success");
											videocall.send({"message": { "request": "set", "audio": audioenabled }});
										});
									$('#togglevideo').html("Disable video").removeClass("btn-success").addClass("btn-danger")
											.unbind('click').removeAttr('disabled').click(
										function() {
											videoenabled = !videoenabled;
											if(videoenabled)
												$('#togglevideo').html("Disable video").removeClass("btn-success").addClass("btn-danger");
											else
												$('#togglevideo').html("Enable video").removeClass("btn-danger").addClass("btn-success");
											videocall.send({"message": { "request": "set", "video": videoenabled }});
										});
									$('#toggleaudio').parent().removeClass('hide').show();
									$('#bitrateset').html("Bandwidth");
									$('#bitrate a').unbind('click').removeAttr('disabled').click(function() {
										var id = $(this).attr("id");
										var bitrate = parseInt(id)*1000;
										if(bitrate === 0) {
											console.log("Not limiting bandwidth via REMB");
										} else {
											console.log("Capping bandwidth to " + bitrate + " via REMB");
										}
										$('#bitrateset').html($(this).html()).parent().removeClass('open');
										videocall.send({"message": { "request": "set", "bitrate": bitrate }});
										return false;
									});
									if(!navigator.mozGetUserMedia) {
										// Only Chrome supports the way we interrogate getStats for the bitrate right now
										$('#curbitrate').removeClass('hide').show();
										bitrateTimer = setInterval(function() {
											// Display updated bitrate, if supported
											var bitrate = videocall.getBitrate();
											$('#curbitrate').text(bitrate);
										}, 1000);
									}
								},
								ondataopen: function(data) {
									console.log("The DataChannel is available!");
									$('#videos').removeClass('hide').show();
									$('#datasend').removeAttr('disabled');
								},
								ondata: function(data) {
									console.log("We got data from the DataChannel! " + data);
									$('#datarecv').val(data);
								},
								oncleanup: function() {
									console.log(" ::: Got a cleanup notification :::");
									$('#myvideo').remove();
									$('#remotevideo').remove();
									$('#callee').empty().hide();
									yourusername = null;
									$('#curbitrate').hide();
									$('#curres').hide();
									$('#videos').hide();
									$('#toggleaudio').attr('disabled', true);
									$('#togglevideo').attr('disabled', true);
									$('#bitrate').attr('disabled', true);
									$('#curbitrate').hide();
									$('#curres').hide();
									if(bitrateTimer !== null && bitrateTimer !== null) 
										clearInterval(bitrateTimer);
									bitrateTimer = null;
									$('#waitingvideo').remove();
									$('#videos').hide();
									$('#peer').removeAttr('disabled').val('');
									$('#call').removeAttr('disabled').html('Call')
										.removeClass("btn-danger").addClass("btn-success")
										.unbind('click').click(doCall);
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
		if(field.id == 'username')
			registerUsername();
		else if(field.id == 'peer')
			doCall();
		else if(field.id == 'datasend')
			sendData();
		return false;
	} else {
		return true;
	}
}

function registerUsername() {
	// Try a registration
	$('#username').attr('disabled', true);
	$('#register').attr('disabled', true).unbind('click');
	var username = $('#username').val();
	if(username === "") {
		bootbox.alert("Insert a username to register (e.g., pippo)");
		$('#username').removeAttr('disabled');
		$('#register').removeAttr('disabled').click(registerUsername);
		return;
	}
	if(/[^a-zA-Z0-9]/.test(username)) {
		bootbox.alert('Input is not alphanumeric');
		$('#username').removeAttr('disabled').val("");
		$('#register').removeAttr('disabled').click(registerUsername);
		return;
	}
	var register = { "request": "register", "username": username };
	videocall.send({"message": register});
}

function doCall() {
	// Call someone
	$('#peer').attr('disabled', true);
	$('#call').attr('disabled', true).unbind('click');
	var username = $('#peer').val();
	if(username === "") {
		bootbox.alert("Insert a username to call (e.g., pluto)");
		$('#peer').removeAttr('disabled');
		$('#call').removeAttr('disabled').click(doCall);
		return;
	}
	if(/[^a-zA-Z0-9]/.test(username)) {
		bootbox.alert('Input is not alphanumeric');
		$('#peer').removeAttr('disabled').val("");
		$('#call').removeAttr('disabled').click(doCall);
		return;
	}
	// Call this user
	videocall.createOffer(
		{
			// By default, it's sendrecv for audio and video...
			media: { data: true },	// ... let's negotiate data channels as well
			success: function(jsep) {
				console.log("Got SDP!");
				console.log(jsep);
				var body = { "request": "call", "username": $('#peer').val() };
				videocall.send({"message": body, "jsep": jsep});
			},
			error: function(error) {
				console.log("WebRTC error... " + error);
				bootbox.alert("WebRTC error... " + error);
			}
		});
}

function doHangup() {
	// Hangup a call
	$('#call').attr('disabled', true).unbind('click');
	var hangup = { "request": "hangup" };
	videocall.send({"message": hangup});
	videocall.hangup();
	yourusername = null;
}

function sendData() {
	var data = $('#datasend').val();
	if(data === "") {
		bootbox.alert('Insert a message to send on the DataChannel to your peer');
		return;
	}
	videocall.data({
		text: data,
		error: function(reason) { bootbox.alert(reason); },
		success: function() { $('#datasend').val(''); },
	});
}
