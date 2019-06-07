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
var sipcall = null;
var opaqueId = "siptest-"+Janus.randomString(12);

var spinner = null;

var selectedApproach = null;
var registered = false;

var incoming = null;


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
						// Attach to echo test plugin
						janus.attach(
							{
								plugin: "janus.plugin.sip",
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									sipcall = pluginHandle;
									Janus.log("Plugin attached! (" + sipcall.getPlugin() + ", id=" + sipcall.getId() + ")");
									// Prepare the username registration
									$('#sipcall').removeClass('hide').show();
									$('#login').removeClass('hide').show();
									$('#registerlist a').unbind('click').click(function() {
										selectedApproach = $(this).attr("id");
										$('#registerset').html($(this).html()).parent().removeClass('open');
										if(selectedApproach === "guest") {
											$('#password').empty().attr('disabled', true);
										} else {
											$('#password').removeAttr('disabled');
										}
										switch(selectedApproach) {
											case "secret":
												bootbox.alert("Using this approach you'll provide a plain secret to REGISTER");
												break;
											case "ha1secret":
												bootbox.alert("Using this approach might not work with Asterisk because the generated HA1 secret could have the wrong realm");
												break;
											case "guest":
												bootbox.alert("Using this approach you'll try to REGISTER as a guest, that is without providing any secret");
												break;
											default:
												break;
										}
										return false;
									});
									$('#register').click(registerUsername);
									$('#server').focus();
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											janus.destroy();
										});
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
								mediaState: function(medium, on) {
									Janus.log("Janus " + (on ? "started" : "stopped") + " receiving our " + medium);
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::");
									Janus.debug(msg);
									// Any error?
									var error = msg["error"];
									if(error != null && error != undefined) {
										if(!registered) {
											$('#server').removeAttr('disabled');
											$('#username').removeAttr('disabled');
											$('#authuser').removeAttr('disabled');
											$('#displayname').removeAttr('disabled');
											$('#password').removeAttr('disabled');
											$('#register').removeAttr('disabled').click(registerUsername);
											$('#registerset').removeAttr('disabled');
										} else {
											// Reset status
											sipcall.hangup();
											$('#dovideo').removeAttr('disabled').val('');
											$('#peer').removeAttr('disabled').val('');
											$('#call').removeAttr('disabled').html('Call')
												.removeClass("btn-danger").addClass("btn-success")
												.unbind('click').click(doCall);
										}
										bootbox.alert(error);
										return;
									}
									var result = msg["result"];
									if(result !== null && result !== undefined && result["event"] !== undefined && result["event"] !== null) {
										var event = result["event"];
										if(event === 'registration_failed') {
											Janus.warn("Registration failed: " + result["code"] + " " + result["reason"]);
											$('#server').removeAttr('disabled');
											$('#username').removeAttr('disabled');
											$('#authuser').removeAttr('disabled');
											$('#displayname').removeAttr('disabled');
											$('#password').removeAttr('disabled');
											$('#register').removeAttr('disabled').click(registerUsername);
											$('#registerset').removeAttr('disabled');
											bootbox.alert(result["code"] + " " + result["reason"]);
											return;
										}
										if(event === 'registered') {
											Janus.log("Successfully registered as " + result["username"] + "!");
											$('#you').removeClass('hide').show().text("Registered as '" + result["username"] + "'");
											// TODO Enable buttons to call now
											if(!registered) {
												registered = true;
												$('#phone').removeClass('hide').show();
												$('#call').unbind('click').click(doCall);
												$('#peer').focus();
											}
										} else if(event === 'calling') {
											Janus.log("Waiting for the peer to answer...");
											// TODO Any ringtone?
											$('#call').removeAttr('disabled').html('Hangup')
												  .removeClass("btn-success").addClass("btn-danger")
												  .unbind('click').click(doHangup);
										} else if(event === 'incomingcall') {
											Janus.log("Incoming call from " + result["username"] + "!");
											var doAudio = true, doVideo = true;
											var offerlessInvite = false;
											if(jsep !== null && jsep !== undefined) {
												// What has been negotiated?
												doAudio = (jsep.sdp.indexOf("m=audio ") > -1);
												doVideo = (jsep.sdp.indexOf("m=video ") > -1);
												Janus.debug("Audio " + (doAudio ? "has" : "has NOT") + " been negotiated");
												Janus.debug("Video " + (doVideo ? "has" : "has NOT") + " been negotiated");
											} else {
												Janus.log("This call doesn't contain an offer... we'll need to provide one ourselves");
												offerlessInvite = true;
												// In case you want to offer video when reacting to an offerless call, set this to true
												doVideo = false;
											}
											// Any security offered? A missing "srtp" attribute means plain RTP
											var rtpType = "";
											var srtp = result["srtp"];
											if(srtp === "sdes_optional")
												rtpType = " (SDES-SRTP offered)";
											else if(srtp === "sdes_mandatory")
												rtpType = " (SDES-SRTP mandatory)";
											// Notify user
											bootbox.hideAll();
											var extra = "";
											if(offerlessInvite)
												extra = " (no SDP offer provided)"
											incoming = bootbox.dialog({
												message: "Incoming call from " + result["username"] + "!" + rtpType + extra,
												title: "Incoming call",
												closeButton: false,
												buttons: {
													success: {
														label: "Answer",
														className: "btn-success",
														callback: function() {
															incoming = null;
															$('#peer').val(result["username"]).attr('disabled', true);
															// Notice that we can only answer if we got an offer: if this was
															// an offerless call, we'll need to create an offer ourselves
															var sipcallAction = (offerlessInvite ? sipcall.createOffer : sipcall.createAnswer);
															sipcallAction(
																{
																	jsep: jsep,
																	media: { audio: doAudio, video: doVideo },
																	success: function(jsep) {
																		Janus.debug("Got SDP " + jsep.type + "! audio=" + doAudio + ", video=" + doVideo);
																		Janus.debug(jsep);
																		var body = { request: "accept" };
																		// Note: as with "call", you can add a "srtp" attribute to
																		// negotiate/mandate SDES support for this incoming call.
																		// The default behaviour is to automatically use it if
																		// the caller negotiated it, but you may choose to require
																		// SDES support by setting "srtp" to "sdes_mandatory", e.g.:
																		//		var body = { request: "accept", srtp: "sdes_mandatory" };
																		// This way you'll tell the plugin to accept the call, but ONLY
																		// if SDES is available, and you don't want plain RTP. If it
																		// is not available, you'll get an error (452) back. You can
																		// also specify the SRTP profile to negotiate by setting the
																		// "srtp_profile" property accordingly (the default if not
																		// set in the request is "AES_CM_128_HMAC_SHA1_80")
																		// Note 2: by default, the SIP plugin auto-answers incoming
																		// re-INVITEs, without involving the browser/client: this is
																		// for backwards compatibility with older Janus clients that
																		// may not be able to handle them. If you want to receive
																		// re-INVITES to handle them yourself, specify it here, e.g.:
																		//		body["autoaccept_reinvites"] = false;
																		sipcall.send({"message": body, "jsep": jsep});
																		$('#call').removeAttr('disabled').html('Hangup')
																			.removeClass("btn-success").addClass("btn-danger")
																			.unbind('click').click(doHangup);
																	},
																	error: function(error) {
																		Janus.error("WebRTC error:", error);
																		bootbox.alert("WebRTC error... " + JSON.stringify(error));
																		// Don't keep the caller waiting any longer, but use a 480 instead of the default 486 to clarify the cause
																		var body = { "request": "decline", "code": 480 };
																		sipcall.send({"message": body});
																	}
																});
														}
													},
													danger: {
														label: "Decline",
														className: "btn-danger",
														callback: function() {
															incoming = null;
															var body = { "request": "decline" };
															sipcall.send({"message": body});
														}
													}
												}
											});
										} else if(event === 'accepting') {
											// Response to an offerless INVITE, let's wait for an 'accepted'
										} else if(event === 'progress') {
											Janus.log("There's early media from " + result["username"] + ", wairing for the call!");
											Janus.log(jsep);
											// Call can start already: handle the remote answer
											if(jsep !== null && jsep !== undefined) {
												sipcall.handleRemoteJsep({jsep: jsep, error: doHangup });
											}
											toastr.info("Early media...");
										} else if(event === 'accepted') {
											Janus.log(result["username"] + " accepted the call!");
											Janus.log(jsep);
											// Call can start, now: handle the remote answer
											if(jsep !== null && jsep !== undefined) {
												sipcall.handleRemoteJsep({jsep: jsep, error: doHangup });
											}
											toastr.success("Call accepted!");
										} else if(event === 'updatingcall') {
											// We got a re-INVITE: while we may prompt the user (e.g.,
											// to notify about media changes), to keep things simple
											// we just accept the update and send an answer right away
											Janus.log("Got re-INVITE");
											var doAudio = (jsep.sdp.indexOf("m=audio ") > -1),
												doVideo = (jsep.sdp.indexOf("m=video ") > -1);
											sipcall.createAnswer(
												{
													jsep: jsep,
													media: { audio: doAudio, video: doVideo },
													success: function(jsep) {
														Janus.debug("Got SDP " + jsep.type + "! audio=" + doAudio + ", video=" + doVideo);
														Janus.debug(jsep);
														var body = { request: "update" };
														sipcall.send({"message": body, "jsep": jsep});
													},
													error: function(error) {
														Janus.error("WebRTC error:", error);
														bootbox.alert("WebRTC error... " + JSON.stringify(error));
													}
												});
										} else if(event === 'hangup') {
											if(incoming != null) {
												incoming.modal('hide');
												incoming = null;
											}
											Janus.log("Call hung up (" + result["code"] + " " + result["reason"] + ")!");
											bootbox.alert(result["code"] + " " + result["reason"]);
											// Reset status
											sipcall.hangup();
											$('#dovideo').removeAttr('disabled').val('');
											$('#peer').removeAttr('disabled').val('');
											$('#call').removeAttr('disabled').html('Call')
												.removeClass("btn-danger").addClass("btn-success")
												.unbind('click').click(doCall);
										}
									}
								},
								onlocalstream: function(stream) {
									Janus.debug(" ::: Got a local stream :::");
									Janus.debug(stream);
									$('#videos').removeClass('hide').show();
									if($('#myvideo').length === 0)
										$('#videoleft').append('<video class="rounded centered" id="myvideo" width=320 height=240 autoplay playsinline muted="muted"/>');
									Janus.attachMediaStream($('#myvideo').get(0), stream);
									$("#myvideo").get(0).muted = "muted";
									if(sipcall.webrtcStuff.pc.iceConnectionState !== "completed" &&
											sipcall.webrtcStuff.pc.iceConnectionState !== "connected") {
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
									Janus.debug(" ::: Got a remote stream :::");
									Janus.debug(stream);
									if($('#remotevideo').length === 0) {
										$('#videoright').parent().find('h3').html(
											'Send DTMF: <span id="dtmf" class="btn-group btn-group-xs"></span>');
										$('#videoright').append(
											'<video class="rounded centered hide" id="remotevideo" width=320 height=240 autoplay playsinline/>');
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
											sipcall.dtmf({dtmf: { tones: $(this).text()}});
											// Notice you can also send DTMF tones using SIP INFO
											// 		sipcall.send({message: {request: "dtmf_info", digit: $(this).text()}});
										});
										// Show the peer and hide the spinner when we get a playing event
										$("#remotevideo").bind("playing", function () {
											$('#waitingvideo').remove();
											if(this.videoWidth)
												$('#remotevideo').removeClass('hide').show();
											if(spinner !== null && spinner !== undefined)
												spinner.stop();
											spinner = null;
										});
									}
									Janus.attachMediaStream($('#remotevideo').get(0), stream);
									var videoTracks = stream.getVideoTracks();
									if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
										// No remote video
										$('#remotevideo').hide();
										if($('#videoright .no-video-container').length === 0) {
											$('#videoright').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
													'<span class="no-video-text">No remote video available</span>' +
												'</div>');
										}
									} else {
										$('#videoright .no-video-container').remove();
										$('#remotevideo').removeClass('hide').show();
									}
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									$('#myvideo').remove();
									$('#waitingvideo').remove();
									$('#remotevideo').remove();
									$('.no-video-container').remove();
									$('#videos').hide();
									$('#dtmf').parent().html("Remote UA");
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
	var theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if(theCode == 13) {
		if(field.id == 'server' || field.id == 'username' || field.id == 'password' || field.id == 'displayname')
			registerUsername();
		else if(field.id == 'peer')
			doCall();
		return false;
	} else {
		return true;
	}
}

function registerUsername() {
	if(selectedApproach === null || selectedApproach === undefined) {
		bootbox.alert("Please select a registration approach from the dropdown menu");
		return;
	}
	// Try a registration
	$('#server').attr('disabled', true);
	$('#username').attr('disabled', true);
	$('#authuser').attr('disabled', true);
	$('#displayname').attr('disabled', true);
	$('#password').attr('disabled', true);
	$('#register').attr('disabled', true).unbind('click');
	$('#registerset').attr('disabled', true);
	// Let's see if the user provided a server address
	// 		NOTE WELL! Even though the attribute we set in the request is called "proxy",
	//		this is actually the _registrar_. If you want to set an outbound proxy (for this
	//		REGISTER request and for all INVITEs that will follow), you'll need to set the
	//		"outbound_proxy" property in the request instead. The two are of course not
	//		mutually exclusive. If you set neither, the domain part of the user identity
	//		will be used as the target of the REGISTER request the plugin might send.
	var sipserver = $('#server').val();
	if(sipserver !== "" && sipserver.indexOf("sip:") != 0 && sipserver.indexOf("sips:") !=0) {
		bootbox.alert("Please insert a valid SIP server (e.g., sip:192.168.0.1:5060)");
		$('#server').removeAttr('disabled');
		$('#username').removeAttr('disabled');
		$('#authuser').removeAttr('disabled');
		$('#displayname').removeAttr('disabled');
		$('#password').removeAttr('disabled');
		$('#register').removeAttr('disabled').click(registerUsername);
		$('#registerset').removeAttr('disabled');
		return;
	}
	if(selectedApproach === "guest") {
		// We're registering as guests, no username/secret provided
		var register = {
			"request" : "register",
			"type" : "guest"
		};
		if(sipserver !== "") {
			register["proxy"] = sipserver;
			// Uncomment this if you want to see an outbound proxy too
			//~ register["outbound_proxy"] = "sip:outbound.example.com";
		}
		var username = $('#username').val();
		if(!username === "" || username.indexOf("sip:") != 0 || username.indexOf("@") < 0) {
			bootbox.alert("Please insert a valid SIP address (e.g., sip:goofy@example.com): this doesn't need to exist for guests, but is required");
			$('#server').removeAttr('disabled');
			$('#username').removeAttr('disabled');
			$('#authuser').removeAttr('disabled');
			$('#displayname').removeAttr('disabled');
			$('#register').removeAttr('disabled').click(registerUsername);
			$('#registerset').removeAttr('disabled');
			return;
		}
		register.username = username;
		var displayname = $('#displayname').val();
		if(displayname) {
			register.display_name = displayname;
		}
		if(sipserver === "") {
			bootbox.confirm("You didn't specify a SIP Registrar to use: this will cause the plugin to try and conduct a standard (<a href='https://tools.ietf.org/html/rfc3263' target='_blank'>RFC3263</a>) lookup. If this is not what you want or you don't know what this means, hit Cancel and provide a SIP Registrar instead'",
				function(result) {
					if(result) {
						sipcall.send({"message": register});
					} else {
						$('#server').removeAttr('disabled');
						$('#username').removeAttr('disabled');
						$('#authuser').removeAttr('disabled');
						$('#displayname').removeAttr('disabled');
						$('#register').removeAttr('disabled').click(registerUsername);
						$('#registerset').removeAttr('disabled');
					}
				});
		} else {
			sipcall.send({"message": register});
		}
		return;
	}
	var username = $('#username').val();
	if(username === "" || username.indexOf("sip:") != 0 || username.indexOf("@") < 0) {
		bootbox.alert('Please insert a valid SIP identity address (e.g., sip:goofy@example.com)');
		$('#server').removeAttr('disabled');
		$('#username').removeAttr('disabled');
		$('#authuser').removeAttr('disabled');
		$('#displayname').removeAttr('disabled');
		$('#password').removeAttr('disabled');
		$('#register').removeAttr('disabled').click(registerUsername);
		$('#registerset').removeAttr('disabled');
		return;
	}
	var password = $('#password').val();
	if(password === "") {
		bootbox.alert("Insert the username secret (e.g., mypassword)");
		$('#server').removeAttr('disabled');
		$('#username').removeAttr('disabled');
		$('#authuser').removeAttr('disabled');
		$('#displayname').removeAttr('disabled');
		$('#password').removeAttr('disabled');
		$('#register').removeAttr('disabled').click(registerUsername);
		$('#registerset').removeAttr('disabled');
		return;
	}
	var register = {
		"request" : "register",
		"username" : username
	};
	// By default, the SIP plugin tries to extract the username part from the SIP
	// identity to register; if the username is different, you can provide it here
	var authuser = $('#authuser').val();
	if(authuser !== "") {
		register.authuser = authuser;
	}
	// The display name is only needed when you want a friendly name to appear when you call someone
	var displayname = $('#displayname').val();
	if(displayname !== "") {
		register.display_name = displayname;
	}
	if(selectedApproach === "secret") {
		// Use the plain secret
		register["secret"] = password;
	} else if(selectedApproach === "ha1secret") {
		var sip_user = username.substring(4, username.indexOf('@'));    /* skip sip: */
		var sip_domain = username.substring(username.indexOf('@')+1);
		register["ha1_secret"] = md5(sip_user+':'+sip_domain+':'+password);
	}
	if(sipserver === "") {
		bootbox.confirm("You didn't specify a SIP Registrar: this will cause the plugin to try and conduct a standard (<a href='https://tools.ietf.org/html/rfc3263' target='_blank'>RFC3263</a>) lookup. If this is not what you want or you don't know what this means, hit Cancel and provide a SIP Registrar instead'",
			function(result) {
				if(result) {
					sipcall.send({"message": register});
				} else {
					$('#server').removeAttr('disabled');
					$('#username').removeAttr('disabled');
					$('#authuser').removeAttr('disabled');
					$('#displayname').removeAttr('disabled');
					$('#password').removeAttr('disabled');
					$('#register').removeAttr('disabled').click(registerUsername);
					$('#registerset').removeAttr('disabled');
				}
			});
	} else {
		register["proxy"] = sipserver;
		// Uncomment this if you want to see an outbound proxy too
		//~ register["outbound_proxy"] = "sip:outbound.example.com";
		sipcall.send({"message": register});
	}
}

function doCall() {
	// Call someone
	$('#peer').attr('disabled', true);
	$('#call').attr('disabled', true).unbind('click');
	$('#dovideo').attr('disabled', true);
	var username = $('#peer').val();
	if(username === "") {
		bootbox.alert('Please insert a valid SIP address (e.g., sip:pluto@example.com)');
		$('#peer').removeAttr('disabled');
		$('#dovideo').removeAttr('disabled');
		$('#call').removeAttr('disabled').click(doCall);
		return;
	}
	if(username.indexOf("sip:") != 0 || username.indexOf("@") < 0) {
		bootbox.alert('Please insert a valid SIP address (e.g., sip:pluto@example.com)');
		$('#peer').removeAttr('disabled').val("");
		$('#dovideo').removeAttr('disabled').val("");
		$('#call').removeAttr('disabled').click(doCall);
		return;
	}
	// Call this URI
	doVideo = $('#dovideo').is(':checked');
	Janus.log("This is a SIP " + (doVideo ? "video" : "audio") + " call (dovideo=" + doVideo + ")");
	sipcall.createOffer(
		{
			media: {
				audioSend: true, audioRecv: true,		// We DO want audio
				videoSend: doVideo, videoRecv: doVideo	// We MAY want video
			},
			success: function(jsep) {
				Janus.debug("Got SDP!");
				Janus.debug(jsep);
				// By default, you only pass the SIP URI to call as an
				// argument to a "call" request. Should you want the
				// SIP stack to add some custom headers to the INVITE,
				// you can do so by adding an additional "headers" object,
				// containing each of the headers as key-value, e.g.:
				//		var body = { request: "call", uri: $('#peer').val(),
				//			headers: {
				//				"My-Header": "value",
				//				"AnotherHeader": "another string"
				//			}
				//		};
				var body = { request: "call", uri: $('#peer').val() };
				// Note: you can also ask the plugin to negotiate SDES-SRTP, instead of the
				// default plain RTP, by adding a "srtp" attribute to the request. Valid
				// values are "sdes_optional" and "sdes_mandatory", e.g.:
				//		var body = { request: "call", uri: $('#peer').val(), srtp: "sdes_optional" };
				// "sdes_optional" will negotiate RTP/AVP and add a crypto line,
				// "sdes_mandatory" will set the protocol to RTP/SAVP instead.
				// Just beware that some endpoints will NOT accept an INVITE
				// with a crypto line in it if the protocol is not RTP/SAVP,
				// so if you want SDES use "sdes_optional" with care.
				// Note 2: by default, the SIP plugin auto-answers incoming
				// re-INVITEs, without involving the browser/client: this is
				// for backwards compatibility with older Janus clients that
				// may not be able to handle them. If you want to receive
				// re-INVITES to handle them yourself, specify it here, e.g.:
				//		body["autoaccept_reinvites"] = false;
				sipcall.send({"message": body, "jsep": jsep});
			},
			error: function(error) {
				Janus.error("WebRTC error...", error);
				bootbox.alert("WebRTC error... " + JSON.stringify(error));
			}
		});
}

function doHangup() {
	// Hangup a call
	$('#call').attr('disabled', true).unbind('click');
	var hangup = { "request": "hangup" };
	sipcall.send({"message": hangup});
	sipcall.hangup();
}
