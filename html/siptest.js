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
var masterId = null, helpers = {}, helpersCount = 0;

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
						// Attach to SIP plugin
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
												masterId = result["master_id"];
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
											// Is this the result of a transfer?
											var transfer = "";
											var referredBy = result["referred_by"];
											if(referredBy)
												transfer = " (referred by " + referredBy + ")";
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
												message: "Incoming call from " + result["username"] + "!" + transfer + rtpType + extra,
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
										} else if(event === 'transfer') {
											// We're being asked to transfer the call, ask the user what to do
											var referTo = result["refer_to"];
											var referredBy = result["referred_by"] ? result["referred_by"] : "an unknown party";
											var referId = result["refer_id"];
											var replaces = result["replaces"];
											var extra = ("referred by " + referredBy);
											if(replaces)
												extra += (", replaces call-ID " + replaces);
											bootbox.confirm("Transfer the call to " + referTo + "? (" + extra + ")",
												function(result) {
													if(result) {
														// Call the person we're being transferred to
														if(!sipcall.webrtcStuff.pc) {
															// Do it here
															actuallyDoCall(sipcall, referTo, false, referId);
														} else {
															// We're in a call already, use a helper
															var h = -1;
															if(Object.keys(helpers).length > 0) {
																// See if any of the helpers if available
																for(var i in helpers) {
																	if(!helpers[i].sipcall.webrtcStuff.pc) {
																		h = parseInt(i);
																		break;
																	}
																}
															}
															if(h !== -1) {
																// Do in this helper
																actuallyDoCall(helpers[h].sipcall, referTo, false, referId);
															} else {
																// Create a new helper
																addHelper(function(id) {
																	// Do it here
																	actuallyDoCall(helpers[id].sipcall, referTo, false, referId);
																});
															}
														}
													} else {
														// We're rejecting the transfer
														var body = { request: "decline", refer_id: referId };
														sipcall.send({"message": body});
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
											sipcall.dtmf({dtmf: { digit: $(this).text()}});
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
									$('#videos .no-video-container').remove();
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

function doCall(ev) {
	// Call someone (from the main session or one of the helpers)
	var button = ev ? ev.currentTarget.id : "call";
	var helperId = button.split("call")[1];
	if(helperId === "")
		helperId = null;
	else
		helperId = parseInt(helperId);
	var handle = helperId ? helpers[helperId].sipcall : sipcall;
	var prefix = helperId ? ("[Helper #" + helperId + "]") : "";
	var suffix = helperId ? (""+helperId) : "";
	$('#peer' + suffix).attr('disabled', true);
	$('#call' + suffix).attr('disabled', true).unbind('click');
	$('#dovideo' + suffix).attr('disabled', true);
	var username = $('#peer' + suffix).val();
	if(username === "") {
		bootbox.alert('Please insert a valid SIP address (e.g., sip:pluto@example.com)');
		$('#peer' + suffix).removeAttr('disabled');
		$('#dovideo' + suffix).removeAttr('disabled');
		$('#call' + suffix).removeAttr('disabled').click(function() { doCall(helperId); });
		return;
	}
	if(username.indexOf("sip:") != 0 || username.indexOf("@") < 0) {
		bootbox.alert('Please insert a valid SIP address (e.g., sip:pluto@example.com)');
		$('#peer' + suffix).removeAttr('disabled').val("");
		$('#dovideo' + suffix).removeAttr('disabled').val("");
		$('#call' + suffix).removeAttr('disabled').click(function() { doCall(helperId); });
		return;
	}
	// Call this URI
	doVideo = $('#dovideo' + suffix).is(':checked');
	Janus.log(prefix + "This is a SIP " + (doVideo ? "video" : "audio") + " call (dovideo=" + doVideo + ")");
	actuallyDoCall(handle, $('#peer' + suffix).val(), doVideo);
}
function actuallyDoCall(handle, uri, doVideo, referId) {
	handle.createOffer(
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
				var body = { request: "call", uri: uri };
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
				if(referId) {
					// In case we're originating this call because of a call
					// transfer, we need to provide the internal reference ID
					body["refer_id"] = referId;
				}
				handle.send({"message": body, "jsep": jsep});
			},
			error: function(error) {
				Janus.error(prefix + "WebRTC error...", error);
				bootbox.alert("WebRTC error... " + JSON.stringify(error));
			}
		});
}

function doHangup(ev) {
	// Hangup a call (on the main session or one of the helpers)
	var button = ev ? ev.currentTarget.id : "call";
	var helperId = button.split("call")[1];
	if(helperId === "")
		helperId = null;
	else
		helperId = parseInt(helperId);
	if(!helperId) {
		$('#call').attr('disabled', true).unbind('click');
		var hangup = { "request": "hangup" };
		sipcall.send({"message": hangup});
		sipcall.hangup();
	} else {
		$('#call' + helperId).attr('disabled', true).unbind('click');
		var hangup = { "request": "hangup" };
		helpers[helperId].sipcall.send({"message": hangup});
		helpers[helperId].sipcall.hangup();
	}
}

// The following code is only needed if you're interested in supporting multiple
// calls at the same time. As explained in the Janus documentation, each Janus
// handle can only do one PeerConnection at a time, which means you normally
// cannot do multiple calls. If that's something you need (e.g., because you
// need to do a SIP transfer, or want to be in two calls), then the SIP plugin
// provides the so-called "helpers": basically additional handles attached to
// the SIP plugin, and associated to your SIP identity. They can be used to
// originate and receive calls exactly as the main handle: notice that incoming
// calls will be rejected with a "486 Busy" if you're in a call already and there
// are no available "helpers", which means you should add one in advance for that.
// In this demo, creating a "helper" adds a new row for calls that looks and
// works exactly as the default one: you can add more than one "helper", and
// obviously the more you have, the more concurrent calls you can have.
function addHelper(helperCreated) {
	helpersCount++;
	var helperId = helpersCount;
	helpers[helperId] = { id: helperId };
	// Add another row with a new "phone"
	$('.footer').before(
		'<div class="container" id="sipcall' + helperId + '">' +
		'	<div class="row">' +
		'		<div class="col-md-12">' +
		'			<div class="col-md-6 container">' +
		'				<span class="label label-info">Helper #' + helperId + '</span>' +
		'			</div>' +
		'			<div class="col-md-6 container" id="phone' + helperId + '">' +
		'				<div class="input-group margin-bottom-sm">' +
		'					<span class="input-group-addon"><i class="fa fa-phone fa-fw"></i></span>' +
		'					<input disabled class="form-control" type="text" placeholder="SIP URI to call (e.g., sip:1000@example.com)" autocomplete="off" id="peer' + helperId + '" onkeypress="return checkEnter(this, event, ' + helperId + ');"></input>' +
		'				</div>' +
		'				<button disabled class="btn btn-success margin-bottom-sm" autocomplete="off" id="call' + helperId + '">Call</button> <input autocomplete="off" id="dovideo' + helperId + '" type="checkbox">Use Video</input>' +
		'			</div>' +
		'		</div>' +
		'	<div/>' +
		'	<div id="videos' + helperId + '" class="hide">' +
		'		<div class="col-md-6">' +
		'			<div class="panel panel-default">' +
		'				<div class="panel-heading">' +
		'					<h3 class="panel-title">You</h3>' +
		'				</div>' +
		'				<div class="panel-body" id="videoleft' + helperId + '"></div>' +
		'			</div>' +
		'		</div>' +
		'		<div class="col-md-6">' +
		'			<div class="panel panel-default">' +
		'				<div class="panel-heading">' +
		'					<h3 class="panel-title">Remote UA</h3>' +
		'				</div>' +
		'				<div class="panel-body" id="videoright' + helperId + '"></div>' +
		'			</div>' +
		'		</div>' +
		'	</div>' +
		'</div>'
	);
	// Attach to SIP plugin, but only register as an helper for the master session
	janus.attach(
		{
			plugin: "janus.plugin.sip",
			opaqueId: opaqueId,
			success: function(pluginHandle) {
				helpers[helperId].sipcall = pluginHandle;
				Janus.log("[Helper #" + helperId + "] Plugin attached! (" + helpers[helperId].sipcall.getPlugin() + ", id=" + helpers[helperId].sipcall.getId() + ")");
				// TODO Send the "register"
				helpers[helperId].sipcall.send({
					message: {
						request: "register",
						type: "helper",
						username: $('#username').val(),	// We use the same username as the master session
						master_id: masterId				// Then we add the ID of the master session, nothing else
					}
				});
			},
			error: function(error) {
				Janus.error("[Helper #" + helperId + "]   -- Error attaching plugin...", error);
				bootbox.alert("  -- Error attaching plugin... " + error);
			},
			consentDialog: function(on) {
				Janus.debug("[Helper #" + helperId + "] Consent dialog should be " + (on ? "on" : "off") + " now");
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
				Janus.log("[Helper #" + helperId + "] Janus " + (on ? "started" : "stopped") + " receiving our " + medium);
			},
			webrtcState: function(on) {
				Janus.log("[Helper #" + helperId + "] Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
				$("#videoleft" + helperId).parent().unblock();
			},
			onmessage: function(msg, jsep) {
				Janus.debug("[Helper #" + helperId + "]  ::: Got a message :::");
				Janus.debug(msg);
				// Any error?
				var error = msg["error"];
				if(error != null && error != undefined) {
					bootbox.alert(error);
					return;
				}
				var result = msg["result"];
				if(result !== null && result !== undefined && result["event"] !== undefined && result["event"] !== null) {
					var event = result["event"];
					if(event === 'registration_failed') {
						Janus.warn("[Helper #" + helperId + "] Registration failed: " + result["code"] + " " + result["reason"]);
						bootbox.alert(result["code"] + " " + result["reason"]);
						// Get rid of the helper
						helpers[helperId].detach();
						delete helpers[helperId];
						$('#sipcall' + helperId).remove();
						return;
					}
					if(event === 'registered') {
						Janus.log("[Helper #" + helperId + "] Successfully registered as " + result["username"] + "!");
						// Unlock the "phone" controls
						$('#peer' + helperId).removeAttr('disabled');
						$('#call' + helperId).removeAttr('disabled').html('Call')
							.removeClass("btn-danger").addClass("btn-success")
							.unbind('click').click(doCall);
						if(helperCreated)
							helperCreated(helperId);
					} else if(event === 'calling') {
						Janus.log("[Helper #" + helperId + "] Waiting for the peer to answer...");
						// TODO Any ringtone?
						$('#call' + helperId).removeAttr('disabled').html('Hangup')
							  .removeClass("btn-success").addClass("btn-danger")
							  .unbind('click').click(doHangup);
					} else if(event === 'incomingcall') {
						Janus.log("[Helper #" + helperId + "] Incoming call from " + result["username"] + "! (on helper #" + helperId + ")");
						var doAudio = true, doVideo = true;
						var offerlessInvite = false;
						if(jsep !== null && jsep !== undefined) {
							// What has been negotiated?
							doAudio = (jsep.sdp.indexOf("m=audio ") > -1);
							doVideo = (jsep.sdp.indexOf("m=video ") > -1);
							Janus.debug("[Helper #" + helperId + "] Audio " + (doAudio ? "has" : "has NOT") + " been negotiated");
							Janus.debug("[Helper #" + helperId + "] Video " + (doVideo ? "has" : "has NOT") + " been negotiated");
						} else {
							Janus.log("[Helper #" + helperId + "] This call doesn't contain an offer... we'll need to provide one ourselves");
							offerlessInvite = true;
							// In case you want to offer video when reacting to an offerless call, set this to true
							doVideo = false;
						}
						// Is this the result of a transfer?
						var transfer = "";
						var referredBy = result["referred_by"];
						var replaces = result["replaces"];
						if(referredBy && replaces)
							transfer = " (referred by " + referredBy + ", replaces call-ID " + replaces + ")";
						else if(referredBy && !replaces)
							transfer = " (referred by " + referredBy + ")";
						else if(!referredBy && replaces)
							transfer = " (replaces call-ID " + replaces + ")";
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
							message: "Incoming call from " + result["username"] + "!" + transfer + rtpType + extra + " (on helper #" + helperId + ")",
							title: "Incoming call (helper " + helperId + ")",
							closeButton: false,
							buttons: {
								success: {
									label: "Answer",
									className: "btn-success",
									callback: function() {
										incoming = null;
										$('#peer' + helperId).val(result["username"]).attr('disabled', true);
										// Notice that we can only answer if we got an offer: if this was
										// an offerless call, we'll need to create an offer ourselves
										var sipcallAction = (offerlessInvite ? helpers[helperId].sipcall.createOffer : helpers[helperId].sipcall.createAnswer);
										sipcallAction(
											{
												jsep: jsep,
												media: { audio: doAudio, video: doVideo },
												success: function(jsep) {
													Janus.debug("[Helper #" + helperId + "] Got SDP " + jsep.type + "! audio=" + doAudio + ", video=" + doVideo);
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
													helpers[helperId].sipcall.send({"message": body, "jsep": jsep});
													$('#call' + helperId).removeAttr('disabled').html('Hangup')
														.removeClass("btn-success").addClass("btn-danger")
														.unbind('click').click(doHangup);
												},
												error: function(error) {
													Janus.error("[Helper #" + helperId + "] WebRTC error:", error);
													bootbox.alert("WebRTC error... " + JSON.stringify(error));
													// Don't keep the caller waiting any longer, but use a 480 instead of the default 486 to clarify the cause
													var body = { "request": "decline", "code": 480 };
													helpers[helperId].sipcall.send({"message": body});
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
										helpers[helperId].sipcall.send({"message": body});
									}
								}
							}
						});
					} else if(event === 'accepting') {
						// Response to an offerless INVITE, let's wait for an 'accepted'
					} else if(event === 'progress') {
						Janus.log("[Helper #" + helperId + "] There's early media from " + result["username"] + ", wairing for the call!");
						Janus.log(jsep);
						// Call can start already: handle the remote answer
						if(jsep !== null && jsep !== undefined) {
							helpers[helperId].sipcall.handleRemoteJsep({jsep: jsep, error: function() {
								// Simulate an hangup from this helper's button
								doHangup({ currentTarget: { id: "call" + helperId } });
							}});
						}
						toastr.info("Early media...");
					} else if(event === 'accepted') {
						Janus.log("[Helper #" + helperId + "] " + result["username"] + " accepted the call!");
						Janus.log(jsep);
						// Call can start, now: handle the remote answer
						if(jsep !== null && jsep !== undefined) {
							helpers[helperId].sipcall.handleRemoteJsep({jsep: jsep, error: function() {
								// Simulate an hangup from this helper's button
								doHangup({ currentTarget: { id: "call" + helperId } });
							}});
						}
						toastr.success("Call accepted!");
					} else if(event === 'updatingcall') {
						// We got a re-INVITE: while we may prompt the user (e.g.,
						// to notify about media changes), to keep things simple
						// we just accept the update and send an answer right away
						Janus.log("[Helper #" + helperId + "] Got re-INVITE");
						var doAudio = (jsep.sdp.indexOf("m=audio ") > -1),
							doVideo = (jsep.sdp.indexOf("m=video ") > -1);
						helpers[helperId].sipcall.createAnswer(
							{
								jsep: jsep,
								media: { audio: doAudio, video: doVideo },
								success: function(jsep) {
									Janus.debug("[Helper #" + helperId + "] Got SDP " + jsep.type + "! audio=" + doAudio + ", video=" + doVideo);
									Janus.debug(jsep);
									var body = { request: "update" };
									helpers[helperId].sipcall.send({"message": body, "jsep": jsep});
								},
								error: function(error) {
									Janus.error("[Helper #" + helperId + "] WebRTC error:", error);
									bootbox.alert("WebRTC error... " + JSON.stringify(error));
								}
							});
					} else if(event === 'transfer') {
						// We're being asked to transfer the call, ask the user what to do
						var referTo = result["refer_to"];
						var referredBy = result["referred_by"] ? result["referred_by"] : "an unknown party";
						var referId = result["refer_id"];
						var replaces = result["replaces"];
						var extra = ("referred by " + referredBy);
						if(replaces)
							extra += (", replaces call-ID " + replaces);
						bootbox.confirm("Transfer the call to " + referTo + "? (" + extra + ", helper " + helperId + ")",
							function(result) {
								if(result) {
									// Call the person we're being transferred to
									if(!helpers[helperId].sipcall.webrtcStuff.pc) {
										// Do it here
										actuallyDoCall(helpers[helperId].sipcall, referTo, false, referId);
									} else if(!sipcall.webrtcStuff.pc) {
										// Do it on the main handle
										actuallyDoCall(sipcall, referTo, false, referId);
									} else {
										// We're in a call already, use the main handle or a helper
										var h = -1;
										if(Object.keys(helpers).length > 0) {
											// See if any of the helpers if available
											for(var i in helpers) {
												if(!helpers[i].sipcall.webrtcStuff.pc) {
													h = parseInt(i);
													break;
												}
											}
										}
										if(h !== -1) {
											// Do in this helper
											actuallyDoCall(helpers[h].sipcall, referTo, false, referId);
										} else {
											// Create a new helper
											addHelper(function(id) {
												// Do it here
												actuallyDoCall(helpers[id].sipcall, referTo, false, referId);
											});
										}
									}
								} else {
									// We're rejecting the transfer
									var body = { request: "decline", refer_id: referId };
									sipcall.send({"message": body});
								}
							});
					} else if(event === 'hangup') {
						if(incoming != null) {
							incoming.modal('hide');
							incoming = null;
						}
						Janus.log("[Helper #" + helperId + "] Call hung up (" + result["code"] + " " + result["reason"] + ")!");
						bootbox.alert(result["code"] + " " + result["reason"]);
						// Reset status
						helpers[helperId].sipcall.hangup();
						$('#dovideo' + helperId).removeAttr('disabled').val('');
						$('#peer' + helperId).removeAttr('disabled').val('');
						$('#call' + helperId).removeAttr('disabled').html('Call')
							.removeClass("btn-danger").addClass("btn-success")
							.unbind('click').click(doCall);
					}
				}
			},
			onlocalstream: function(stream) {
				Janus.debug("[Helper #" + helperId + "]  ::: Got a local stream :::");
				Janus.debug(stream);
				$('#videos' + helperId).removeClass('hide').show();
				if($('#myvideo' + helperId).length === 0)
					$('#videoleft' + helperId).append('<video class="rounded centered" id="myvideo' + helperId + '" width=320 height=240 autoplay playsinline muted="muted"/>');
				Janus.attachMediaStream($('#myvideo' + helperId).get(0), stream);
				$("#myvideo" + helperId).get(0).muted = "muted";
				if(helpers[helperId].sipcall.webrtcStuff.pc.iceConnectionState !== "completed" &&
						helpers[helperId].sipcall.webrtcStuff.pc.iceConnectionState !== "connected") {
					$("#videoleft" + helperId).parent().block({
						message: '<b>Calling...</b>',
						css: {
							border: 'none',
							backgroundColor: 'transparent',
							color: 'white'
						}
					});
					// No remote video yet
					$('#videoright' + helperId).append('<video class="rounded centered" id="waitingvideo' + helperId + '" width=320 height=240 />');
					if(helpers[helperId].spinner == null) {
						var target = document.getElementById('videoright' + helperId);
						helpers[helperId].spinner = new Spinner({top:100}).spin(target);
					} else {
						helpers[helperId].spinner.spin();
					}
				}
				var videoTracks = stream.getVideoTracks();
				if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
					// No webcam
					$('#myvideo' + helperId).hide();
					if($('#videoleft' + helperId + ' .no-video-container').length === 0) {
						$('#videoleft' + helperId).append(
							'<div class="no-video-container">' +
								'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
								'<span class="no-video-text">No webcam available</span>' +
							'</div>');
					}
				} else {
					$('#videoleft' + helperId + ' .no-video-container').remove();
					$('#myvideo' + helperId).removeClass('hide').show();
				}
			},
			onremotestream: function(stream) {
				Janus.debug("[Helper #" + helperId + "]  ::: Got a remote stream :::");
				Janus.debug(stream);
				if($('#remotevideo' + helperId).length === 0) {
					$('#videoright' + helperId).parent().find('h3').html(
						'Send DTMF: <span id="dtmf' + helperId + '" class="btn-group btn-group-xs"></span>');
					$('#videoright' + helperId).append(
						'<video class="rounded centered hide" id="remotevideo' + helperId + '" width=320 height=240 autoplay playsinline/>');
					for(var i=0; i<12; i++) {
						if(i<10)
							$('#dtmf' + helperId).append('<button class="btn btn-info dtmf">' + i + '</button>');
						else if(i == 10)
							$('#dtmf' + helperId).append('<button class="btn btn-info dtmf">#</button>');
						else if(i == 11)
							$('#dtmf' + helperId).append('<button class="btn btn-info dtmf">*</button>');
					}
					$('.dtmf' + helperId).click(function() {
						// Send DTMF tone (inband)
						helpers[helperId].sipcall.dtmf({dtmf: { tones: $(this).text()}});
						// Notice you can also send DTMF tones using SIP INFO
						// 		helpers[helperId].sipcall.send({message: {request: "dtmf_info", digit: $(this).text()}});
					});
					// Show the peer and hide the spinner when we get a playing event
					$("#remotevideo" + helperId).bind("playing", function () {
						$('#waitingvideo' + helperId).remove();
						if(this.videoWidth)
							$('#remotevideo' + helperId).removeClass('hide').show();
						if(helpers[helperId].spinner !== null && helpers[helperId].spinner !== undefined)
							helpers[helperId].spinner.stop();
						helpers[helperId].spinner = null;
					});
				}
				Janus.attachMediaStream($('#remotevideo' + helperId).get(0), stream);
				var videoTracks = stream.getVideoTracks();
				if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
					// No remote video
					$('#remotevideo' + helperId).hide();
					if($('#videoright' + helperId + ' .no-video-container').length === 0) {
						$('#videoright' + helperId).append(
							'<div class="no-video-container">' +
								'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
								'<span class="no-video-text">No remote video available</span>' +
							'</div>');
					}
				} else {
					$('#videoright' + helperId + ' .no-video-container').remove();
					$('#remotevideo' + helperId).removeClass('hide').show();
				}
			},
			oncleanup: function() {
				Janus.log("[Helper #" + helperId + "]  ::: Got a cleanup notification :::");
				$('#myvideo' + helperId).remove();
				$('#waitingvideo' + helperId).remove();
				$('#remotevideo' + helperId).remove();
				$('#videos' + helperId + ' .no-video-container').remove();
				$('#videos' + helperId).hide();
				$('#dtmf' + helperId).parent().html("Remote UA");
			}
		});

}
