// We import the settings.js file to know which address we should contact
// to talk to Janus, and optionally which STUN/TURN servers should be
// used as well. Specifically, that file defines the "server" and
// "iceServers" properties we'll pass when creating the Janus session.

var janus = null;
var sipcall = null;
var opaqueId = "siptest-"+Janus.randomString(12);

var localTracks = {}, localVideos = 0,
	remoteTracks = {}, remoteVideos = 0;
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
					iceServers: iceServers,
					// Should the Janus API require authentication, you can specify either the API secret or user token here too
					//		token: "mytoken",
					//	or
					//		apisecret: "serversecret",
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
								iceState: function(state) {
									Janus.log("ICE state changed to " + state);
								},
								mediaState: function(medium, on, mid) {
									Janus.log("Janus " + (on ? "started" : "stopped") + " receiving our " + medium + " (mid=" + mid + ")");
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
								},
								slowLink: function(uplink, lost, mid) {
									Janus.warn("Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on mid " + mid + " (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::", msg);
									// Any error?
									var error = msg["error"];
									if(error) {
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
									var callId = msg["call_id"];
									var result = msg["result"];
									if(result && result["event"]) {
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
												$('#server').parent().addClass('hide').hide();
												$('#authuser').parent().addClass('hide').hide();
												$('#displayname').parent().addClass('hide').hide();
												$('#password').parent().addClass('hide').hide();
												$('#register').parent().addClass('hide').hide();
												$('#registerset').parent().addClass('hide').hide();
												$('#username').parent().parent().append(
													'<button id="addhelper" class="btn btn-xs btn-info pull-right" title="Add a new line">' +
														'<i class="fa fa-plus"></i>' +
													'</button>'
												);
												$('#addhelper').click(addHelper);
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
											sipcall.callId = callId;
											var doAudio = true, doVideo = true;
											var offerlessInvite = false;
											if(jsep) {
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
											if(referredBy) {
												transfer = " (referred by " + referredBy + ")";
												transfer = transfer.replace(new RegExp('<', 'g'), '&lt');
												transfer = transfer.replace(new RegExp('>', 'g'), '&gt');
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
															// We want bidirectional audio and/or video
															let tracks = [];
															if(doAudio)
																tracks.push({ type: 'audio', capture: true, recv: true });
															if(doVideo)
																tracks.push({ type: 'video', capture: true, recv: true });
															sipcallAction(
																{
																	jsep: jsep,
																	tracks: tracks,
																	success: function(jsep) {
																		Janus.debug("Got SDP " + jsep.type + "! audio=" + doAudio + ", video=" + doVideo + ":", jsep);
																		sipcall.doAudio = doAudio;
																		sipcall.doVideo = doVideo;
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
																		// may not be able to handle them. Since we want to receive
																		// re-INVITES to handle them ourselves, we specify it here:
																		body["autoaccept_reinvites"] = false;
																		sipcall.send({ message: body, jsep: jsep });
																		$('#call').removeAttr('disabled').html('Hangup')
																			.removeClass("btn-success").addClass("btn-danger")
																			.unbind('click').click(doHangup);
																	},
																	error: function(error) {
																		Janus.error("WebRTC error:", error);
																		bootbox.alert("WebRTC error... " + error.message);
																		// Don't keep the caller waiting any longer, but use a 480 instead of the default 486 to clarify the cause
																		var body = { request: "decline", code: 480 };
																		sipcall.send({ message: body });
																	}
																});
														}
													},
													danger: {
														label: "Decline",
														className: "btn-danger",
														callback: function() {
															incoming = null;
															var body = { request: "decline" };
															sipcall.send({ message: body });
														}
													}
												}
											});
										} else if(event === 'accepting') {
											// Response to an offerless INVITE, let's wait for an 'accepted'
										} else if(event === 'progress') {
											Janus.log("There's early media from " + result["username"] + ", wairing for the call!", jsep);
											// Call can start already: handle the remote answer
											if(jsep) {
												sipcall.handleRemoteJsep({ jsep: jsep, error: doHangup });
											}
											toastr.info("Early media...");
										} else if(event === 'accepted') {
											Janus.log(result["username"] + " accepted the call!", jsep);
											// Call can start, now: handle the remote answer
											if(jsep) {
												sipcall.handleRemoteJsep({ jsep: jsep, error: doHangup });
											}
											toastr.success("Call accepted!");
											sipcall.callId = callId;
										} else if(event === 'updatingcall') {
											// We got a re-INVITE: while we may prompt the user (e.g.,
											// to notify about media changes), to keep things simple
											// we just accept the update and send an answer right away
											Janus.log("Got re-INVITE");
											var doAudio = (jsep.sdp.indexOf("m=audio ") > -1),
												doVideo = (jsep.sdp.indexOf("m=video ") > -1);
											// We want bidirectional audio and/or video, but only
											// populate tracks if we weren't sending something before
											let tracks = [];
											if(doAudio && !sipcall.doAudio) {
												sipcall.doAudio = true;
												tracks.push({ type: 'audio', capture: true, recv: true });
											}
											if(doVideo && !sipcall.doVideo) {
												sipcall.doVideo = true;
												tracks.push({ type: 'video', capture: true, recv: true });
											}
											sipcall.createAnswer(
												{
													jsep: jsep,
													tracks: tracks,
													success: function(jsep) {
														Janus.debug("Got SDP " + jsep.type + "! audio=" + doAudio + ", video=" + doVideo + ":", jsep);
														var body = { request: "update" };
														sipcall.send({ message: body, jsep: jsep });
													},
													error: function(error) {
														Janus.error("WebRTC error:", error);
														bootbox.alert("WebRTC error... " + error.message);
													}
												});
										} else if(event === 'message') {
											// We got a MESSAGE
											var sender = result["displayname"] ? result["displayname"] : result["sender"];
											var content = result["content"];
											content = content.replace(new RegExp('<', 'g'), '&lt');
											content = content.replace(new RegExp('>', 'g'), '&gt');
											toastr.success(content, "Message from " + sender);
										} else if(event === 'info') {
											// We got an INFO
											var sender = result["displayname"] ? result["displayname"] : result["sender"];
											var content = result["content"];
											content = content.replace(new RegExp('<', 'g'), '&lt');
											content = content.replace(new RegExp('>', 'g'), '&gt');
											toastr.info(content, "Info from " + sender);
										} else if(event === 'notify') {
											// We got a NOTIFY
											var notify = result["notify"];
											var content = result["content"];
											toastr.info(content, "Notify (" + notify + ")");
										} else if(event === 'transfer') {
											// We're being asked to transfer the call, ask the user what to do
											var referTo = result["refer_to"];
											var referredBy = result["referred_by"] ? result["referred_by"] : "an unknown party";
											var referId = result["refer_id"];
											var replaces = result["replaces"];
											var extra = ("referred by " + referredBy);
											if(replaces)
												extra += (", replaces call-ID " + replaces);
											extra = extra.replace(new RegExp('<', 'g'), '&lt');
											extra = extra.replace(new RegExp('>', 'g'), '&gt');
											bootbox.confirm("Transfer the call to " + referTo + "? (" + extra + ")",
												function(result) {
													if(result) {
														// Call the person we're being transferred to
														if(!sipcall.webrtcStuff.pc) {
															// Do it here
															$('#peer').val(referTo).attr('disabled', true);
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
																$('#peer' + h).val(referTo).attr('disabled', true);
																actuallyDoCall(helpers[h].sipcall, referTo, false, referId);
															} else {
																// Create a new helper
																addHelper(function(id) {
																	// Do it here
																	$('#peer' + id).val(referTo).attr('disabled', true);
																	actuallyDoCall(helpers[id].sipcall, referTo, false, referId);
																});
															}
														}
													} else {
														// We're rejecting the transfer
														var body = { request: "decline", refer_id: referId };
														sipcall.send({ message: body });
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
										} else if(event === 'messagedelivery') {
											// message delivery status
											let reason = result["reason"];
											let code = result["code"];
											let callid = msg['call_id'];
											if (code == 200) {
												toastr.success(`${callid} Delivery Status: ${code} ${reason}`);
											} else {
												toastr.error(`${callid} Delivery Status: ${code} ${reason}`);
											}
										}
									}
								},
								onlocaltrack: function(track, on) {
									Janus.debug("Local track " + (on ? "added" : "removed") + ":", track);
									// We use the track ID as name of the element, but it may contain invalid characters
									var trackId = track.id.replace(/[{}]/g, "");
									if(!on) {
										// Track removed, get rid of the stream and the rendering
										var stream = localTracks[trackId];
										if(stream) {
											try {
												var tracks = stream.getTracks();
												for(var i in tracks) {
													var mst = tracks[i];
													if(mst)
														mst.stop();
												}
											} catch(e) {}
										}
										if(track.kind === "video") {
											$('#myvideot' + trackId).remove();
											localVideos--;
											if(localVideos === 0) {
												// No video, at least for now: show a placeholder
												if($('#videoleft .no-video-container').length === 0) {
													$('#videoleft').append(
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
									var stream = localTracks[trackId];
									if(stream) {
										// We've been here already
										return;
									}
									if($('#videoleft video').length === 0) {
										$('#videos').removeClass('hide').show();
									}
									if(track.kind === "audio") {
										// We ignore local audio tracks, they'd generate echo anyway
										if(localVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videoleft .no-video-container').length === 0) {
												$('#videoleft').append(
													'<div class="no-video-container">' +
														'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
														'<span class="no-video-text">No webcam available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										localVideos++;
										$('#videoleft .no-video-container').remove();
										stream = new MediaStream([track]);
										localTracks[trackId] = stream;
										Janus.log("Created local stream:", stream);
										$('#videoleft').append('<video class="rounded centered" id="myvideot' + trackId + '" width="100%" height="100%" autoplay playsinline muted="muted"/>');
										Janus.attachMediaStream($('#myvideot' + trackId).get(0), stream);
									}
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
									}
								},
								onremotetrack: function(track, mid, on) {
									Janus.debug("Remote track (mid=" + mid + ") " + (on ? "added" : "removed") + ":", track);
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
											} catch(e) {}
										}
										$('#peervideom' + mid).remove();
										if(track.kind === "video") {
											remoteVideos--;
											if(remoteVideos === 0) {
												// No video, at least for now: show a placeholder
												if($('#videoright .no-video-container').length === 0) {
													$('#videoright').append(
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
									// If we're here, a new track was added
									if($('#videoright audio').length === 0 && $('#videoright video').length === 0) {
										$('#videos').removeClass('hide').show();
										$('#videoright').parent().find('h3').html(
											'Send DTMF: <span id="dtmf" class="btn-group btn-group-xs"></span>');
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
										$('#msg').click(function() {
											bootbox.prompt("Insert message to send", function(result) {
												if(result && result !== '') {
													// Send the message
													var msg = { request: "message", content: result };
													sipcall.send({ message: msg });
												}
											});
										});
										$('#info').click(function() {
											bootbox.dialog({
												message: 'Type: <input class="form-control" type="text" id="type" placeholder="e.g., application/xml">' +
													'<br/>Content: <input class="form-control" type="text" id="content" placeholder="e.g., <message>hi</message>">',
												title: "Insert the type and content to send",
												buttons: {
													cancel: {
														label: "Cancel",
														className: "btn-default",
														callback: function() {
															// Do nothing
														}
													},
													ok: {
														label: "OK",
														className: "btn-primary",
														callback: function() {
															// Send the INFO
															var type = $('#type').val();
															var content = $('#content').val();
															if(type === '' || content === '')
																return;
															var msg = { request: "info", type: type, content: content };
															sipcall.send({ message: msg });
														}
													}
												}
											});
										});
										$('#transfer').click(function() {
											bootbox.dialog({
												message: '<input class="form-control" type="text" id="transferto" placeholder="e.g., sip:goofy@example.com">',
												title: "Insert the address to transfer the call to",
												buttons: {
													cancel: {
														label: "Cancel",
														className: "btn-default",
														callback: function() {
															// Do nothing
														}
													},
													blind: {
														label: "Blind transfer",
														className: "btn-info",
														callback: function() {
															// Start a blind transfer
															var address = $('#transferto').val();
															if(address === '')
																return;
															var msg = { request: "transfer", uri: address };
															sipcall.send({ message: msg });
														}
													},
													attended: {
														label: "Attended transfer",
														className: "btn-primary",
														callback: function() {
															// Start an attended transfer
															var address = $('#transferto').val();
															if(address === '')
																return;
															// Add the call-id to replace to the transfer
															var msg = { request: "transfer", uri: address, replace: sipcall.callId };
															sipcall.send({ message: msg });
														}
													}
												}
											});
										});
									}
									if(track.kind === "audio") {
										// New audio track: create a stream out of it, and use a hidden <audio> element
										stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote audio stream:", stream);
										$('#videoright').append('<audio class="hide" id="peervideom' + mid + '" autoplay playsinline/>');
										Janus.attachMediaStream($('#peervideom' + mid).get(0), stream);
										if(remoteVideos === 0) {
											// No video, at least for now: show a placeholder
											if($('#videoright .no-video-container').length === 0) {
												$('#videoright').append(
													'<div class="no-video-container">' +
														'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
														'<span class="no-video-text">No remote video available</span>' +
													'</div>');
											}
										}
									} else {
										// New video track: create a stream out of it
										remoteVideos++;
										$('#videoright .no-video-container').remove();
										stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote video stream:", stream);
										$('#videoright').append('<video class="rounded centered" id="peervideom' + mid + '" width="100%" height="100%" autoplay playsinline/>');
										Janus.attachMediaStream($('#peervideom' + mid).get(0), stream);
									}
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									$("#videoleft").empty().parent().unblock();
									$('#videoright').empty();
									$('#videos').hide();
									$('#dtmf').parent().html("Remote UA");
									if(sipcall) {
										delete sipcall.callId;
										delete sipcall.doAudio;
										delete sipcall.doVideo;
									}
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
	if(!selectedApproach) {
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
			request: "register",
			type: "guest"
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
						sipcall.send({ message: register });
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
			sipcall.send({ message: register });
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
		request: "register",
		username: username
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
	// Should you want the SIP stack to add some custom headers to the
	// REGISTER, you can do so by adding an additional "headers" object,
	// containing each of the headers as key-value, e.g.:
	//		register["headers"] = {
	//			"My-Header": "value",
	//			"AnotherHeader": "another string"
	//		};
	// Similarly, a "contact_params" object will allow you to
	// inject custom Contact URI params, e.g.:
	//		register["contact_params"] = {
	//			"pn-provider": "acme",
	//			"pn-param": "acme-param",
	//			"pn-prid": "ZTY4ZDJlMzODE1NmUgKi0K"
	//		};
	if(sipserver === "") {
		bootbox.confirm("You didn't specify a SIP Registrar: this will cause the plugin to try and conduct a standard (<a href='https://tools.ietf.org/html/rfc3263' target='_blank'>RFC3263</a>) lookup. If this is not what you want or you don't know what this means, hit Cancel and provide a SIP Registrar instead'",
			function(result) {
				if(result) {
					sipcall.send({ message: register });
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
		sipcall.send({ message: register });
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
		$('#call' + suffix).removeAttr('disabled').click(function(ev) { doCall(ev); });
		return;
	}
	if(username.indexOf("sip:") != 0 || username.indexOf("@") < 0) {
		bootbox.alert('Please insert a valid SIP address (e.g., sip:pluto@example.com)');
		$('#peer' + suffix).removeAttr('disabled').val("");
		$('#dovideo' + suffix).removeAttr('disabled').val("");
		$('#call' + suffix).removeAttr('disabled').click(function(ev) { doCall(ev); });
		return;
	}
	// Call this URI
	doVideo = $('#dovideo' + suffix).is(':checked');
	Janus.log(prefix + "This is a SIP " + (doVideo ? "video" : "audio") + " call (dovideo=" + doVideo + ")");
	actuallyDoCall(handle, $('#peer' + suffix).val(), doVideo);
}
function actuallyDoCall(handle, uri, doVideo, referId) {
	// We want bidirectional audio for sure, and maybe video
	handle.doAudio = true;
	handle.doVideo = doVideo;
	let tracks = [{ type: 'audio', capture: true, recv: true }];
	if(doVideo)
		tracks.push({ type: 'video', capture: true, recv: true });
	handle.createOffer(
		{
			tracks: tracks,
			success: function(jsep) {
				Janus.debug("Got SDP!", jsep);
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
				// may not be able to handle them. Since we want to receive
				// re-INVITES to handle them ourselves, we specify it here:
				body["autoaccept_reinvites"] = false;
				if(referId) {
					// In case we're originating this call because of a call
					// transfer, we need to provide the internal reference ID
					body["refer_id"] = referId;
				}
				handle.send({ message: body, jsep: jsep });
			},
			error: function(error) {
				Janus.error(prefix + "WebRTC error...", error);
				bootbox.alert("WebRTC error... " + error.message);
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
		var hangup = { request: "hangup" };
		sipcall.send({ message: hangup });
		sipcall.hangup();
	} else {
		$('#call' + helperId).attr('disabled', true).unbind('click');
		var hangup = { request: "hangup" };
		helpers[helperId].sipcall.send({ message: hangup });
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
	helperCreated = (typeof helperCreated == "function") ? helperCreated : Janus.noop;
	helpersCount++;
	var helperId = helpersCount;
	helpers[helperId] = { id: helperId,
		localTracks: {}, localVideos: 0,
		remoteTracks: {}, remoteVideos: 0 };
	// Add another row with a new "phone"
	$('.footer').before(
		'<div class="container" id="sipcall' + helperId + '">' +
		'	<div class="row">' +
		'		<div class="col-md-12">' +
		'			<div class="col-md-6 container">' +
		'				<span class="label label-info">Helper #' + helperId +
		'					<i class="fa fa-window-close" id="rmhelper' + helperId + '" style="cursor: pointer;" title="Remove this helper"></i>' +
		'				</span>' +
		'			</div>' +
		'			<div class="col-md-6 container" id="phone' + helperId + '">' +
		'				<div class="input-group margin-bottom-sm">' +
		'					<span class="input-group-addon"><i class="fa fa-phone fa-fw"></i></span>' +
		'					<input disabled class="form-control" type="text" placeholder="SIP URI to call (e.g., sip:1000@example.com)" autocomplete="off" id="peer' + helperId + '" onkeypress="return checkEnter(this, event, ' + helperId + ');"></input>' +
		'				</div>' +
		'				<button disabled class="btn btn-success margin-bottom-sm" autocomplete="off" id="call' + helperId + '">Call</button> <input autocomplete="off" id="dovideo' + helperId + '" type="checkbox">Use Video</input>' +
		'			</div>' +
		'		</div>' +
		'	</div>' +
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
	$('#rmhelper' + helperId).click(function() {
		var hid = $(this).attr('id').split("rmhelper")[1];
		console.log(hid);
		removeHelper(hid);
	});
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
				removeHelper(helperId);
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
			iceState: function(state) {
				Janus.log("[Helper #" + helperId + "] ICE state changed to " + state);
			},
			mediaState: function(medium, on, mid) {
				Janus.log("[Helper #" + helperId + "] Janus " + (on ? "started" : "stopped") + " receiving our " + medium + " (mid=" + mid + ")");
			},
			webrtcState: function(on) {
				Janus.log("[Helper #" + helperId + "] Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
				$("#videoleft" + helperId).parent().unblock();
			},
			slowLink: function(uplink, lost, mid) {
				Janus.warn("Janus reports problems " + (uplink ? "sending" : "receiving") +
					" packets on mid " + mid + " (" + lost + " lost packets)");
			},
			onmessage: function(msg, jsep) {
				Janus.debug("[Helper #" + helperId + "]  ::: Got a message :::", msg);
				// Any error?
				var error = msg["error"];
				if(error) {
					bootbox.alert(error);
					return;
				}
				var callId = msg["call_id"];
				var result = msg["result"];
				if(result && result["event"]) {
					var event = result["event"];
					if(event === 'registration_failed') {
						Janus.warn("[Helper #" + helperId + "] Registration failed: " + result["code"] + " " + result["reason"]);
						bootbox.alert(result["code"] + " " + result["reason"]);
						// Get rid of the helper
						removeHelper(helperId);
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
						helpers[helperId].sipcall.callId = callId;
						var doAudio = true, doVideo = true;
						var offerlessInvite = false;
						if(jsep) {
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
						transfer = transfer.replace(new RegExp('<', 'g'), '&lt');
						transfer = transfer.replace(new RegExp('>', 'g'), '&gt');
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
										// We want bidirectional audio and/or video
										let tracks = [];
										if(doAudio)
											tracks.push({ type: 'audio', capture: true, recv: true });
										if(doVideo)
											tracks.push({ type: 'video', capture: true, recv: true });
										sipcallAction(
											{
												jsep: jsep,
												tracks: tracks,
												success: function(jsep) {
													Janus.debug("[Helper #" + helperId + "] Got SDP " + jsep.type + "! audio=" + doAudio + ", video=" + doVideo + ":", jsep);
													helpers[helperId].sipcall.doAudio = doAudio;
													helpers[helperId].sipcall.doVideo = doVideo;
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
													// may not be able to handle them. Since we want to receive
													// re-INVITES to handle them ourselves, we specify it here:
													body["autoaccept_reinvites"] = false;
													helpers[helperId].sipcall.send({ message: body, jsep: jsep });
													$('#call' + helperId).removeAttr('disabled').html('Hangup')
														.removeClass("btn-success").addClass("btn-danger")
														.unbind('click').click(doHangup);
												},
												error: function(error) {
													Janus.error("[Helper #" + helperId + "] WebRTC error:", error);
													bootbox.alert("WebRTC error... " + error.message);
													// Don't keep the caller waiting any longer, but use a 480 instead of the default 486 to clarify the cause
													var body = { request: "decline", code: 480 };
													helpers[helperId].sipcall.send({ message: body });
												}
											});
									}
								},
								danger: {
									label: "Decline",
									className: "btn-danger",
									callback: function() {
										incoming = null;
										var body = { request: "decline" };
										helpers[helperId].sipcall.send({ message: body });
									}
								}
							}
						});
					} else if(event === 'accepting') {
						// Response to an offerless INVITE, let's wait for an 'accepted'
					} else if(event === 'progress') {
						Janus.log("[Helper #" + helperId + "] There's early media from " + result["username"] + ", wairing for the call!", jsep);
						// Call can start already: handle the remote answer
						if(jsep) {
							helpers[helperId].sipcall.handleRemoteJsep({ jsep: jsep, error: function() {
								// Simulate an hangup from this helper's button
								doHangup({ currentTarget: { id: "call" + helperId } });
							}});
						}
						toastr.info("Early media...");
					} else if(event === 'accepted') {
						Janus.log("[Helper #" + helperId + "] " + result["username"] + " accepted the call!", jsep);
						// Call can start, now: handle the remote answer
						if(jsep) {
							helpers[helperId].sipcall.handleRemoteJsep({ jsep: jsep, error: function() {
								// Simulate an hangup from this helper's button
								doHangup({ currentTarget: { id: "call" + helperId } });
							}});
						}
						helpers[helperId].sipcall.callId = callId;
						toastr.success("Call accepted!");
					} else if(event === 'updatingcall') {
						// We got a re-INVITE: while we may prompt the user (e.g.,
						// to notify about media changes), to keep things simple
						// we just accept the update and send an answer right away
						Janus.log("[Helper #" + helperId + "] Got re-INVITE");
						var doAudio = (jsep.sdp.indexOf("m=audio ") > -1),
							doVideo = (jsep.sdp.indexOf("m=video ") > -1);
						// We want bidirectional audio and/or video, but only
						// populate tracks if we weren't sending something before
						let tracks = [];
						if(doAudio && !sipcall.doAudio) {
							helpers[helperId].sipcall.doAudio = true;
							tracks.push({ type: 'audio', capture: true, recv: true });
						}
						if(doVideo && !sipcall.doVideo) {
							helpers[helperId].sipcall.doVideo = true;
							tracks.push({ type: 'video', capture: true, recv: true });
						}
						helpers[helperId].sipcall.createAnswer(
							{
								jsep: jsep,
								tracks: tracks,
								success: function(jsep) {
									Janus.debug("[Helper #" + helperId + "] Got SDP " + jsep.type + "! audio=" + doAudio + ", video=" + doVideo + ":", jsep);
									var body = { request: "update" };
									helpers[helperId].sipcall.send({ message: body, jsep: jsep });
								},
								error: function(error) {
									Janus.error("[Helper #" + helperId + "] WebRTC error:", error);
									bootbox.alert("WebRTC error... " + error.message);
								}
							});
					} else if(event === 'message') {
						// We got a MESSAGE
						var sender = result["displayname"] ? result["displayname"] : result["sender"];
						var content = result["content"];
						content = content.replace(new RegExp('<', 'g'), '&lt');
						content = content.replace(new RegExp('>', 'g'), '&gt');
						toastr.success(content, "Message from " + sender);
					} else if(event === 'info') {
						// We got an INFO
						var sender = result["displayname"] ? result["displayname"] : result["sender"];
						var content = result["content"];
						content = content.replace(new RegExp('<', 'g'), '&lt');
						content = content.replace(new RegExp('>', 'g'), '&gt');
						toastr.info(content, "Info from " + sender);
					} else if(event === 'notify') {
						// We got a NOTIFY
						var notify = result["notify"];
						var content = result["content"];
						toastr.info(content, "Notify (" + notify + ")");
					} else if(event === 'transfer') {
						// We're being asked to transfer the call, ask the user what to do
						var referTo = result["refer_to"];
						var referredBy = result["referred_by"] ? result["referred_by"] : "an unknown party";
						var referId = result["refer_id"];
						var replaces = result["replaces"];
						var extra = ("referred by " + referredBy);
						if(replaces)
							extra += (", replaces call-ID " + replaces);
						extra = extra.replace(new RegExp('<', 'g'), '&lt');
						extra = extra.replace(new RegExp('>', 'g'), '&gt');
						bootbox.confirm("Transfer the call to " + referTo + "? (" + extra + ", helper " + helperId + ")",
							function(result) {
								if(result) {
									// Call the person we're being transferred to
									if(!helpers[helperId].sipcall.webrtcStuff.pc) {
										// Do it here
										$('#peer' + helperId).val(referTo).attr('disabled', true);
										actuallyDoCall(helpers[helperId].sipcall, referTo, false, referId);
									} else if(!sipcall.webrtcStuff.pc) {
										// Do it on the main handle
										$('#peer').val(referTo).attr('disabled', true);
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
											$('#peer' + h).val(referTo).attr('disabled', true);
											actuallyDoCall(helpers[h].sipcall, referTo, false, referId);
										} else {
											// Create a new helper
											addHelper(function(id) {
												// Do it here
												$('#peer' + id).val(referTo).attr('disabled', true);
												actuallyDoCall(helpers[id].sipcall, referTo, false, referId);
											});
										}
									}
								} else {
									// We're rejecting the transfer
									var body = { request: "decline", refer_id: referId };
									sipcall.send({ message: body });
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
					} else if(event === 'messagedelivery') {
						// message delivery status
						let reason = result["reason"];
						let code = result["code"];
						let callid = msg['call_id'];
						if (code == 200) {
							toastr.success(`${callid}/${helperId} Delivery Status: ${code} ${reason}`);
						} else {
							toastr.error(`${callid}/${helperId} Delivery Status: ${code} ${reason}`);
						}
					}
				}
			},
			onlocaltrack: function(track, on) {
				Janus.debug("[Helper #" + helperId + "] Local track " + (on ? "added" : "removed") + ":", track);
				// We use the track ID as name of the element, but it may contain invalid characters
				var trackId = track.id.replace(/[{}]/g, "");
				if(!on) {
					// Track removed, get rid of the stream and the rendering
					var stream = helpers[helperId].localTracks[trackId];
					if(stream) {
						try {
							var tracks = stream.getTracks();
							for(var i in tracks) {
								var mst = tracks[i];
								if(mst)
									mst.stop();
							}
						} catch(e) {}
					}
					if(track.kind === "video") {
						$('#myvideo' + helperId + 't' + trackId).remove();
						helpers[helperId].localVideos--;
						if(helpers[helperId].localVideos === 0) {
							// No video, at least for now: show a placeholder
							if($('#videoleft' + helperId + ' .no-video-container').length === 0) {
								$('#videoleft' + helperId).append(
									'<div class="no-video-container">' +
										'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
										'<span class="no-video-text">No webcam available</span>' +
									'</div>');
							}
						}
					}
					delete helpers[helperId].localTracks[trackId];
					return;
				}
				// If we're here, a new track was added
				var stream = helpers[helperId].localTracks[trackId];
				if(stream) {
					// We've been here already
					return;
				}
				if($('#videoleft' + helperId + ' video').length === 0) {
					$('#videos' + helperId).removeClass('hide').show();
				}
				if(track.kind === "audio") {
					// We ignore local audio tracks, they'd generate echo anyway
					if(helpers[helperId].localVideos === 0) {
						// No video, at least for now: show a placeholder
						if($('#videoleft' + helperId + ' .no-video-container').length === 0) {
							$('#videoleft' + helperId).append(
								'<div class="no-video-container">' +
									'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
									'<span class="no-video-text">No webcam available</span>' +
								'</div>');
						}
					}
				} else {
					// New video track: create a stream out of it
					helpers[helperId].localVideos++;
					$('#videoleft' + helperId + ' .no-video-container').remove();
					stream = new MediaStream([track]);
					helpers[helperId].localTracks[trackId] = stream;
					Janus.log("[Helper #" + helperId + "] Created local stream:", stream);
					$('#videoleft' + helperId).append('<video class="rounded centered" id="myvideo' + helperId + 't' + trackId + '" width="100%" height="100%" autoplay playsinline muted="muted"/>');
					Janus.attachMediaStream($('#myvideo' + helperId + 't' + trackId).get(0), stream);
				}
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
				}
			},
			onremotetrack: function(track, mid, on) {
				Janus.debug("[Helper #" + helperId + "] Remote track (mid=" + mid + ") " + (on ? "added" : "removed") + ":", track);
				if(!on) {
					// Track removed, get rid of the stream and the rendering
					var stream = helpers[helperId].remoteTracks[mid];
					if(stream) {
						try {
							var tracks = stream.getTracks();
							for(var i in tracks) {
								var mst = tracks[i];
								if(mst)
									mst.stop();
							}
						} catch(e) {}
					}
					$('#peervideo' + helperId + 'm' + mid).remove();
					if(track.kind === "video") {
						remoteVideos--;
						if(remoteVideos === 0) {
							// No video, at least for now: show a placeholder
							if($('#videoright' + helperId + ' .no-video-container').length === 0) {
								$('#videoright').append(
									'<div class="no-video-container">' +
										'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
										'<span class="no-video-text">No remote video available</span>' +
									'</div>');
							}
						}
					}
					delete helpers[helperId].remoteTracks[mid];
					return;
				}
				// If we're here, a new track was added
				if($('#videoright' + helperId + ' audio').length === 0 && $('#videoright' + helperId + ' video').length === 0) {
					$('#videos' + helperId).removeClass('hide').show();
					$('#videoright' + helperId).parent().find('h3').html(
						'Send DTMF: <span id="dtmf' + helperId + '" class="btn-group btn-group-xs"></span>');
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
						// 		helpers[helperId].sipcall.send({ message: { request: "dtmf_info", digit: $(this).text() }});
					});
					$('#msg' + helperId).click(function() {
						bootbox.prompt("Insert message to send", function(result) {
							if(result && result !== '') {
								// Send the message
								var msg = { request: "message", content: result };
								helpers[helperId].sipcall.send({ message: msg });
							}
						});
					});
					$('#info' + helperId).click(function() {
						bootbox.dialog({
							message: 'Type: <input class="form-control" type="text" id="type" placeholder="e.g., application/xml">' +
								'<br/>Content: <input class="form-control" type="text" id="content" placeholder="e.g., <message>hi</message>">',
							title: "Insert the type and content to send",
							buttons: {
								cancel: {
									label: "Cancel",
									className: "btn-default",
									callback: function() {
										// Do nothing
									}
								},
								ok: {
									label: "OK",
									className: "btn-primary",
									callback: function() {
										// Send the INFO
										var type = $('#type').val();
										var content = $('#content').val();
										if(type === '' || content === '')
											return;
										var msg = { request: "info", type: type, content: content };
										helpers[helperId].sipcall.send({ message: msg });
									}
								}
							}
						});
					});
					$('#transfer' + helperId).click(function() {
						bootbox.dialog({
							message: '<input class="form-control" type="text" id="transferto" placeholder="e.g., sip:goofy@example.com">',
							title: "Insert the address to transfer the call to",
							buttons: {
								cancel: {
									label: "Cancel",
									className: "btn-default",
									callback: function() {
										// Do nothing
									}
								},
								blind: {
									label: "Blind transfer",
									className: "btn-info",
									callback: function() {
										// Start a blind transfer
										var address = $('#transferto').val();
										if(address === '')
											return;
										var msg = {
											request: "transfer",
											uri: address
										};
										helpers[helperId].sipcall.send({ message: msg });
									}
								},
								attended: {
									label: "Attended transfer",
									className: "btn-primary",
									callback: function() {
										// Start an attended transfer
										var address = $('#transferto').val();
										if(address === '')
											return;
										// Add the call-id to replace to the transfer
										var msg = {
											request: "transfer",
											uri: address,
											replace: helpers[helperId].sipcall.callId
										};
										helpers[helperId].sipcall.send({ message: msg });
									}
								}
							}
						});
					});
				}
				if(track.kind === "audio") {
					// New audio track: create a stream out of it, and use a hidden <audio> element
					stream = new MediaStream([track]);
					helpers[helperId].remoteTracks[mid] = stream;
					Janus.log("[Helper #" + helperId + "] Created remote audio stream:", stream);
					$('#videoright' + helperId).append('<audio class="hide" id="peervideo' + helperId + 'm' + mid + '" autoplay playsinline/>');
					Janus.attachMediaStream($('#peervideo' + helperId + 'm' + mid).get(0), stream);
					if(helpers[helperId].remoteVideos === 0) {
						// No video, at least for now: show a placeholder
						if($('#videoright' + helperId + ' .no-video-container').length === 0) {
							$('#videoright' + helperId).append(
								'<div class="no-video-container">' +
									'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
									'<span class="no-video-text">No remote video available</span>' +
								'</div>');
						}
					}
				} else {
					// New video track: create a stream out of it
					helpers[helperId].remoteVideos++;
					$('#videoright' + helperId + ' .no-video-container').remove();
					stream = new MediaStream([track]);
					helpers[helperId].remoteTracks[mid] = stream;
					Janus.log("[Helper #" + helperId + "] Created remote video stream:", stream);
					$('#videoright' + helperId).append('<video class="rounded centered" id="peervideo' + helperId + 'm' + mid + '" width="100%" height="100%" autoplay playsinline/>');
					Janus.attachMediaStream($('#peervideo' + helperId + 'm' + mid).get(0), stream);
				}
			},
			oncleanup: function() {
				Janus.log("[Helper #" + helperId + "]  ::: Got a cleanup notification :::");
				$('#videoleft' + helperId).empty().parent().unblock();
				$('#videoleft' + helperId).empty();
				$('#videos' + helperId).hide();
				$('#dtmf' + helperId).parent().html("Remote UA");
				if(helpers[helperId] && helpers[helperId].sipcall) {
					delete helpers[helperId].sipcall.callId;
					delete helpers[helperId].sipcall.doAudio;
					delete helpers[helperId].sipcall.doVideo;
				}
				if(helpers[helperId]) {
					helpers[helperId].localTracks = {};
					helpers[helperId].localVideos = 0;
					helpers[helperId].remoteTracks = {};
					helpers[helperId].remoteVideos = 0;
				}
			}
		});

}
function removeHelper(helperId) {
	if(helpers[helperId] && helpers[helperId].sipcall) {
		// Detach from the helper's Janus handle
		helpers[helperId].sipcall.detach();
		delete helpers[helperId];
		// Remove the related UI too
		$('#sipcall'+helperId).remove();
	}
}
