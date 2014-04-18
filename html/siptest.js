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
var server = null;
if(window.location.protocol === 'http:')
	server = "http://" + window.location.hostname + ":8088/janus";
else
	server = "https://" + window.location.hostname + ":8089/janus";

var janus = null;
var sipcall = null;
var started = false;
var spinner = null;

var registered = false;

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
								plugin: "janus.plugin.sip",
								success: function(pluginHandle) {
									$('#details').remove();
									sipcall = pluginHandle;
									console.log("Plugin attached! (" + sipcall.getPlugin() + ", id=" + sipcall.getId() + ")");
									// Prepare the username registration
									$('#sipcall').removeClass('hide').show();
									$('#login').removeClass('hide').show();
									$('#register').click(registerUsername);
									$('#server').focus();
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
												left: (navigator.mozGetUserMedia ? '-100px' : '400px')
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
									if(result !== null && result !== undefined && result["event"] !== undefined && result["event"] !== null) {
										var event = result["event"];
										if(event === 'registered') {
											console.log("Successfully registered as " + result["username"] + "!");
											$('#you').removeClass('hide').show().text("Registered as '" + result["username"]);
											// TODO Enable buttons to call now
											if(!registered) {
												registered = true;
												$('#phone').removeClass('hide').show();
												$('#call').unbind('click').click(doCall);
												$('#peer').focus();
											}
										} else if(event === 'calling') {
											console.log("Waiting for the peer to answer...");
											// TODO Any ringtone?
										} else if(event === 'incomingcall') {
											console.log("Incoming call from " + result["username"] + "!");
											$('#peer').val(result["username"]).attr('disabled');
											// TODO Enable buttons to answer
											if(jsep !== null && jsep !== undefined)
												sipcall.handleRemoteJsep({jsep: jsep});
											sipcall.createAnswer(
												{
													jsep: jsep,
													// No media provided: by default, it's sendrecv for audio and video
													success: function(jsep) {
														console.log("Got SDP!");
														console.log(jsep.sdp);
														var body = { "request": "accept" };
														sipcall.send({"message": body, "jsep": jsep});
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
											console.log(result["username"] + " accepted the call!");
											// TODO Video call can start
											if(jsep !== null && jsep !== undefined)
												sipcall.handleRemoteJsep({jsep: jsep});
											$('#call').removeAttr('disabled').html('Hangup')
												.removeClass("btn-success").addClass("btn-danger")
												.unbind('click').click(doHangup);
										} else if(event === 'hangup') {
											console.log("Call hung up by " + result["username"] + " (" + result["reason"] + ")!");
											// TODO Reset status
											sipcall.hangup();
											$('#peer').removeAttr('disabled').val('');
											$('#call').removeAttr('disabled').html('Call')
												.removeClass("btn-danger").addClass("btn-success")
												.unbind('click').click(doCall);
										}
									}
								},
								onlocalstream: function(stream) {
									console.log(" ::: Got a local stream :::");
									console.log(JSON.stringify(stream));
									$('#videos').removeClass('hide').show();
									if($('#myvideo').length === 0)
										$('#videoleft').append('<video class="rounded centered" id="myvideo" width=320 height=240 autoplay muted="muted"/>');
									attachMediaStream($('#myvideo').get(0), stream);
									// No remote video yet
									$('#videoright').append('<video class="rounded centered" id="waitingvideo" width=320 height=240 />');
									if(spinner == null) {
										var target = document.getElementById('videoright');
										spinner = new Spinner({top:100}).spin(target);
									} else {
										spinner.spin();
									}
								},
								onremotestream: function(stream) {
									console.log(" ::: Got a remote stream :::");
									console.log(JSON.stringify(stream));
									spinner.stop();
									$('#waitingvideo').remove();
									if($('#remotevideo').length === 0) {
										$('#videoright').append(
											'<div>DTMF: <div id="dtmf" class="btn-group btn-group-xs"></div></div>' +
											'<video class="rounded centered" id="remotevideo" width=320 height=240 autoplay/>');
										for(var i=0; i<12; i++) {
											if(i<10)
												$('#dtmf').append('<button class="btn btn-info dtmf">' + i + '</button>');
											else if(i == 10)
												$('#dtmf').append('<button class="btn btn-info dtmf">#</button>');
											else if(i == 11)
												$('#dtmf').append('<button class="btn btn-info dtmf">*</button>');
										}
										$('.dtmf').click(function() {
											// Send DTMF tone
											sipcall.dtmf({dtmf: { tones: $(this).text()}});
										});
									}
									attachMediaStream($('#remotevideo').get(0), stream);
								},
								oncleanup: function() {
									console.log(" ::: Got a cleanup notification :::");
									$('#myvideo').remove();
									$('#remotevideo').remove();
									$('#videos').hide();
									$('#dtmf').parent().remove();
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
		if(field.id == 'server' || field.id == 'username' || field.id == 'password')
			registerUsername();
		else if(field.id == 'peer')
			doCall();
		return false;
	} else {
		return true;
	}
}

function registerUsername() {
	// Try a registration
	$('#server').attr('disabled', true);
	$('#username').attr('disabled', true);
	$('#password').attr('disabled', true);
	$('#register').attr('disabled', true).unbind('click');
	var sipserver = $('#server').val();
	if(sipserver === "" || sipserver.indexOf(":") === -1) {
		bootbox.alert("Insert the SIP server (e.g., 192.168.0.1:5060)");
		$('#server').removeAttr('disabled');
		$('#username').removeAttr('disabled');
		$('#password').removeAttr('disabled');
		$('#register').removeAttr('disabled').click(registerUsername);
		return;
	}
	var parts = sipserver.split(":");
	var server = parts[0];
	var port = parseInt(parts[1]);
	if(port === NaN) {
		bootbox.alert("Inalid port " + port + " in the SIP server (e.g., 192.168.0.1:5060)");
		$('#server').removeAttr('disabled');
		$('#username').removeAttr('disabled');
		$('#password').removeAttr('disabled');
		$('#register').removeAttr('disabled').click(registerUsername);
		return;
	}
	var username = $('#username').val();
	if(username === "") {
		bootbox.alert("Insert the username to register (e.g., pippo)");
		$('#server').removeAttr('disabled');
		$('#username').removeAttr('disabled');
		$('#password').removeAttr('disabled');
		$('#register').removeAttr('disabled').click(registerUsername);
		return;
	}
	if(/[^a-zA-Z0-9]/.test(username)) {
		bootbox.alert('Input is not alphanumeric');
		$('#server').removeAttr('disabled');
		$('#username').removeAttr('disabled');
		$('#password').removeAttr('disabled');
		$('#register').removeAttr('disabled').click(registerUsername);
		return;
	}
	var password = $('#password').val();
	if(password === "") {
		bootbox.alert("Insert the username secret (e.g., mypassword)");
		$('#server').removeAttr('disabled');
		$('#username').removeAttr('disabled');
		$('#password').removeAttr('disabled');
		$('#register').removeAttr('disabled').click(registerUsername);
		return;
	}
	var register = {
		"request" : "register",
		"username" : username,
		"secret" : password,
		"proxy_ip" : server,
		"proxy_port" : port
	};
	sipcall.send({"message": register});
}

function doCall() {
	// Call someone
	$('#peer').attr('disabled', true);
	$('#call').attr('disabled', true).unbind('click');
	$('#dovideo').attr('disabled', true);
	var username = $('#peer').val();
	if(username === "") {
		bootbox.alert("Insert a username to call (e.g., pluto)");
		$('#peer').removeAttr('disabled');
		$('#dovideo').removeAttr('disabled');
		$('#call').removeAttr('disabled').click(doCall);
		return;
	}
	if(/[^a-zA-Z0-9]/.test(username)) {
		bootbox.alert('Input is not alphanumeric');
		$('#peer').removeAttr('disabled').val("");
		$('#dovideo').removeAttr('disabled').val("");
		$('#call').removeAttr('disabled').click(doCall);
		return;
	}
	// Call this extension
	doVideo = ($('#dovideo:checked').val() === true);
	console.log("This is a SIP " + (doVideo ? "video" : "audio") + " call (dovideo=" + doVideo + ")"); 
	sipcall.createOffer(
		{
			media: {
				audioSend: true, audioRecv: true,		// We DO want audio
				videoSend: doVideo, videoRecv: doVideo	// We MAY want video
			},
			success: function(jsep) {
				console.log("Got SDP!");
				console.log(jsep.sdp);
				var body = { "request": "call", extension: $('#peer').val() };
				sipcall.send({"message": body, "jsep": jsep});
			},
			error: function(error) {
				console.log("WebRTC error...");
				console.log(error);
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
