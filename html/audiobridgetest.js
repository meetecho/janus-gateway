var server = "http://" + window.location.hostname + ":8088/janus";

var janus = null;
var mixertest = null;
var started = false;
var spinner = null;

var myusername = null;
var myid = null;
var audioenabled = false;


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
						// Attach to Audio Bridge test plugin
						janus.attach(
							{
								plugin: "janus.plugin.audiobridge",
								success: function(pluginHandle) {
									mixertest = pluginHandle;
									console.log("Plugin attached! (" + mixertest.getPlugin() + ", id=" + mixertest.getId() + ")");
									// Prepare the username registration
									$('#audiojoin').removeClass('hide').show();
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
									var event = msg["audiobridge"];
									console.log("Event: " + event);
									if(event != undefined && event != null) {
										if(event === "joined") {
											// Successfully joined, negotiate WebRTC now
											myid = msg["id"];
											console.log("Successfully joined room " + msg["room"] + " with ID " + myid);
											// Publish our stream
											mixertest.createOffer(
												{
													media: { video: false},	// This is an audio only room
													success: function(jsep) {
														console.log("Got SDP!");
														console.log(jsep.sdp);
														var publish = { "request": "configure", "audio": true };
														mixertest.send({"message": publish, "jsep": jsep});
													},
													error: function(error) {
														console.log("WebRTC error:");
														console.log(error);
														bootbox.alert("WebRTC error... " + error);
													}
												});
											// Any room participant?
											if(msg["participants"] !== undefined && msg["participants"] !== null) {
												var list = msg["participants"];
												console.log("Got a list of participants:");
												console.log(list);
												for(var f in list) {
													var id = list[f]["id"];
													var display = list[f]["display"];
													var muted = list[f]["muted"];
													console.log("  >> [" + id + "] " + display + " (muted=" + muted + ")");
													if($('#rp'+id).length === 0) {
														// Add to the participants list
														$('#list').append('<li id="rp'+id+'" class="list-group-item">'+display+' <i class="fa fa-microphone-slash"></i></li>');
														$('#rp'+id + ' > i').hide();
													}
													if(muted === true || muted === "true")
														$('#rp'+id + ' > i').removeClass('hide').show();
													else
														$('#rp'+id + ' > i').hide();
												}
											}
										} else if(event === "event") {
											if(msg["participants"] !== undefined && msg["participants"] !== null) {
												var list = msg["participants"];
												console.log("Got a list of participants:");
												console.log(list);
												for(var f in list) {
													var id = list[f]["id"];
													var display = list[f]["display"];
													var muted = list[f]["muted"];
													console.log("  >> [" + id + "] " + display + " (muted=" + muted + ")");
													if($('#rp'+id).length === 0) {
														// Add to the participants list
														$('#list').append('<li id="rp'+id+'" class="list-group-item">'+display+' <i class="fa fa-microphone-slash"></li>');
														$('#rp'+id + ' > i').hide();
													}
													if(muted === true || muted === "true")
														$('#rp'+id + ' > i').removeClass('hide').show();
													else
														$('#rp'+id + ' > i').hide();
												}
											}
											// Any new feed to attach to?
											if(msg["leaving"] !== undefined && msg["leaving"] !== null) {
												// One of the participants has gone away?
												var leaving = msg["leaving"];
												console.log("Participant left: " + leaving + " (we have " + $('#rp'+leaving).length + " elements with ID #rp" +leaving + ")");
												$('#rp'+leaving).remove();
											}
										}
									}
									if(jsep !== undefined && jsep !== null) {
										console.log("Handling SDP as well...");
										console.log(jsep.sdp);
										mixertest.handleRemoteJsep({jsep: jsep});
									}
								},
								onlocalstream: function(stream) {
									console.log(" ::: Got a local stream :::");
									console.log(JSON.stringify(stream));
									// We're not going to attach the local audio stream
									$('#room').removeClass('hide').show();
									$('#participant').removeClass('hide').html(myusername).show();
								},
								onremotestream: function(stream) {
									$('#room').removeClass('hide').show();
									if($('#roomaudio').length === 0) {
										$('#mixedaudio').append('<video class="rounded centered" id="roomaudio" width="100%" height="100%" autoplay/>');
									}
									attachMediaStream($('#roomaudio').get(0), stream);
									// Mute button
									audioenabled = true;
									$('#toggleaudio').click(
										function() {
											audioenabled = !audioenabled;
											if(audioenabled)
												$('#toggleaudio').html("Mute").removeClass("btn-success").addClass("btn-danger");
											else
												$('#toggleaudio').html("Unmute").removeClass("btn-danger").addClass("btn-success");
											mixertest.send({message: { "request": "configure", "audio": audioenabled }});
										}).removeClass('hide').show();

								},
								oncleanup: function() {
									console.log(" ::: Got a cleanup notification :::");
									$('#participant').empty().hide();
									$('#list').empty();
									$('#mixedaudio').empty();
									$('#room').hide();
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
		var register = { "request": "join", "room": 1234, "display": username };
		myusername = username;
		mixertest.send({"message": register});
	}
}
