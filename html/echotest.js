var server = "http://" + window.location.hostname + ":8088/janus";

var janus = null;
var echotest = null;
var started = false;
var bitrateTimer = null;
var spinner = null;

var audioenabled = false;
var videoenabled = false;

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
					// No "iceServers" is provided, meaning janus.js will use a default STUN server
					// Here are some examples of how an iceServers field may look like to support TURN
					// 		iceServers: [{url: "turn:janususer@yourturnserver.com:3478", credential: "januspwd"}],
					// 		iceServers: [{url: "turn:janususer@yourturnserver.com:443?transport=tcp", credential: "januspwd"}],
					// 		iceServers: [{url: "turns:janususer@yourturnserver.com:443?transport=tcp", credential: "januspwd"}],
					success: function() {
						// Attach to echo test plugin
						janus.attach(
							{
								plugin: "janus.plugin.echotest",
								success: function(pluginHandle) {
									echotest = pluginHandle;
									console.log("Plugin attached! (" + echotest.getPlugin() + ", id=" + echotest.getId() + ")");
									// Negotiate WebRTC
									var body = { "audio": true, "video": true };
									console.log("Sending message (" + JSON.stringify(body) + ")");
									echotest.send({"message": body});
									console.log("Trying a createOffer too (audio/video sendrecv)");
									echotest.createOffer(
										{
											// No media provided: by default, it's sendrecv for audio and video
											success: function(jsep) {
												console.log("Got SDP!");
												console.log(jsep.sdp);
												echotest.send({"message": body, "jsep": jsep});
											},
											error: function(error) {
												console.log("WebRTC error:");
												console.log(error);
												bootbox.alert("WebRTC error... " + error);
											}
										});
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											clearInterval(bitrateTimer);
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
												left: (navigator.mozGetUserMedia ? '-100px' : '500px')
											} });
									} else {
										// Restore screen
										$.unblockUI();
									}
								},
								onmessage: function(msg, jsep) {
									console.log(" ::: Got a message :::");
									console.log(JSON.stringify(msg));
									if(jsep !== undefined && jsep !== null) {
										console.log("Handling SDP as well...");
										console.log(jsep.sdp);
										echotest.handleRemoteJsep({jsep: jsep});
									}
									var result = msg["result"];
									if(result !== null && result !== undefined) {
										if(result === "done") {
											// The plugin closed the echo test
											bootbox.alert("The Echo Test is over");
											if(spinner !== null && spinner !== undefined)
												spinner.stop();
											spinenr = null;
											$('#myvideo').remove();
											$('#waitingvideo').remove();
											$('#peervideo').remove();
											$('#toggleaudio').attr('disabled', true);
											$('#togglevideo').attr('disabled', true);
											$('#bitrate').attr('disabled', true);
											$('#curbitrate').hide();
											$('#curres').hide();
										}
									}
								},
								onlocalstream: function(stream) {
									console.log(" ::: Got a local stream :::");
									console.log(JSON.stringify(stream));
									if($('#myvideo').length === 0) {
										$('#videos').removeClass('hide').show();
										$('#videoleft').append('<video class="rounded centered" id="myvideo" width=320 height=240 autoplay muted="true"/>');
									}
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
									if($('#peervideo').length === 0) {
										spinner.stop();
										$('#waitingvideo').remove();
										$('#videos').removeClass('hide').show();
										$('#videoright').append('<video class="rounded centered" id="peervideo" width=320 height=240 autoplay/>');
										// Detect resolution
										$("#peervideo").bind("loadedmetadata", function () {
											var width = this.videoWidth;
											var height = this.videoHeight;
											$('#curres').removeClass('hide').text(width+'x'+height).show();
										});
									}
									attachMediaStream($('#peervideo').get(0), stream);
									// Enable audio/video buttons and bitrate limiter
									audioenabled = true;
									videoenabled = true;
									$('#toggleaudio').click(
										function() {
											audioenabled = !audioenabled;
											if(audioenabled)
												$('#toggleaudio').html("Disable audio").removeClass("btn-success").addClass("btn-danger");
											else
												$('#toggleaudio').html("Enable audio").removeClass("btn-danger").addClass("btn-success");
											echotest.send({"message": { "audio": audioenabled }});
										});
									$('#togglevideo').click(
										function() {
											videoenabled = !videoenabled;
											if(videoenabled)
												$('#togglevideo').html("Disable video").removeClass("btn-success").addClass("btn-danger");
											else
												$('#togglevideo').html("Enable video").removeClass("btn-danger").addClass("btn-success");
											echotest.send({"message": { "video": videoenabled }});
										});
									$('#toggleaudio').parent().removeClass('hide').show();
									$('#bitrate a').click(function() {
										var id = $(this).attr("id");
										var bitrate = parseInt(id)*1000;
										if(bitrate === 0) {
											console.log("Not limiting bandwidth via REMB");
										} else {
											console.log("Capping bandwidth to " + bitrate + " via REMB");
										}
										$('#bitrateset').html($(this).html()).parent().removeClass('open');
										echotest.send({"message": { "bitrate": bitrate }});
										return false;
									});
									$('#curbitrate').removeClass('hide').show();
									bitrateTimer = setInterval(function() {
										// Display updated bitrate, if supported
										var bitrate = echotest.getBitrate();
										//~ console.log("Current bitrate is " + echotest.getBitrate());
										$('#curbitrate').text(bitrate);
									}, 1000);
								},
								oncleanup: function() {
									console.log(" ::: Got a cleanup notification :::");
									if(spinner !== null && spinner !== undefined)
										spinner.stop();
									spinenr = null;
									$('#myvideo').remove();
									$('#waitingvideo').remove();
									$('#peervideo').remove();
									$('#toggleaudio').attr('disabled', true);
									$('#togglevideo').attr('disabled', true);
									$('#bitrate').attr('disabled', true);
									$('#curbitrate').hide();
									$('#curres').hide();
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
