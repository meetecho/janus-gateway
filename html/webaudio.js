// We import the settings.js file to know which address we should contact
// to talk to Janus, and optionally which STUN/TURN servers should be
// used as well. Specifically, that file defines the "server" and
// "iceServers" properties we'll pass when creating the Janus session.

var janus = null;
var echotest = null;
var opaqueId = "echotest-"+Janus.randomString(12);

var localTracks = {}, localVideos = 0,
	remoteTracks = {}, remoteVideos = 0;
var bitrateTimer = null;
var spinner = null;

var audioenabled = false;
var videoenabled = false;

var acodec = (getQueryStringValue("acodec") !== "" ? getQueryStringValue("acodec") : null);
var doDtx = (getQueryStringValue("dtx") === "yes" || getQueryStringValue("dtx") === "true");
var doOpusred = (getQueryStringValue("opusred") === "yes" || getQueryStringValue("opusred") === "true");

// Web Audio context and filters
var AudioContext = window.AudioContext || window.webkitAudioContext;
var audioContext = new AudioContext();
var compressor = null, analyser = null;
// Canvas and visualizer data
var canvasContext = null, dataArray = null;

// By default we talk to the "regular" EchoTest plugin
var echotestPluginBackend = "janus.plugin.echotest";
// We can use query string arguments to talk to the Lua or Duktape EchoTest
// demo scripts instead. Notice that this assumes that the Lua or Duktape
// plugins are configured to run the sample scripts that comes with the repo
if(getQueryStringValue("plugin") === "lua")
	echotestPluginBackend = "janus.plugin.echolua";
else if(getQueryStringValue("plugin") === "duktape")
	echotestPluginBackend = "janus.plugin.echojs";

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
					// No "iceServers" is provided, meaning janus.js will use a default STUN server
					// Here are some examples of how an iceServers field may look like to support TURN
					// 		iceServers: [{urls: "turn:yourturnserver.com:3478", username: "janususer", credential: "januspwd"}],
					// 		iceServers: [{urls: "turn:yourturnserver.com:443?transport=tcp", username: "janususer", credential: "januspwd"}],
					// 		iceServers: [{urls: "turns:yourturnserver.com:443?transport=tcp", username: "janususer", credential: "januspwd"}],
					// Should the Janus API require authentication, you can specify either the API secret or user token here too
					//		token: "mytoken",
					//	or
					//		apisecret: "serversecret",
					success: function() {
						// Attach to EchoTest plugin
						janus.attach(
							{
								plugin: echotestPluginBackend,
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									echotest = pluginHandle;
									Janus.log("Plugin attached! (" + echotest.getPlugin() + ", id=" + echotest.getId() + ")");
									// Capture the webcam and create the Web Audio processors
									setupWebAudioDemo();
									// Done
									$('#demo').removeClass('hide');
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											if(bitrateTimer)
												clearInterval(bitrateTimer);
											bitrateTimer = null;
											janus.destroy();
										});
								},
								error: function(error) {
									console.error("  -- Error attaching plugin...", error);
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
									$("#videoleft").parent().unblock();
								},
								slowLink: function(uplink, lost, mid) {
									Janus.warn("Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on mid " + mid + " (" + lost + " lost packets)");
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::", msg);
									if(jsep) {
										Janus.debug("Handling SDP as well...", jsep);
										echotest.handleRemoteJsep({ jsep: jsep });
									}
									var result = msg["result"];
									if(result) {
										if(result === "done") {
											// The plugin closed the echo test
											bootbox.alert("The test is over");
											return;
										}
										// Any loss?
										var status = result["status"];
										if(status === "slow_link") {
											toastr.warning("Janus apparently missed many packets we sent, maybe we should reduce the bitrate", "Packet loss?", {timeOut: 2000});
										}
									}
								},
								onlocaltrack: function(track, on) {
									Janus.debug("Local track " + (on ? "added" : "removed") + ":", track);
									// We don't do anything here, since we captured the stream ourselves
								},
								onremotetrack: function(track, mid, on) {
									Janus.debug("Remote track (mid=" + mid + ") " + (on ? "added" : "removed") + ":", track);
									// Now that we're aware of the remote stream, we process it to visualize it
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
										$('#peeraudio' + mid).remove();
										delete remoteTracks[mid];
										return;
									}
									// If we're here, a new track was added
									if(track.kind === "audio") {
										// New audio track: create a stream out of it, and use a hidden <audio> element
										stream = new MediaStream([track]);
										remoteTracks[mid] = stream;
										Janus.log("Created remote audio stream:", stream);
										if($('#peeraudio'+mid).length === 0)
											$('#remote').append('<audio class="hide" id="peeraudio' + mid + '" autoplay playsinline/>');
										Janus.attachMediaStream($('#peeraudio' + mid).get(0), stream);
										// Do we have a visualizer already?
										if($('#canvas').length === 0) {
											// Create a new visualizer: since we're lazy we use this existing example:
											// https://developer.mozilla.org/en-US/docs/Web/API/Web_Audio_API/Visualizations_with_Web_Audio_API
											$('#remote').append('<canvas id="canvas" width="432" height="240" style="display: block; margin: auto; padding: 0"></canvas>');
											var canvas = $('#canvas').get(0);
											canvasContext = canvas.getContext('2d');
											analyser = audioContext.createAnalyser();
											analyser.fftSize = 256;
											dataArray = new Uint8Array(analyser.frequencyBinCount);
											canvasContext.clearRect(0, 0, 432, 240);
											var source = audioContext.createMediaStreamSource(stream);
											source.connect(analyser);
											drawVisualizer();
											// Also unlock the compressor controls
											$('#threshold').removeAttr('disabled');
											$('#knee').removeAttr('disabled');
											$('#ratio').removeAttr('disabled');
											$('#attack').removeAttr('disabled');
											$('#release').removeAttr('disabled');
										}
									} else {
										// Video? Ignore
									}
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
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

// Helper to parse query string
function getQueryStringValue(name) {
	name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
	var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
		results = regex.exec(location.search);
	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

function checkEnter(event) {
	var theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if(theCode == 13) {
		// Update the compressor values, if needed
		var threshold = parseFloat($('#threshold').val());
		if(threshold !== compressor.threshold.value) {
			if(threshold < compressor.threshold.minValue || threshold > compressor.threshold.maxValue) {
				toastr["warning"]("Invalid threshold value");
			} else {
				compressor.threshold.setValueAtTime(threshold, audioContext.currentTime);
				toastr["success"]("Threshold updated");
			}
			$('#threshold').val('' + compressor.threshold.value);
		}
		var knee = parseFloat($('#knee').val());
		if(knee !== compressor.knee.value) {
			if(knee < compressor.knee.minValue || knee > compressor.knee.maxValue) {
				toastr["warning"]("Invalid knee value");
			} else {
				compressor.knee.setValueAtTime(knee, audioContext.currentTime);
				toastr["success"]("Knee updated");
			}
			$('#knee').val('' + compressor.knee.value);
		}
		var ratio = parseFloat($('#ratio').val());
		if(ratio !== compressor.ratio.value) {
			if(ratio < compressor.ratio.minValue || ratio > compressor.ratio.maxValue) {
				toastr["warning"]("Invalid ratio value");
			} else {
				compressor.ratio.setValueAtTime(ratio, audioContext.currentTime);
				toastr["success"]("Ratio updated");
			}
			$('#ratio').val('' + compressor.ratio.value);
		}
		var attack = parseFloat($('#attack').val());
		if(attack !== compressor.attack.value) {
			if(attack < compressor.attack.minValue || attack > compressor.attack.maxValue) {
				toastr["warning"]("Invalid attack value");
			} else {
				compressor.attack.setValueAtTime(attack, audioContext.currentTime);
				toastr["success"]("Attack updated");
			}
			$('#attack').val('' + compressor.attack.value);
		}
		var release = parseFloat($('#release').val());
		if(release !== compressor.release.value) {
			if(release < compressor.release.minValue || release > compressor.release.maxValue) {
				toastr["warning"]("Invalid release value");
			} else {
				compressor.release.setValueAtTime(release, audioContext.currentTime);
				toastr["success"]("Release updated");
			}
			$('#release').val('' + compressor.release.value);
		}
		return false;
	} else {
		return true;
	}
}

// We setup the Web Audio resources here
function setupWebAudioDemo() {
	// We have a context already, let's capture the microphone (with gain control disabled)
	navigator.mediaDevices.getUserMedia({ audio: { autoGainControl: false }, video: false })
	.then(function(audioStream) {
		// Let's create a source from the microphone stream
		var microphone = audioContext.createMediaStreamSource(audioStream);
		// Create a compressor node with some default values
		compressor = audioContext.createDynamicsCompressor();
		compressor.threshold.setValueAtTime(-18.0, audioContext.currentTime);
		compressor.knee.setValueAtTime(9.0, audioContext.currentTime);
		compressor.ratio.setValueAtTime(3.0, audioContext.currentTime);
		compressor.attack.setValueAtTime(0.02, audioContext.currentTime);
		compressor.release.setValueAtTime(0.25, audioContext.currentTime);
		// Update the content of the compressor UI with the current settings
		$('#threshold').val('' + compressor.threshold.value);
		$('#knee').val('' + compressor.knee.value);
		$('#ratio').val('' + compressor.ratio.value);
		$('#attack').val('' + compressor.attack.value);
		$('#release').val('' + compressor.release.value);
		// Use the compressor as a filter to get a new stream
		var peer = audioContext.createMediaStreamDestination();
		microphone.connect(compressor);
		compressor.connect(peer);
		// Let's use the compressed stream as source for our PeerConnection
		echotest.createOffer(
			{
				// We provide our own stream
				tracks: [
					{ type: 'audio', capture: peer.stream.getAudioTracks()[0], recv: true }
				],
				success: function(jsep) {
					Janus.debug("Got SDP!", jsep);
					var body = { audio: true, video: true };
					echotest.send({ message: body, jsep: jsep });
				},
				error: function(error) {
					Janus.error("WebRTC error:", error);
					bootbox.alert("WebRTC error... " + error.message);
				}
			});
	});
}

// This is our callback to draw the visualizer for the remore audio data
function drawVisualizer() {
	drawVisual = requestAnimationFrame(drawVisualizer);
	analyser.getByteFrequencyData(dataArray);
	canvasContext.fillStyle = 'rgb(0, 0, 0)';
	canvasContext.fillRect(0, 0, 432, 240);
	var barWidth = (432 / analyser.frequencyBinCount) * 2.5;
	var barHeight;
	var x = 0;
	for(var i=0; i < analyser.frequencyBinCount; i++) {
		barHeight = dataArray[i]/2;
		canvasContext.fillStyle = 'rgb(' + (barHeight+100) + ',50,50)';
		canvasContext.fillRect(x, 240-barHeight/2, barWidth, barHeight);
		x += barWidth + 1;
	}
}
