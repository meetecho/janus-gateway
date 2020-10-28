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
var echotest = null;
var opaqueId = "echotest-"+Janus.randomString(12);

var bitrateTimer = null;
var spinner = null;

var audioenabled = false;
var videoenabled = false;

var doSimulcast = (getQueryStringValue("simulcast") === "yes" || getQueryStringValue("simulcast") === "true");
var doSimulcast2 = (getQueryStringValue("simulcast2") === "yes" || getQueryStringValue("simulcast2") === "true");
var acodec = (getQueryStringValue("acodec") !== "" ? getQueryStringValue("acodec") : null);
var vcodec = (getQueryStringValue("vcodec") !== "" ? getQueryStringValue("vcodec") : null);
var vprofile = (getQueryStringValue("vprofile") !== "" ? getQueryStringValue("vprofile") : null);
var simulcastStarted = false;

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
								plugin: "janus.plugin.echotest",
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									echotest = pluginHandle;
									Janus.log("Plugin attached! (" + echotest.getPlugin() + ", id=" + echotest.getId() + ")");
									// Negotiate WebRTC
									var body = { audio: true, video: true };
									// We can try and force a specific codec, by telling the plugin what we'd prefer
									// For simplicity, you can set it via a query string (e.g., ?vcodec=vp9)
									if(acodec)
										body["audiocodec"] = acodec;
									if(vcodec)
										body["videocodec"] = vcodec;
									// For the codecs that support them (VP9 and H.264) you can specify a codec
									// profile as well (e.g., ?vprofile=2 for VP9, or ?vprofile=42e01f for H.264)
									if(vprofile)
										body["videoprofile"] = vprofile;
									Janus.debug("Sending message:", body);
									echotest.send({ message: body });
									Janus.debug("Trying a createOffer too (audio/video sendrecv)");
									echotest.createOffer(
										{
											// No media provided: by default, it's sendrecv for audio and video
											media: { data: true },	// Let's negotiate data channels as well
											// If you want to test simulcasting (Chrome and Firefox only), then
											// pass a ?simulcast=true when opening this demo page: it will turn
											// the following 'simulcast' property to pass to janus.js to true
											simulcast: doSimulcast,
											simulcast2: doSimulcast2,
											success: function(jsep) {
												Janus.debug("Got SDP!", jsep);
												echotest.send({ message: body, jsep: jsep });
											},
											error: function(error) {
												Janus.error("WebRTC error:", error);
												bootbox.alert("WebRTC error... " + error.message);
											}
										});
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
								mediaState: function(medium, on) {
									Janus.log("Janus " + (on ? "started" : "stopped") + " receiving our " + medium);
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
								},
								slowLink: function(uplink, lost) {
									Janus.warn("Janus reports problems " + (uplink ? "sending" : "receiving") +
										" packets on this PeerConnection (" + lost + " lost packets)");
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
											bootbox.alert("The Echo Test is over");
											if(spinner)
												spinner.stop();
											spinner = null;
											$('#myvideo').remove();
											$('#waitingvideo').remove();
											$('#peervideo').remove();
											$('#toggleaudio').attr('disabled', true);
											$('#togglevideo').attr('disabled', true);
											$('#bitrate').attr('disabled', true);
											$('#curbitrate').hide();
											$('#curres').hide();
											return;
										}
										// Any loss?
										var status = result["status"];
										if(status === "slow_link") {
											toastr.warning("Janus apparently missed many packets we sent, maybe we should reduce the bitrate", "Packet loss?", {timeOut: 2000});
										}
									}
									// Is simulcast in place?
									var substream = msg["substream"];
									var temporal = msg["temporal"];
									if((substream !== null && substream !== undefined) || (temporal !== null && temporal !== undefined)) {
										if(!simulcastStarted) {
											simulcastStarted = true;
											addSimulcastButtons(msg["videocodec"] === "vp8" || msg["videocodec"] === "h264");
										}
										// We just received notice that there's been a switch, update the buttons
										updateSimulcastButtons(substream, temporal);
									}
								},
								onlocalstream: function(stream) {
									Janus.debug(" ::: Got a local stream :::", stream);
									if($('#myvideo').length === 0) {
										$('#videos').removeClass('hide').show();
										$('#videoleft').append('<video class="rounded centered" id="myvideo" width="100%" height="100%" autoplay playsinline muted="muted"/>');
									}
									Janus.attachMediaStream($('#myvideo').get(0), stream);
									$("#myvideo").get(0).muted = "muted";
									if(echotest.webrtcStuff.pc.iceConnectionState !== "completed" &&
											echotest.webrtcStuff.pc.iceConnectionState !== "connected") {
										$("#videoleft").parent().block({
											message: '<b>Publishing...</b>',
											css: {
												border: 'none',
												backgroundColor: 'transparent',
												color: 'white'
											}
										});
										// No remote video yet
										$('#videoright').append('<video class="rounded centered" id="waitingvideo" width="100%" height="100%" />');
										if(spinner == null) {
											var target = document.getElementById('videoright');
											spinner = new Spinner({top:100}).spin(target);
										} else {
											spinner.spin();
										}
									}
									var videoTracks = stream.getVideoTracks();
									if(!videoTracks || videoTracks.length === 0) {
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
									Janus.debug(" ::: Got a remote stream :::", stream);
									var addButtons = false;
									if($('#peervideo').length === 0) {
										addButtons = true;
										$('#videos').removeClass('hide').show();
										$('#videoright').append('<video class="rounded centered hide" id="peervideo" width="100%" height="100%" autoplay playsinline/>');
										// Show the video, hide the spinner and show the resolution when we get a playing event
										$("#peervideo").bind("playing", function () {
											$('#waitingvideo').remove();
											if(this.videoWidth)
												$('#peervideo').removeClass('hide').show();
											if(spinner)
												spinner.stop();
											spinner = null;
											var width = this.videoWidth;
											var height = this.videoHeight;
											$('#curres').removeClass('hide').text(width+'x'+height).show();
										});
									}
									Janus.attachMediaStream($('#peervideo').get(0), stream);
									var videoTracks = stream.getVideoTracks();
									if(!videoTracks || videoTracks.length === 0) {
										// No remote video
										$('#peervideo').hide();
										if($('#videoright .no-video-container').length === 0) {
											$('#videoright').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
													'<span class="no-video-text">No remote video available</span>' +
												'</div>');
										}
									} else {
										$('#videoright .no-video-container').remove();
										$('#peervideo').removeClass('hide').show();
									}
									if(!addButtons)
										return;
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
											echotest.send({ message: { audio: audioenabled }});
										});
									$('#togglevideo').click(
										function() {
											videoenabled = !videoenabled;
											if(videoenabled)
												$('#togglevideo').html("Disable video").removeClass("btn-success").addClass("btn-danger");
											else
												$('#togglevideo').html("Enable video").removeClass("btn-danger").addClass("btn-success");
											echotest.send({ message: { video: videoenabled }});
										});
									$('#toggleaudio').parent().removeClass('hide').show();
									$('#bitrate a').click(function() {
										var id = $(this).attr("id");
										var bitrate = parseInt(id)*1000;
										if(bitrate === 0) {
											Janus.log("Not limiting bandwidth via REMB");
										} else {
											Janus.log("Capping bandwidth to " + bitrate + " via REMB");
										}
										$('#bitrateset').html($(this).html() + '<span class="caret"></span>').parent().removeClass('open');
										echotest.send({ message: { bitrate: bitrate }});
										return false;
									});
									if(Janus.webRTCAdapter.browserDetails.browser === "chrome" || Janus.webRTCAdapter.browserDetails.browser === "firefox" ||
											Janus.webRTCAdapter.browserDetails.browser === "safari") {
										$('#curbitrate').removeClass('hide').show();
										bitrateTimer = setInterval(function() {
											// Display updated bitrate, if supported
											var bitrate = echotest.getBitrate();
											$('#curbitrate').text(bitrate);
											// Check if the resolution changed too
											var width = $("#peervideo").get(0).videoWidth;
											var height = $("#peervideo").get(0).videoHeight;
											if(width > 0 && height > 0)
												$('#curres').removeClass('hide').text(width+'x'+height).show();
										}, 1000);
									}
								},
								ondataopen: function(data) {
									Janus.log("The DataChannel is available!");
									$('#videos').removeClass('hide').show();
									$('#datasend').removeAttr('disabled');
								},
								ondata: function(data) {
									Janus.debug("We got data from the DataChannel!", data);
									$('#datarecv').val(data);
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									if(spinner)
										spinner.stop();
									spinner = null;
									if(bitrateTimer)
										clearInterval(bitrateTimer);
									bitrateTimer = null;
									$('#myvideo').remove();
									$('#waitingvideo').remove();
									$("#videoleft").parent().unblock();
									$('#peervideo').remove();
									$('#toggleaudio').attr('disabled', true);
									$('#togglevideo').attr('disabled', true);
									$('#bitrate').attr('disabled', true);
									$('#curbitrate').hide();
									$('#curres').hide();
									$('#datasend').attr('disabled', true);
									simulcastStarted = false;
									$('#simulcast').remove();
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

function checkEnter(event) {
	var theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if(theCode == 13) {
		sendData();
		return false;
	} else {
		return true;
	}
}

function sendData() {
	var data = $('#datasend').val();
	if(data === "") {
		bootbox.alert('Insert a message to send on the DataChannel');
		return;
	}
	echotest.data({
		text: data,
		error: function(reason) { bootbox.alert(reason); },
		success: function() { $('#datasend').val(''); },
	});
}

// Helper to parse query string
function getQueryStringValue(name) {
	name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
	var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
		results = regex.exec(location.search);
	return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

// Helpers to create Simulcast-related UI, if enabled
function addSimulcastButtons(temporal) {
	$('#curres').parent().append(
		'<div id="simulcast" class="btn-group-vertical btn-group-vertical-xs pull-right">' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs" style="width: 100%">' +
		'			<button id="sl-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to higher quality" style="width: 33%">SL 2</button>' +
		'			<button id="sl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to normal quality" style="width: 33%">SL 1</button>' +
		'			<button id="sl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to lower quality" style="width: 34%">SL 0</button>' +
		'		</div>' +
		'	</div>' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs hide" style="width: 100%">' +
		'			<button id="tl-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 2" style="width: 34%">TL 2</button>' +
		'			<button id="tl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 1" style="width: 33%">TL 1</button>' +
		'			<button id="tl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 0" style="width: 33%">TL 0</button>' +
		'		</div>' +
		'	</div>' +
		'</div>');
	// Enable the simulcast selection buttons
	$('#sl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching simulcast substream, wait for it... (lower quality)", null, {timeOut: 2000});
			if(!$('#sl-2').hasClass('btn-success'))
				$('#sl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#sl-1').hasClass('btn-success'))
				$('#sl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			echotest.send({ message: { substream: 0 }});
		});
	$('#sl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching simulcast substream, wait for it... (normal quality)", null, {timeOut: 2000});
			if(!$('#sl-2').hasClass('btn-success'))
				$('#sl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#sl-0').hasClass('btn-success'))
				$('#sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			echotest.send({ message: { substream: 1 }});
		});
	$('#sl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching simulcast substream, wait for it... (higher quality)", null, {timeOut: 2000});
			$('#sl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#sl-1').hasClass('btn-success'))
				$('#sl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#sl-0').hasClass('btn-success'))
				$('#sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			echotest.send({ message: { substream: 2 }});
		});
	if(!temporal)	// No temporal layer support
		return;
	$('#tl-0').parent().removeClass('hide');
	$('#tl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping simulcast temporal layer, wait for it... (lowest FPS)", null, {timeOut: 2000});
			if(!$('#tl-2').hasClass('btn-success'))
				$('#tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#tl-1').hasClass('btn-success'))
				$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			echotest.send({ message: { temporal: 0 }});
		});
	$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping simulcast temporal layer, wait for it... (medium FPS)", null, {timeOut: 2000});
			if(!$('#tl-2').hasClass('btn-success'))
				$('#tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-info');
			if(!$('#tl-0').hasClass('btn-success'))
				$('#tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			echotest.send({ message: { temporal: 1 }});
		});
	$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping simulcast temporal layer, wait for it... (highest FPS)", null, {timeOut: 2000});
			$('#tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#tl-1').hasClass('btn-success'))
				$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#tl-0').hasClass('btn-success'))
				$('#tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			echotest.send({ message: { temporal: 2 }});
		});
}

function updateSimulcastButtons(substream, temporal) {
	// Check the substream
	if(substream === 0) {
		toastr.success("Switched simulcast substream! (lower quality)", null, {timeOut: 2000});
		$('#sl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(substream === 1) {
		toastr.success("Switched simulcast substream! (normal quality)", null, {timeOut: 2000});
		$('#sl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#sl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(substream === 2) {
		toastr.success("Switched simulcast substream! (higher quality)", null, {timeOut: 2000});
		$('#sl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#sl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
	// Check the temporal layer
	if(temporal === 0) {
		toastr.success("Capped simulcast temporal layer! (lowest FPS)", null, {timeOut: 2000});
		$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(temporal === 1) {
		toastr.success("Capped simulcast temporal layer! (medium FPS)", null, {timeOut: 2000});
		$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(temporal === 2) {
		toastr.success("Capped simulcast temporal layer! (highest FPS)", null, {timeOut: 2000});
		$('#tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
}
