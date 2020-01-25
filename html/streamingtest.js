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
var streaming = null;
var opaqueId = "streamingtest-"+Janus.randomString(12);

var bitrateTimer = null;
var spinner = null;

var simulcastStarted = false, svcStarted = false;

var selectedStream = null;


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
						// Attach to Streaming plugin
						janus.attach(
							{
								plugin: "janus.plugin.streaming",
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									streaming = pluginHandle;
									Janus.log("Plugin attached! (" + streaming.getPlugin() + ", id=" + streaming.getId() + ")");
									// Setup streaming session
									$('#update-streams').click(updateStreamsList);
									updateStreamsList();
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											clearInterval(bitrateTimer);
											janus.destroy();
											$('#streamslist').attr('disabled', true);
											$('#watch').attr('disabled', true).unbind('click');
											$('#start').attr('disabled', true).html("Bye").unbind('click');
										});
								},
								error: function(error) {
									Janus.error("  -- Error attaching plugin... ", error);
									bootbox.alert("Error attaching plugin... " + error);
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::");
									Janus.debug(msg);
									var result = msg["result"];
									if(result !== null && result !== undefined) {
										if(result["status"] !== undefined && result["status"] !== null) {
											var status = result["status"];
											if(status === 'starting')
												$('#status').removeClass('hide').text("Starting, please wait...").show();
											else if(status === 'started')
												$('#status').removeClass('hide').text("Started").show();
											else if(status === 'stopped')
												stopStream();
										} else if(msg["streaming"] === "event") {
											// Is simulcast in place?
											var substream = result["substream"];
											var temporal = result["temporal"];
											if((substream !== null && substream !== undefined) || (temporal !== null && temporal !== undefined)) {
												if(!simulcastStarted) {
													simulcastStarted = true;
													addSimulcastButtons(temporal !== null && temporal !== undefined);
												}
												// We just received notice that there's been a switch, update the buttons
												updateSimulcastButtons(substream, temporal);
											}
											// Is VP9/SVC in place?
											var spatial = result["spatial_layer"];
											temporal = result["temporal_layer"];
											if((spatial !== null && spatial !== undefined) || (temporal !== null && temporal !== undefined)) {
												if(!svcStarted) {
													svcStarted = true;
													addSvcButtons();
												}
												// We just received notice that there's been a switch, update the buttons
												updateSvcButtons(spatial, temporal);
											}
										}
									} else if(msg["error"] !== undefined && msg["error"] !== null) {
										bootbox.alert(msg["error"]);
										stopStream();
										return;
									}
									if(jsep !== undefined && jsep !== null) {
										Janus.debug("Handling SDP as well...");
										Janus.debug(jsep);
										// Offer from the plugin, let's answer
										streaming.createAnswer(
											{
												jsep: jsep,
												// We want recvonly audio/video and, if negotiated, datachannels
												media: { audioSend: false, videoSend: false, data: true },
												success: function(jsep) {
													Janus.debug("Got SDP!");
													Janus.debug(jsep);
													var body = { "request": "start" };
													streaming.send({"message": body, "jsep": jsep});
													$('#watch').html("Stop").removeAttr('disabled').click(stopStream);
												},
												error: function(error) {
													Janus.error("WebRTC error:", error);
													bootbox.alert("WebRTC error... " + JSON.stringify(error));
												}
											});
									}
								},
								onremotestream: function(stream) {
									Janus.debug(" ::: Got a remote stream :::");
									Janus.debug(stream);
									var addButtons = false;
									if($('#remotevideo').length === 0) {
										addButtons = true;
										$('#stream').append('<video class="rounded centered hide" id="remotevideo" width=320 height=240 autoplay playsinline/>');
										// Show the stream and hide the spinner when we get a playing event
										$("#remotevideo").bind("playing", function () {
											$('#waitingvideo').remove();
											if(this.videoWidth)
												$('#remotevideo').removeClass('hide').show();
											if(spinner !== null && spinner !== undefined)
												spinner.stop();
											spinner = null;
											var videoTracks = stream.getVideoTracks();
											if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0)
												return;
											var width = this.videoWidth;
											var height = this.videoHeight;
											$('#curres').removeClass('hide').text(width+'x'+height).show();
											if(Janus.webRTCAdapter.browserDetails.browser === "firefox") {
												// Firefox Stable has a bug: width and height are not immediately available after a playing
												setTimeout(function() {
													var width = $("#remotevideo").get(0).videoWidth;
													var height = $("#remotevideo").get(0).videoHeight;
													$('#curres').removeClass('hide').text(width+'x'+height).show();
												}, 2000);
											}
										});
									}
									Janus.attachMediaStream($('#remotevideo').get(0), stream);
									var videoTracks = stream.getVideoTracks();
									if(videoTracks === null || videoTracks === undefined || videoTracks.length === 0) {
										// No remote video
										$('#remotevideo').hide();
										if($('#stream .no-video-container').length === 0) {
											$('#stream').append(
												'<div class="no-video-container">' +
													'<i class="fa fa-video-camera fa-5 no-video-icon"></i>' +
													'<span class="no-video-text">No remote video available</span>' +
												'</div>');
										}
									} else {
										$('#stream .no-video-container').remove();
										$('#remotevideo').removeClass('hide').show();
									}
									if(!addButtons)
										return;
									if(videoTracks && videoTracks.length &&
											(Janus.webRTCAdapter.browserDetails.browser === "chrome" ||
												Janus.webRTCAdapter.browserDetails.browser === "firefox" ||
												Janus.webRTCAdapter.browserDetails.browser === "safari")) {
										$('#curbitrate').removeClass('hide').show();
										bitrateTimer = setInterval(function() {
											// Display updated bitrate, if supported
											var bitrate = streaming.getBitrate();
											//~ Janus.debug("Current bitrate is " + streaming.getBitrate());
											$('#curbitrate').text(bitrate);
											// Check if the resolution changed too
											var width = $("#remotevideo").get(0).videoWidth;
											var height = $("#remotevideo").get(0).videoHeight;
											if(width > 0 && height > 0)
												$('#curres').removeClass('hide').text(width+'x'+height).show();
										}, 1000);
									}
								},
								ondataopen: function(data) {
									Janus.log("The DataChannel is available!");
									$('#waitingvideo').remove();
									$('#stream').append(
										'<input class="form-control" type="text" id="datarecv" disabled></input>'
									);
									if(spinner !== null && spinner !== undefined)
										spinner.stop();
									spinner = null;
								},
								ondata: function(data) {
									Janus.debug("We got data from the DataChannel! " + data);
									$('#datarecv').val(data);
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									$('#waitingvideo').remove();
									$('#remotevideo').remove();
									$('#datarecv').remove();
									$('.no-video-container').remove();
									$('#bitrate').attr('disabled', true);
									$('#bitrateset').html('Bandwidth<span class="caret"></span>');
									$('#curbitrate').hide();
									if(bitrateTimer !== null && bitrateTimer !== undefined)
										clearInterval(bitrateTimer);
									bitrateTimer = null;
									$('#curres').hide();
									$('#simulcast').remove();
									simulcastStarted = false;
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

function updateStreamsList() {
	$('#update-streams').unbind('click').addClass('fa-spin');
	var body = { "request": "list" };
	Janus.debug("Sending message (" + JSON.stringify(body) + ")");
	streaming.send({"message": body, success: function(result) {
		setTimeout(function() {
			$('#update-streams').removeClass('fa-spin').click(updateStreamsList);
		}, 500);
		if(result === null || result === undefined) {
			bootbox.alert("Got no response to our query for available streams");
			return;
		}
		if(result["list"] !== undefined && result["list"] !== null) {
			$('#streams').removeClass('hide').show();
			$('#streamslist').empty();
			$('#watch').attr('disabled', true).unbind('click');
			var list = result["list"];
			Janus.log("Got a list of available streams");
			Janus.debug(list);
			for(var mp in list) {
				Janus.debug("  >> [" + list[mp]["id"] + "] " + list[mp]["description"] + " (" + list[mp]["type"] + ")");
				$('#streamslist').append("<li><a href='#' id='" + list[mp]["id"] + "'>" + list[mp]["description"] + " (" + list[mp]["type"] + ")" + "</a></li>");
			}
			$('#streamslist a').unbind('click').click(function() {
				selectedStream = $(this).attr("id");
				$('#streamset').html($(this).html()).parent().removeClass('open');
				return false;

			});
			$('#watch').removeAttr('disabled').unbind('click').click(startStream);
		}
	}});
}

function startStream() {
	Janus.log("Selected video id #" + selectedStream);
	if(selectedStream === undefined || selectedStream === null) {
		bootbox.alert("Select a stream from the list");
		return;
	}
	$('#streamset').attr('disabled', true);
	$('#streamslist').attr('disabled', true);
	$('#watch').attr('disabled', true).unbind('click');
	var body = { "request": "watch", id: parseInt(selectedStream) };
	streaming.send({"message": body});
	// No remote video yet
	$('#stream').append('<video class="rounded centered" id="waitingvideo" width=320 height=240 />');
	if(spinner == null) {
		var target = document.getElementById('stream');
		spinner = new Spinner({top:100}).spin(target);
	} else {
		spinner.spin();
	}
}

function stopStream() {
	$('#watch').attr('disabled', true).unbind('click');
	var body = { "request": "stop" };
	streaming.send({"message": body});
	streaming.hangup();
	$('#streamset').removeAttr('disabled');
	$('#streamslist').removeAttr('disabled');
	$('#watch').html("Watch or Listen").removeAttr('disabled').unbind('click').click(startStream);
	$('#status').empty().hide();
	$('#bitrate').attr('disabled', true);
	$('#bitrateset').html('Bandwidth<span class="caret"></span>');
	$('#curbitrate').hide();
	if(bitrateTimer !== null && bitrateTimer !== undefined)
		clearInterval(bitrateTimer);
	bitrateTimer = null;
	$('#curres').empty().hide();
	$('#simulcast').remove();
	simulcastStarted = false;
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
			streaming.send({message: { request: "configure", substream: 0 }});
		});
	$('#sl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching simulcast substream, wait for it... (normal quality)", null, {timeOut: 2000});
			if(!$('#sl-2').hasClass('btn-success'))
				$('#sl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#sl-0').hasClass('btn-success'))
				$('#sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({message: { request: "configure", substream: 1 }});
		});
	$('#sl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching simulcast substream, wait for it... (higher quality)", null, {timeOut: 2000});
			$('#sl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#sl-1').hasClass('btn-success'))
				$('#sl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#sl-0').hasClass('btn-success'))
				$('#sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({message: { request: "configure", substream: 2 }});
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
			streaming.send({message: { request: "configure", temporal: 0 }});
		});
	$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping simulcast temporal layer, wait for it... (medium FPS)", null, {timeOut: 2000});
			if(!$('#tl-2').hasClass('btn-success'))
				$('#tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-info');
			if(!$('#tl-0').hasClass('btn-success'))
				$('#tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({message: { request: "configure", temporal: 1 }});
		});
	$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping simulcast temporal layer, wait for it... (highest FPS)", null, {timeOut: 2000});
			$('#tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#tl-1').hasClass('btn-success'))
				$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#tl-0').hasClass('btn-success'))
				$('#tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({message: { request: "configure", temporal: 2 }});
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

// Helpers to create SVC-related UI for a new viewer
function addSvcButtons() {
	if($('#svc').length > 0)
		return;
	$('#curres').parent().append(
		'<div id="svc" class="btn-group-vertical btn-group-vertical-xs pull-right">' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs" style="width: 100%">' +
		'			<button id="sl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to normal resolution" style="width: 50%">SL 1</button>' +
		'			<button id="sl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Switch to low resolution" style="width: 50%">SL 0</button>' +
		'		</div>' +
		'	</div>' +
		'	<div class"row">' +
		'		<div class="btn-group btn-group-xs" style="width: 100%">' +
		'			<button id="tl-2" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 2 (high FPS)" style="width: 34%">TL 2</button>' +
		'			<button id="tl-1" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 1 (medium FPS)" style="width: 33%">TL 1</button>' +
		'			<button id="tl-0" type="button" class="btn btn-primary" data-toggle="tooltip" title="Cap to temporal layer 0 (low FPS)" style="width: 33%">TL 0</button>' +
		'		</div>' +
		'	</div>' +
		'</div>'
	);
	// Enable the VP8 simulcast selection buttons
	$('#sl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching SVC spatial layer, wait for it... (low resolution)", null, {timeOut: 2000});
			if(!$('#sl-1').hasClass('btn-success'))
				$('#sl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			streaming.send({message: { request: "configure", spatial_layer: 0 }});
		});
	$('#sl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Switching SVC spatial layer, wait for it... (normal resolution)", null, {timeOut: 2000});
			$('#sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#sl-0').hasClass('btn-success'))
				$('#sl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({message: { request: "configure", spatial_layer: 1 }});
		});
	$('#tl-0').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping SVC temporal layer, wait for it... (lowest FPS)", null, {timeOut: 2000});
			if(!$('#tl-2').hasClass('btn-success'))
				$('#tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#tl-1').hasClass('btn-success'))
				$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			streaming.send({message: { request: "configure", temporal_layer: 0 }});
		});
	$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping SVC temporal layer, wait for it... (medium FPS)", null, {timeOut: 2000});
			if(!$('#tl-2').hasClass('btn-success'))
				$('#tl-2').removeClass('btn-primary btn-info').addClass('btn-primary');
			$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-info');
			if(!$('#tl-0').hasClass('btn-success'))
				$('#tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({message: { request: "configure", temporal_layer: 1 }});
		});
	$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary')
		.unbind('click').click(function() {
			toastr.info("Capping SVC temporal layer, wait for it... (highest FPS)", null, {timeOut: 2000});
			$('#tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-info');
			if(!$('#tl-1').hasClass('btn-success'))
				$('#tl-1').removeClass('btn-primary btn-info').addClass('btn-primary');
			if(!$('#tl-0').hasClass('btn-success'))
				$('#tl-0').removeClass('btn-primary btn-info').addClass('btn-primary');
			streaming.send({message: { request: "configure", temporal_layer: 2 }});
		});
}

function updateSvcButtons(spatial, temporal) {
	// Check the spatial layer
	if(spatial === 0) {
		toastr.success("Switched SVC spatial layer! (lower resolution)", null, {timeOut: 2000});
		$('#sl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#sl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(spatial === 1) {
		toastr.success("Switched SVC spatial layer! (normal resolution)", null, {timeOut: 2000});
		$('#sl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#sl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
	// Check the temporal layer
	if(temporal === 0) {
		toastr.success("Capped SVC temporal layer! (lowest FPS)", null, {timeOut: 2000});
		$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-0').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
	} else if(temporal === 1) {
		toastr.success("Capped SVC temporal layer! (medium FPS)", null, {timeOut: 2000});
		$('#tl-2').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-1').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	} else if(temporal === 2) {
		toastr.success("Capped SVC temporal layer! (highest FPS)", null, {timeOut: 2000});
		$('#tl-2').removeClass('btn-primary btn-info btn-success').addClass('btn-success');
		$('#tl-1').removeClass('btn-primary btn-success').addClass('btn-primary');
		$('#tl-0').removeClass('btn-primary btn-success').addClass('btn-primary');
	}
}
