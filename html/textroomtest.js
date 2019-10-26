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
var textroom = null;
var opaqueId = "textroomtest-"+Janus.randomString(12);

var myroom = 1234;	// Demo room
var myusername = null;
var myid = null;
var participants = {}
var transactions = {}

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
						// Attach to text room plugin
						janus.attach(
							{
								plugin: "janus.plugin.textroom",
								opaqueId: opaqueId,
								success: function(pluginHandle) {
									$('#details').remove();
									textroom = pluginHandle;
									Janus.log("Plugin attached! (" + textroom.getPlugin() + ", id=" + textroom.getId() + ")");
									// Setup the DataChannel
									var body = { "request": "setup" };
									Janus.debug("Sending message (" + JSON.stringify(body) + ")");
									textroom.send({"message": body});
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											janus.destroy();
										});
								},
								error: function(error) {
									console.error("  -- Error attaching plugin...", error);
									bootbox.alert("Error attaching plugin... " + error);
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videoleft").parent().unblock();
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::");
									Janus.debug(msg);
									if(msg["error"] !== undefined && msg["error"] !== null) {
										bootbox.alert(msg["error"]);
									}
									if(jsep !== undefined && jsep !== null) {
										// Answer
										textroom.createAnswer(
											{
												jsep: jsep,
												media: { audio: false, video: false, data: true },	// We only use datachannels
												success: function(jsep) {
													Janus.debug("Got SDP!");
													Janus.debug(jsep);
													var body = { "request": "ack" };
													textroom.send({"message": body, "jsep": jsep});
												},
												error: function(error) {
													Janus.error("WebRTC error:", error);
													bootbox.alert("WebRTC error... " + JSON.stringify(error));
												}
											});
									}
								},
								ondataopen: function(data) {
									Janus.log("The DataChannel is available!");
									// Prompt for a display name to join the default room
									$('#roomjoin').removeClass('hide').show();
									$('#registernow').removeClass('hide').show();
									$('#register').click(registerUsername);
									$('#username').focus();
								},
								ondata: function(data) {
									Janus.debug("We got data from the DataChannel! " + data);
									//~ $('#datarecv').val(data);
									var json = JSON.parse(data);
									var transaction = json["transaction"];
									if(transactions[transaction]) {
										// Someone was waiting for this
										transactions[transaction](json);
										delete transactions[transaction];
										return;
									}
									var what = json["textroom"];
									if(what === "message") {
										// Incoming message: public or private?
										var msg = json["text"];
										msg = msg.replace(new RegExp('<', 'g'), '&lt');
										msg = msg.replace(new RegExp('>', 'g'), '&gt');
										var from = json["from"];
										var dateString = getDateString(json["date"]);
										var whisper = json["whisper"];
										if(whisper === true) {
											// Private message
											$('#chatroom').append('<p style="color: purple;">[' + dateString + '] <b>[whisper from ' + participants[from] + ']</b> ' + msg);
											$('#chatroom').get(0).scrollTop = $('#chatroom').get(0).scrollHeight;
										} else {
											// Public message
											$('#chatroom').append('<p>[' + dateString + '] <b>' + participants[from] + ':</b> ' + msg);
											$('#chatroom').get(0).scrollTop = $('#chatroom').get(0).scrollHeight;
										}
									} else if(what === "announcement") {
										// Room announcement
										var msg = json["text"];
										msg = msg.replace(new RegExp('<', 'g'), '&lt');
										msg = msg.replace(new RegExp('>', 'g'), '&gt');
										var dateString = getDateString(json["date"]);
										$('#chatroom').append('<p style="color: purple;">[' + dateString + '] <i>' + msg + '</i>');
										$('#chatroom').get(0).scrollTop = $('#chatroom').get(0).scrollHeight;
									} else if(what === "join") {
										// Somebody joined
										var username = json["username"];
										var display = json["display"];
										participants[username] = display ? display : username;
										if(username !== myid && $('#rp' + username).length === 0) {
											// Add to the participants list
											$('#list').append('<li id="rp' + username + '" class="list-group-item">' + participants[username] + '</li>');
											$('#rp' + username).css('cursor', 'pointer').click(function() {
												var username = $(this).attr('id').split("rp")[1];
												sendPrivateMsg(username);
											});
										}
										$('#chatroom').append('<p style="color: green;">[' + getDateString() + '] <i>' + participants[username] + ' joined</i></p>');
										$('#chatroom').get(0).scrollTop = $('#chatroom').get(0).scrollHeight;
									} else if(what === "leave") {
										// Somebody left
										var username = json["username"];
										var when = new Date();
										$('#rp' + username).remove();
										$('#chatroom').append('<p style="color: green;">[' + getDateString() + '] <i>' + participants[username] + ' left</i></p>');
										$('#chatroom').get(0).scrollTop = $('#chatroom').get(0).scrollHeight;
										delete participants[username];
									} else if(what === "kicked") {
										// Somebody was kicked
										var username = json["username"];
										var when = new Date();
										$('#rp' + username).remove();
										$('#chatroom').append('<p style="color: green;">[' + getDateString() + '] <i>' + participants[username] + ' was kicked from the room</i></p>');
										$('#chatroom').get(0).scrollTop = $('#chatroom').get(0).scrollHeight;
										delete participants[username];
										if(username === myid) {
											bootbox.alert("You have been kicked from the room", function() {
												window.location.reload();
											});
										}
									} else if(what === "destroyed") {
										if(json["room"] !== myroom)
											return;
										// Room was destroyed, goodbye!
										Janus.warn("The room has been destroyed!");
										bootbox.alert("The room has been destroyed", function() {
											window.location.reload();
										});
									}
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									$('#datasend').attr('disabled', true);
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
		if(field.id == 'username')
			registerUsername();
		else if(field.id == 'datasend')
			sendData();
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
		myid = randomString(12);
		var transaction = randomString(12);
		var register = {
			textroom: "join",
			transaction: transaction,
			room: myroom,
			username: myid,
			display: username
		};
		myusername = username;
		transactions[transaction] = function(response) {
			if(response["textroom"] === "error") {
				// Something went wrong
				if(response["error_code"] === 417) {
					// This is a "no such room" error: give a more meaningful description
					bootbox.alert(
						"<p>Apparently room <code>" + myroom + "</code> (the one this demo uses as a test room) " +
						"does not exist...</p><p>Do you have an updated <code>janus.plugin.textroom.jcfg</code> " +
						"configuration file? If not, make sure you copy the details of room <code>" + myroom + "</code> " +
						"from that sample in your current configuration file, then restart Janus and try again."
					);
				} else {
					bootbox.alert(response["error"]);
				}
				$('#username').removeAttr('disabled').val("");
				$('#register').removeAttr('disabled').click(registerUsername);
				return;
			}
			// We're in
			$('#roomjoin').hide();
			$('#room').removeClass('hide').show();
			$('#participant').removeClass('hide').html(myusername).show();
			$('#chatroom').css('height', ($(window).height()-420)+"px");
			$('#datasend').removeAttr('disabled');
			// Any participants already in?
			console.log("Participants:", response.participants);
			if(response.participants && response.participants.length > 0) {
				for(var i in response.participants) {
					var p = response.participants[i];
					participants[p.username] = p.display ? p.display : p.username;
					if(p.username !== myid && $('#rp' + p.username).length === 0) {
						// Add to the participants list
						$('#list').append('<li id="rp' + p.username + '" class="list-group-item">' + participants[p.username] + '</li>');
						$('#rp' + p.username).css('cursor', 'pointer').click(function() {
							var username = $(this).attr('id').split("rp")[1];
							sendPrivateMsg(username);
						});
					}
					$('#chatroom').append('<p style="color: green;">[' + getDateString() + '] <i>' + participants[p.username] + ' joined</i></p>');
					$('#chatroom').get(0).scrollTop = $('#chatroom').get(0).scrollHeight;
				}
			}
		};
		textroom.data({
			text: JSON.stringify(register),
			error: function(reason) {
				bootbox.alert(reason);
				$('#username').removeAttr('disabled').val("");
				$('#register').removeAttr('disabled').click(registerUsername);
			}
		});
	}
}

function sendPrivateMsg(username) {
	var display = participants[username];
	if(!display)
		return;
	bootbox.prompt("Private message to " + display, function(result) {
		if(result && result !== "") {
			var message = {
				textroom: "message",
				transaction: randomString(12),
				room: myroom,
				to: username,
				text: result
			};
			textroom.data({
				text: JSON.stringify(message),
				error: function(reason) { bootbox.alert(reason); },
				success: function() {
					$('#chatroom').append('<p style="color: purple;">[' + getDateString() + '] <b>[whisper to ' + display + ']</b> ' + result);
					$('#chatroom').get(0).scrollTop = $('#chatroom').get(0).scrollHeight;
				}
			});
		}
	});
	return;
}

function sendData() {
	var data = $('#datasend').val();
	if(data === "") {
		bootbox.alert('Insert a message to send on the DataChannel');
		return;
	}
	var message = {
		textroom: "message",
		transaction: randomString(12),
		room: myroom,
 		text: data,
	};
	// Note: messages are always acknowledged by default. This means that you'll
	// always receive a confirmation back that the message has been received by the
	// server and forwarded to the recipients. If you do not want this to happen,
	// just add an ack:false property to the message above, and server won't send
	// you a response (meaning you just have to hope it succeeded).
	textroom.data({
		text: JSON.stringify(message),
		error: function(reason) { bootbox.alert(reason); },
		success: function() { $('#datasend').val(''); }
	});
}

// Helper to format times
function getDateString(jsonDate) {
	var when = new Date();
	if(jsonDate) {
		when = new Date(Date.parse(jsonDate));
	}
	var dateString =
			("0" + when.getUTCHours()).slice(-2) + ":" +
			("0" + when.getUTCMinutes()).slice(-2) + ":" +
			("0" + when.getUTCSeconds()).slice(-2);
	return dateString;
}

// Just an helper to generate random usernames
function randomString(len, charSet) {
    charSet = charSet || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var randomString = '';
    for (var i = 0; i < len; i++) {
    	var randomPoz = Math.floor(Math.random() * charSet.length);
    	randomString += charSet.substring(randomPoz,randomPoz+1);
    }
    return randomString;
}
