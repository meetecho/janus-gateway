//
// This 'server' variable we use to contact the Admin/Monitor backend is
// constructed in this example pretty much as we do in all the demos, so
// refer to the guidelines there with respect to absolute vs. relative
// paths and the like.
//
var server = null;
if(window.location.protocol === 'http:')
	server = "http://" + window.location.hostname + ":7088/admin";
else
	server = "https://" + window.location.hostname + ":7889/admin";
var secret = "janusoverlord";	// This is what you configured in janus.cfg

var session = null;		// Selected session
var handle = null;		// Selected handle

$(document).ready(function() {
	if(typeof console == "undefined" || typeof console.log == "undefined")
		console = { log: function() {} };
	$('#handles').hide();
	$('#info').hide();
	$('#update-sessions').click(updateSessions);
	$('#update-handles').click(updateHandles);
	$('#update-handle').click(updateHandleInfo);
	updateSessions();
});

// Helper method to create random identifiers (e.g., transaction)
function randomString(len) {
	charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	var randomString = '';
	for (var i = 0; i < len; i++) {
		var randomPoz = Math.floor(Math.random() * charSet.length);
		randomString += charSet.substring(randomPoz,randomPoz+1);
	}
	return randomString;
}

function updateSessions() {
	$('#update-sessions').unbind('click').addClass('fa-spin');
	$('#update-handles').unbind('click');
	$('#update-handle').unbind('click');
	var request = { "janus": "list_sessions", "transaction": randomString(12), "admin_secret": secret };
	$.ajax({
		type: 'POST',
		url: server,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				bootbox.alert(json["error"].reason);
				setTimeout(function() {
					$('#update-sessions').removeClass('fa-spin').click(updateSessions);
					$('#update-handles').click(updateHandles);
					$('#update-handle').click(updateHandleInfo);
				}, 1000);
				session = null;
				handle = null;
				$('#handles-list').empty();
				$('#handles').hide();
				$('#handle-info').empty();
				$('#info').hide();
				return;
			}
			console.log("Got sessions:");
			console.log(json);
			$('#sessions-list').empty();
			var sessions = json["sessions"];
			$('#sessions-num').text(sessions.length);
			for(var i=0; i<sessions.length; i++) {
				var s = sessions[i];
				$('#sessions-list').append(
					'<a id="session-'+s+'" href="#" class="list-group-item">'+s+'</a>'
				);
				$('#session-'+s).click(function() {
					var sh = $(this).text();
					console.log("Getting session " + sh + " handles");
					session = sh;
					$('#sessions-list a').removeClass('active');
					$('#session-'+sh).addClass('active');
					handle = null;
					$('#handles-list').empty();
					$('#handles').show();
					$('#handle-info').empty();
					$('#info').hide();
					updateHandles();
				});
			}
			if(session !== null && session !== undefined) {
				if($('#session-'+session).length) {
					$('#session-'+session).addClass('active');
				} else {
					// The session that was selected has disappeared
					session = null;
					handle = null;
					$('#handles-list').empty();
					$('#handles').hide();
					$('#handle-info').empty();
					$('#info').hide();
				}
			}
			setTimeout(function() {
				$('#update-sessions').removeClass('fa-spin').click(updateSessions);
				$('#update-handles').click(updateHandles);
				$('#update-handle').click(updateHandleInfo);
			}, 1000);
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?");
			setTimeout(function() {
				$('#update-sessions').removeClass('fa-spin').click(updateSessions);
				$('#update-handles').click(updateHandles);
				$('#update-handle').click(updateHandleInfo);
			}, 1000);
			session = null;
			handle = null;
			$('#handles-list').empty();
			$('#handles').hide();
			$('#handle-info').empty();
			$('#info').hide();
		},
		dataType: "json"
	});
}

function updateHandles() {
	if(session === null || session === undefined)
		return;
	$('#update-sessions').unbind('click');
	$('#update-handles').unbind('click').addClass('fa-spin');
	$('#update-handle').unbind('click');
	var request = { "janus": "list_handles", "transaction": randomString(12), "admin_secret": secret };
	$.ajax({
		type: 'POST',
		url: server + "/" + session,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				bootbox.alert(json["error"].reason);
				setTimeout(function() {
					$('#update-handles').removeClass('fa-spin').click(updateHandles);
					$('#update-sessions').click(updateSessions);
					$('#update-handle').click(updateHandleInfo);
				}, 1000);
				return;
			}
			console.log("Got handles:");
			console.log(json);
			$('#handles-list').empty();
			var handles = json["handles"];
			$('#handles-num').text(handles.length);
			for(var i=0; i<handles.length; i++) {
				var h = handles[i];
				$('#handles-list').append(
					'<a id="handle-'+h+'" href="#" class="list-group-item">'+h+'</a>'
				);
				$('#handle-'+h).click(function() {
					var hi = $(this).text();
					console.log("Getting handle " + hi + " info");
					handle = hi;
					$('#handles-list a').removeClass('active');
					$('#handle-'+hi).addClass('active');
					$('#handle-info').empty();
					$('#info').show();
					updateHandleInfo();
				});
			}
			if(handle !== null && handle !== undefined) {
				if($('#handle-'+handle).length) {
					$('#handle-'+handle).addClass('active');
				} else {
					// The handle that was selected has disappeared
					handle = null;
					$('#handle-info').empty();
					$('#info').hide();
				}
			}
			setTimeout(function() {
				$('#update-handles').removeClass('fa-spin').click(updateHandles);
				$('#update-sessions').click(updateSessions);
				$('#update-handle').click(updateHandleInfo);
			}, 1000);
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled/inaccessible?");
			$('#update-handles').removeClass('fa-spin').click(updateHandles);
			$('#update-sessions').click(updateSessions);
			$('#update-handle').click(updateHandleInfo);
		},
		dataType: "json"
	});
}

function updateHandleInfo() {
	if(handle === null || handle === undefined)
		return;
	$('#update-sessions').unbind('click');
	$('#update-handles').unbind('click');
	$('#update-handle').unbind('click').addClass('fa-spin');
	var request = { "janus": "handle_info", "transaction": randomString(12), "admin_secret": secret };
	$.ajax({
		type: 'POST',
		url: server + "/" + session + "/" + handle,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				bootbox.alert(json["error"].reason);
				setTimeout(function() {
					$('#update-sessions').click(updateSessions);
					$('#update-handles').click(updateHandles);
					$('#update-handle').removeClass('fa-spin').click(updateHandleInfo);
				}, 1000);
				return;
			}
			console.log("Got info:");
			console.log(json);
			$('#handle-info').text(JSON.stringify(json["info"], null, 4));
			setTimeout(function() {
				$('#update-sessions').click(updateSessions);
				$('#update-handles').click(updateHandles);
				$('#update-handle').removeClass('fa-spin').click(updateHandleInfo);
			}, 1000);
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?");
			$('#update-handles').removeClass('fa-spin').click(updateHandles);
			$('#update-sessions').click(updateSessions);
			$('#update-handle').click(updateHandleInfo);
		},
		dataType: "json"
	});
}
