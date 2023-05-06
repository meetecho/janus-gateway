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
// If you don't want the page to prompt you for a password, insert it here
var secret = "";

var session = null;		// Selected session
var handle = null;		// Selected handle

var plugins = [], pluginsIndex = [], pluginRows = 0;
var transports = [], transportsIndex = [], transportRows = 0;
var settings = {};

var currentHandle = null;
var localSdp = null, remoteSdp = null;

var handleInfo;

$(document).ready(function() {
	$('#admintabs a').click(function (e) {
		e.preventDefault()
		$(this).tab('show')
	});
	if(!server)
		server = "";
	if(!secret)
		secret = "";
	if(server !== "" && secret !== "") {
		updateServerInfo();
	} else {
		promptAccessDetails();
	}
});

var prompting = false;
var alerted = false;
function promptAccessDetails() {
	if(prompting)
		return;
	prompting = true;
	let serverPlaceholder = "Insert the address of the Admin API backend";
	let secretPlaceholder = "Insert the Admin API secret";
	bootbox.alert({
		message: "<div class='input-group margin-bottom-sm'>" +
			"	<span class='input-group-addon'><i class='fa fa-cloud-upload fa-fw'></i></span>" +
			"	<input class='form-control' type='text' value='" + server + "' placeholder='" + serverPlaceholder + "' autocomplete='off' id='server'></input>" +
			"</div>" +
			"<div class='input-group margin-bottom-sm'>" +
			"	<span class='input-group-addon'><i class='fa fa-key fa-fw'></i></span>" +
			"	<input class='form-control' type='password'  value='" + secret + "'placeholder='" + secretPlaceholder + "' autocomplete='off' id='secret'></input>" +
			"</div>",
		closeButton: false,
		callback: function() {
			prompting = false;
			server = $('#server').val();
			secret = $('#secret').val();
			updateServerInfo();
		}
	});
}

// Helper method to create random identifiers (e.g., transaction)
function randomString(len) {
	const charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	let randomString = '';
	for (let i = 0; i < len; i++) {
		let randomPoz = Math.floor(Math.random() * charSet.length);
		randomString += charSet.substring(randomPoz,randomPoz+1);
	}
	return randomString;
}

// Server info
function updateServerInfo() {
	plugins = [];
	pluginsIndex = [];
	transports = [];
	transportsIndex = [];
	$.ajax({
		type: 'GET',
		url: server + "/info",
		cache: false,
		contentType: "application/json",
		success: function(json) {
			if(json["janus"] !== "server_info") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				if(!prompting && !alerted) {
					alerted = true;
					bootbox.alert(json["error"].reason, function() {
						promptAccessDetails();
						alerted = false;
					});
				}
				return;
			}
			console.log("Got server info:");
			console.log(json);
			var pluginsJson = json.plugins;
			let transportsJson = json.transports;
			let eventsJson = json.events;
			delete json.janus;
			delete json.transaction;
			delete json.plugins;
			delete json.transports;
			delete json.events;
			$('#server-details').empty();
			for(let k in json) {
				if(k === "dependencies") {
					$('#server-deps').html(
						'<tr>' +
						'	<th>Library</th>' +
						'	<th>Version</th>' +
						'</tr>'
					);
					for(let ln in json[k]) {
						$('#server-deps').append(
							'<tr>' +
							'	<td>' + ln + '</td>' +
							'	<td>' + json[k][ln] + '</td>' +
							'</tr>'
						);
					}
					continue;
				}
				let v = json[k];
				$('#server-details').append(
					'<tr>' +
					'	<td><b>' + k + ':</b></td>' +
					'	<td>' + v + '</td>' +
					'</tr>');
			}
			$('#server-plugins').html(
				'<tr>' +
				'	<th>Name</th>' +
				'	<th>Author</th>' +
				'	<th>Description</th>' +
				'	<th>Version</th>' +
				'</tr>'
			);
			$('#plugins-list').empty();
			for(let p in pluginsJson) {
				plugins.push(p);
				let v = pluginsJson[p];
				$('#server-plugins').append(
					'<tr>' +
					'	<td>' + v.name + '</td>' +
					'	<td>' + v.author + '</td>' +
					'	<td>' + v.description + '</td>' +
					'	<td>' + v.version_string + '</td>' +
					'</tr>');
				pluginsIndex.push(p);
				$('#plugins-list').append(
					'<a id="plugin-'+(pluginsIndex.length-1)+'" href="#" class="list-group-item">'+p+'</a>'
				);
				$('#plugin-'+(pluginsIndex.length-1)).click(function(event) {
					event.preventDefault();
					let pi = parseInt($(this).attr('id').split('plugin-')[1]);
					let plugin = pluginsIndex[pi];
					console.log("Selected plugin:", plugin);
					$('#plugins-list a').removeClass('active');
					$('#plugin-'+pi).addClass('active');
					resetPluginRequest();
				});
			}
			$('#server-transports').html(
				'<tr>' +
				'	<th>Name</th>' +
				'	<th>Author</th>' +
				'	<th>Description</th>' +
				'	<th>Version</th>' +
				'</tr>'
			);
			for(let t in transportsJson) {
				transports.push(t);
				let v = transportsJson[t];
				$('#server-transports').append(
					'<tr>' +
					'	<td>' + v.name + '</td>' +
					'	<td>' + v.author + '</td>' +
					'	<td>' + v.description + '</td>' +
					'	<td>' + v.version_string + '</td>' +
					'</tr>');
				transportsIndex.push(t);
				$('#transports-list').append(
					'<a id="transport-'+(transportsIndex.length-1)+'" href="#" class="list-group-item">'+t+'</a>'
				);
				$('#transport-'+(transportsIndex.length-1)).click(function(event) {
					event.preventDefault();
					let ti = parseInt($(this).attr('id').split('transport-')[1]);
					let transport = transportsIndex[ti];
					console.log("Selected transport:", transport);
					$('#transports-list a').removeClass('active');
					$('#transport-'+ti).addClass('active');
					resetTransportRequest();
				});
			}
			$('#server-handlers').html(
				'<tr>' +
				'	<th>Name</th>' +
				'	<th>Author</th>' +
				'	<th>Description</th>' +
				'	<th>Version</th>' +
				'</tr>'
			);
			for(let e in eventsJson) {
				let v = eventsJson[e];
				$('#server-handlers').append(
					'<tr>' +
					'	<td>' + v.name + '</td>' +
					'	<td>' + v.author + '</td>' +
					'	<td>' + v.description + '</td>' +
					'	<td>' + v.version_string + '</td>' +
					'</tr>');
			}
			// Unlock tabs
			$('#admintabs li').removeClass('disabled');
			// Refresh settings now
			updateSettings();
			// Refresh sessions and handles now
			$('#handles').hide();
			$('#info').hide();
			$('#update-sessions').click(updateSessions);
			$('#update-handles').click(updateHandles);
			$('#update-handle').click(updateHandleInfo);
			updateSessions();
			$("#autorefresh").change(function() {
				if(this.checked) {
					updateHandleInfo(true);
				}
			});
			$("#prettify").change(function() {
				if(this.checked) {
					prettyHandleInfo();
				} else {
					rawHandleInfo();
				}
			});
			$("#capture").change(function() {
				if(this.checked) {
					// We're trying to start a new capture, show a dialog
					$('#capturetext').html('Stop capture');
					captureTrafficPrompt();
				} else {
					// We're trying to stop a capture
					$('#capturetext').html('Start capture');
					captureTrafficRequest(false, handleInfo["dump-to-text2pcap"] === true);
				}
			});
			// Only check tokens if the mechanism is enabled
			if(!json["auth_token"]) {
				$('a[href=#tokens]').parent().addClass('disabled');
				$('a[href=#tokens]').attr('href', '#').unbind('click').click(function (e) { e.preventDefault(); return false; });
			} else {
				updateTokens();
			}
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}

// Settings
function updateSettings() {
	$('#update-settings').unbind('click').addClass('fa-spin');
	let request = { "janus": "get_status", "transaction": randomString(12), "admin_secret": secret };
	$.ajax({
		type: 'POST',
		url: server,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				let authenticate = (json["error"].code === 403);
				if(!authenticate || (authenticate && !prompting && !alerted)) {
					if(authenticate)
						alerted = true;
					bootbox.alert(json["error"].reason, function() {
						if(authenticate) {
							promptAccessDetails();
							alerted = false;
						}
					});
				}
				setTimeout(function() {
					$('#update-settings').removeClass('fa-spin').click(updateSettings);
				}, 1000);
				return;
			}
			console.log("Got status:");
			console.log(json);
			setTimeout(function() {
				$('#update-settings').removeClass('fa-spin').click(updateSettings);
			}, 1000);
			$('#server-settings').empty();
			for(let k in json.status) {
				settings[k] = json.status[k];
				$('#server-settings').append(
					'<tr>' +
					'	<td><b>' + k + ':</b></td>' +
					'	<td>' + settings[k] + '</td>' +
					'	<td id="' + k + '"></td>' +
					'</tr>');
				if(k === 'session_timeout') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs btn-primary">Edit session timeout value</button>');
					$('#'+k + "_button").click(function() {
						bootbox.prompt("Set the new session timeout value (in seconds, currently " + settings["session_timeout"] + ")", function(result) {
							if(isNaN(result)) {
								bootbox.alert("Invalid session timeout value");
								return;
							}
							result = parseInt(result);
							if(result < 0) {
								console.log(isNaN(result));
								console.log(result < 0);
								bootbox.alert("Invalid session timeout value");
								return;
							}
							setSessionTimeoutValue(result);
						});
					});
				} else if(k === 'log_level') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs btn-primary">Edit log level</button>');
					$('#'+k + "_button").click(function() {
						bootbox.prompt("Set the new desired log level (0-7, currently " + settings["log_level"] + ")", function(result) {
							if(isNaN(result)) {
								bootbox.alert("Invalid log level (should be [0,7])");
								return;
							}
							result = parseInt(result);
							if(result < 0 || result > 7) {
								console.log(isNaN(result));
								console.log(result < 0);
								console.log(result > 7);
								bootbox.alert("Invalid log level (should be [0,7])");
								return;
							}
							setLogLevel(result);
						});
					});
				} else if(k === 'min_nack_queue') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs btn-primary">Edit min NACK queue</button>');
					$('#'+k + "_button").click(function() {
						bootbox.prompt("Set the new desired min NACK queue (a positive integer, currently " + settings["min_nack_queue"] + ")", function(result) {
							if(isNaN(result)) {
								bootbox.alert("Invalid min NACK queue (should be a positive integer)");
								return;
							}
							result = parseInt(result);
							if(result < 0) {
								bootbox.alert("Invalid min NACK queue (should be a positive integer)");
								return;
							}
							setMinNackQueue(result);
						});
					});
				} else if(k === 'no_media_timer') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs btn-primary">Edit no-media timer value</button>');
					$('#'+k + "_button").click(function() {
						bootbox.prompt("Set the new desired no-media timer value (in seconds, currently " + settings["no_media_timer"] + ")", function(result) {
							if(isNaN(result)) {
								bootbox.alert("Invalid no-media timer (should be a positive integer)");
								return;
							}
							result = parseInt(result);
							if(result < 0) {
								bootbox.alert("Invalid no-media timer (should be a positive integer)");
								return;
							}
							setNoMediaTimer(result);
						});
					});
				} else if(k === 'slowlink_threshold') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs btn-primary">Edit slowlink-threshold value</button>');
					$('#'+k + "_button").click(function() {
						bootbox.prompt("Set the new desired slowlink-threshold value (in lost packets per seconds, currently " + settings["slowlink_threshold"] + ")", function(result) {
							if(isNaN(result)) {
								bootbox.alert("Invalid slowlink-threshold timer (should be a positive integer)");
								return;
							}
							result = parseInt(result);
							if(result < 0) {
								bootbox.alert("Invalid slowlink-threshold timer (should be a positive integer)");
								return;
							}
							setSlowlinkThreshold(result);
						});
					});
				} else if(k === 'locking_debug') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs"></button>');
					$('#'+k + "_button")
						.addClass(!settings[k] ? "btn-success" : "btn-danger")
						.html(!settings[k] ? "Enable locking debug" : "Disable locking debug");
					$('#'+k + "_button").click(function() {
						let text = (!settings["locking_debug"] ?
							"Are you sure you want to enable the locking debug?<br/>This will print a line on the console any time a mutex is locked/unlocked"
							: "Are you sure you want to disable the locking debug?");
						bootbox.confirm(text, function(result) {
							if(result)
								setLockingDebug(!settings["locking_debug"]);
						});
					});
				} else if(k === 'refcount_debug') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs"></button>');
					$('#'+k + "_button")
						.addClass(!settings[k] ? "btn-success" : "btn-danger")
						.html(!settings[k] ? "Enable reference counters debug" : "Disable reference counters debug");
					$('#'+k + "_button").click(function() {
						let text = (!settings["refcount_debug"] ?
							"Are you sure you want to enable the reference counters debug?<br/>This will print a line on the console any time a reference counter is increased/decreased"
							: "Are you sure you want to disable the reference counters debug?");
						bootbox.confirm(text, function(result) {
							if(result)
								setRefcountDebug(!settings["refcount_debug"]);
						});
					});
				} else if(k === 'log_timestamps') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs"></button>');
					$('#'+k + "_button")
						.addClass(!settings[k] ? "btn-success" : "btn-danger")
						.html(!settings[k] ? "Enable log timestamps" : "Disable log timestamps");
					$('#'+k + "_button").click(function() {
						let text = (!settings["log_timestamps"] ?
							"Are you sure you want to enable the log timestamps?<br/>This will print the current date/time for each new line on the console"
							: "Are you sure you want to disable the log timestamps?");
						bootbox.confirm(text, function(result) {
							if(result)
								setLogTimestamps(!settings["log_timestamps"]);
						});
					});
				} else if(k === 'log_colors') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs"></button>');
					$('#'+k + "_button")
						.addClass(!settings[k] ? "btn-success" : "btn-danger")
						.html(!settings[k] ? "Enable log colors" : "Disable log colors");
					$('#'+k + "_button").click(function() {
						let text = (!settings["log_colors"] ?
							"Are you sure you want to enable the log colors?<br/>This will strip the colors from events like warnings, errors, etc. on the console"
							: "Are you sure you want to disable the log colors?");
						bootbox.confirm(text, function(result) {
							if(result)
								setLogColors(!settings["log_colors"]);
						});
					});
				} else if(k === 'libnice_debug') {
					$('#'+k).append('<button id="' + k + '_button" type="button" class="btn btn-xs"></button>');
					$('#'+k + "_button")
						.addClass(!settings[k] ? "btn-success" : "btn-danger")
						.html(!settings[k] ? "Enable libnice debug" : "Disable libnice debug");
					$('#'+k + "_button").click(function() {
						let text = (!settings["libnice_debug"] ?
							"Are you sure you want to enable the libnice debug?<br/>This will print the a very verbose debug of every libnice-related operation on the console"
							: "Are you sure you want to disable the libnice debug?");
						bootbox.confirm(text, function(result) {
							if(result)
								setLibniceDebug(!settings["libnice_debug"]);
						});
					});
				}
			}
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			$('#update-settings').removeClass('fa-spin').click(updateSettings);
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}

function setSessionTimeoutValue(timeout) {
	let request = { "janus": "set_session_timeout", "timeout": timeout, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function setLogLevel(level) {
	let request = { "janus": "set_log_level", "level": level, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function setLockingDebug(enable) {
	let request = { "janus": "set_locking_debug", "debug": enable, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function setRefcountDebug(enable) {
	let request = { "janus": "set_refcount_debug", "debug": enable, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function setLogTimestamps(enable) {
	let request = { "janus": "set_log_timestamps", "timestamps": enable, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function setLogColors(enable) {
	let request = { "janus": "set_log_colors", "colors": enable, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function setLibniceDebug(enable) {
	let request = { "janus": "set_libnice_debug", "debug": enable, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function setMinNackQueue(queue) {
	let request = { "janus": "set_min_nack_queue", "min_nack_queue": queue, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function setNoMediaTimer(timer) {
	let request = { "janus": "set_no_media_timer", "no_media_timer": timer, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function setSlowlinkThreshold(packets) {
	let request = { "janus": "set_slowlink_threshold", "slowlink_threshold": packets, "transaction": randomString(12), "admin_secret": secret };
	sendSettingsRequest(request);
}

function sendSettingsRequest(request) {
	console.log(request);
	$.ajax({
		type: 'POST',
		url: server,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				let authenticate = (json["error"].code === 403);
				if(!authenticate || (authenticate && !prompting && !alerted)) {
					if(authenticate)
						alerted = true;
					bootbox.alert(json["error"].reason, function() {
						if(authenticate) {
							promptAccessDetails();
							alerted = false;
						}
					});
				}
				return;
			}
			updateSettings();
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}

// Plugins
function resetPluginRequest() {
	pluginRows = 0;
	$('#plugin-request').empty().append(
		'<tr style="background: #f9f9f9;">' +
		'	<th width="25%">Name</th>' +
		'	<th width="25%">Value</th>' +
		'	<th width="25%">Type</th>' +
		'	<th></th>' +
		'</tr>' +
		'<tr>' +
		'	<td><i id="addattr" class="fa fa-plus-circle" style="cursor: pointer;"></i></td>' +
		'	<td></td>' +
		'	<td></td>' +
		'	<td><button id="sendmsg" type="button" class="btn btn-xs btn-success pull-right">Send message</button></td>' +
		'</tr>');
	$('#addattr').click(addPluginMessageAttribute).click();
	$('#sendmsg').click(function() {
		let message = {};
		let index = 0;
		for(let i=0; i<=pluginRows; i++) {
			if($('#attrname'+i).length === 0)
				continue;
			index++;
			let name = $('#attrname'+i).val();
			if(name === '') {
				bootbox.alert("Missing name in attribute #" + index);
				return;
			}
			if(message[name] !== null && message[name] !== undefined) {
				bootbox.alert("Duplicate attribute '" + name + "'");
				return;
			}
			let value = $('#attrvalue'+i).val();
			if(value === '') {
				bootbox.alert("Missing value in attribute #" + index);
				return;
			}
			let type = $('#attrtype'+i).val();
			if(type === "number") {
				value = parseInt(value);
				if(isNaN(value)) {
					bootbox.alert("Invalid value in attribute #" + index + " (expecting a number)");
					return;
				}
			} else if(type === "boolean") {
				if(value.toLowerCase() === "true") {
					value = true;
				} else if(value.toLowerCase() === "false") {
					value = false;
				} else {
					bootbox.alert("Invalid value in attribute #" + index + " (expecting a boolean)");
					return;
				}
			}
			console.log("Type:", type);
			message[name] = value;
		}
		sendPluginMessage($('#plugins-list .active').text(), message);
	});
	$('#plugin-message').removeClass('hide');
}

function addPluginMessageAttribute() {
	let num = pluginRows;
	pluginRows++;
	$('#addattr').parent().parent().before(
		'<tr>' +
		'	<td><input type="text" id="attrname' + num + '" placeholder="Attribute name" onkeypress="return checkEnter(this, event);" style="width: 100%;" class="pm-property form-control input-sm"></td>' +
		'	<td><input type="text" id="attrvalue' + num + '" placeholder="Attribute value" onkeypress="return checkEnter(this, event);" style="width: 100%;" class="form-control input-sm"></td>' +
		'	<td>' +
		'		<select id="attrtype' + num + '" class="form-control input-sm">' +
		'			<option>string</option>' +
		'			<option>number</option>' +
		'			<option>boolean</option>' +
		'		</select>' +
		'	</td>' +
		'	<td><i id="rmattr' + num + '" class="fa fa-window-close" style="cursor: pointer;"></i></td>' +
		'</tr>'
	);
	$('#rmattr' + num).click(function() {
		$(this).parent().parent().remove();
	});
}

function sendPluginMessage(plugin, message) {
	console.log("Sending message to " + plugin + ":", message);
	let request = {
		janus: "message_plugin",
		transaction: randomString(12),
		admin_secret: secret,
		plugin: plugin,
		request: message
	};
	$.ajax({
		type: 'POST',
		url: server,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				let authenticate = (json["error"].code === 403);
				if(!authenticate || (authenticate && !prompting && !alerted)) {
					if(authenticate)
						alerted = true;
					bootbox.alert(json["error"].reason, function() {
						if(authenticate) {
							promptAccessDetails();
							alerted = false;
						}
					});
				}
			}
			$('#plugin-response').text(JSON.stringify(json, null, 4));
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}

// Transports
function resetTransportRequest() {
	transportRows = 0;
	$('#transport-request').empty().append(
		'<tr style="background: #f9f9f9;">' +
		'	<th width="25%">Name</th>' +
		'	<th width="25%">Value</th>' +
		'	<th width="25%">Type</th>' +
		'	<th></th>' +
		'</tr>' +
		'<tr>' +
		'	<td><i id="traddattr" class="fa fa-plus-circle" style="cursor: pointer;"></i></td>' +
		'	<td></td>' +
		'	<td></td>' +
		'	<td><button id="trsendmsg" type="button" class="btn btn-xs btn-success pull-right">Send message</button></td>' +
		'</tr>');
	$('#traddattr').click(addTransportMessageAttribute).click();
	$('#trsendmsg').click(function() {
		let message = {};
		let index = 0;
		for(let i=0; i<=transportRows; i++) {
			if($('#trattrname'+i).length === 0)
				continue;
			index++;
			let name = $('#trattrname'+i).val();
			if(name === '') {
				bootbox.alert("Missing name in attribute #" + index);
				return;
			}
			if(message[name] !== null && message[name] !== undefined) {
				bootbox.alert("Duplicate attribute '" + name + "'");
				return;
			}
			let value = $('#trattrvalue'+i).val();
			if(value === '') {
				bootbox.alert("Missing value in attribute #" + index);
				return;
			}
			let type = $('#trattrtype'+i).val();
			if(type === "number") {
				value = parseInt(value);
				if(isNaN(value)) {
					bootbox.alert("Invalid value in attribute #" + index + " (expecting a number)");
					return;
				}
			} else if(type === "boolean") {
				if(value.toLowerCase() === "true") {
					value = true;
				} else if(value.toLowerCase() === "false") {
					value = false;
				} else {
					bootbox.alert("Invalid value in attribute #" + index + " (expecting a boolean)");
					return;
				}
			}
			console.log("Type:", type);
			message[name] = value;
		}
		sendTransportMessage($('#transports-list .active').text(), message);
	});
	$('#transport-message').removeClass('hide');
}

function addTransportMessageAttribute() {
	let num = transportRows;
	transportRows++;
	$('#traddattr').parent().parent().before(
		'<tr>' +
		'	<td><input type="text" id="trattrname' + num + '" placeholder="Attribute name" onkeypress="return checkEnter(this, event);" style="width: 100%;" class="pm-property form-control input-sm"></td>' +
		'	<td><input type="text" id="trattrvalue' + num + '" placeholder="Attribute value" onkeypress="return checkEnter(this, event);" style="width: 100%;" class="form-control input-sm"></td>' +
		'	<td>' +
		'		<select id="trattrtype' + num + '" class="form-control input-sm">' +
		'			<option>string</option>' +
		'			<option>number</option>' +
		'			<option>boolean</option>' +
		'		</select>' +
		'	</td>' +
		'	<td><i id="rmtrattr' + num + '" class="fa fa-window-close" style="cursor: pointer;"></i></td>' +
		'</tr>'
	);
	$('#rmtrattr' + num).click(function() {
		$(this).parent().parent().remove();
	});
}

function sendTransportMessage(transport, message) {
	console.log("Sending message to " + transport + ":", message);
	let request = {
		janus: "query_transport",
		transaction: randomString(12),
		admin_secret: secret,
		transport: transport,
		request: message
	};
	$.ajax({
		type: 'POST',
		url: server,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				let authenticate = (json["error"].code === 403);
				if(!authenticate || (authenticate && !prompting && !alerted)) {
					if(authenticate)
						alerted = true;
					bootbox.alert(json["error"].reason, function() {
						if(authenticate) {
							promptAccessDetails();
							alerted = false;
						}
					});
				}
			}
			$('#transport-response').text(JSON.stringify(json, null, 4));
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}


// Handles
function updateSessions() {
	$('#update-sessions').unbind('click').addClass('fa-spin');
	$('#update-handles').unbind('click');
	$('#update-handle').unbind('click');
	let request = { "janus": "list_sessions", "transaction": randomString(12), "admin_secret": secret };
	$.ajax({
		type: 'POST',
		url: server,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				let authenticate = (json["error"].code === 403);
				if(!authenticate || (authenticate && !prompting && !alerted)) {
					if(authenticate)
						alerted = true;
					bootbox.alert(json["error"].reason, function() {
						if(authenticate) {
							promptAccessDetails();
							alerted = false;
						}
					});
				}
				setTimeout(function() {
					$('#update-sessions').removeClass('fa-spin').click(updateSessions);
					$('#update-handles').click(updateHandles);
					$('#update-handle').click(updateHandleInfo);
				}, 1000);
				session = null;
				handle = null;
				currentHandle = null;
				$('#handles-list').empty();
				$('#handles').hide();
				$('#handle-info').empty();
				$('#options').hide();
				$('#info').hide();
				return;
			}
			console.log("Got sessions:");
			console.log(json);
			$('#sessions-list').empty();
			let sessions = json["sessions"];
			$('#sessions-num').text(sessions.length);
			for(let i=0; i<sessions.length; i++) {
				let s = sessions[i];
				$('#sessions-list').append(
					'<a id="session-'+s+'" href="#" class="list-group-item">'+s+'</a>'
				);
				$('#session-'+s).click(function() {
					let sh = $(this).text();
					console.log("Getting session " + sh + " handles");
					session = sh;
					$('#sessions-list a').removeClass('active');
					$('#session-'+sh).addClass('active');
					handle = null;
					currentHandle = null;
					$('#handles-list').empty();
					$('#handles').show();
					$('#handle-info').empty();
					$('#options').hide();
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
					currentHandle = null;
					$('#handles-list').empty();
					$('#handles').hide();
					$('#handle-info').empty();
					$('#options').hide();
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
			setTimeout(function() {
				$('#update-sessions').removeClass('fa-spin').click(updateSessions);
				$('#update-handles').click(updateHandles);
				$('#update-handle').click(updateHandleInfo);
			}, 1000);
			session = null;
			handle = null;
			currentHandle = null;
			$('#handles-list').empty();
			$('#handles').hide();
			$('#handle-info').empty();
			$('#options').hide();
			$('#info').hide();
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
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
	let request = { "janus": "list_handles", "transaction": randomString(12), "admin_secret": secret };
	$.ajax({
		type: 'POST',
		url: server + "/" + session,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				let authenticate = (json["error"].code === 403);
				if(!authenticate || (authenticate && !prompting && !alerted)) {
					if(authenticate)
						alerted = true;
					bootbox.alert(json["error"].reason, function() {
						if(authenticate) {
							promptAccessDetails();
							alerted = false;
						}
					});
				}
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
			let handles = json["handles"];
			$('#handles-num').text(handles.length);
			for(let i=0; i<handles.length; i++) {
				let h = handles[i];
				$('#handles-list').append(
					'<a id="handle-'+h+'" href="#" class="list-group-item">'+h+'</a>'
				);
				$('#handle-'+h).click(function() {
					let hi = $(this).text();
					console.log("Getting handle " + hi + " info");
					handle = hi;
					if(handle === currentHandle)
						return;	// The self-refresh takes care of that
					$('#handles-list a').removeClass('active');
					$('#handle-'+hi).addClass('active');
					$('#handle-info').empty();
					$('#options').hide();
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
					currentHandle = null;
					$('#handle-info').empty();
					$('#options').hide();
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
			$('#update-handles').removeClass('fa-spin').click(updateHandles);
			$('#update-sessions').click(updateSessions);
			$('#update-handle').click(updateHandleInfo);
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}

function updateHandleInfo(refresh) {
	if(handle === null || handle === undefined)
		return;
	if(refresh !== true) {
		if(handle === currentHandle && $('#autorefresh')[0].checked)
			return;	// The self-refresh takes care of that
		currentHandle = handle;
	}
	let updateHandle = currentHandle;
	$('#update-sessions').unbind('click');
	$('#update-handles').unbind('click');
	$('#update-handle').unbind('click').addClass('fa-spin');
	$('#capture').removeAttr('checked');
	$('#capturetext').html('Start capture');
	let request = { "janus": "handle_info", "transaction": randomString(12), "admin_secret": secret };
	$.ajax({
		type: 'POST',
		url: server + "/" + session + "/" + handle,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				if(refresh !== true) {
					let authenticate = (json["error"].code === 403);
					if(!authenticate || (authenticate && !prompting && !alerted)) {
						if(authenticate)
							alerted = true;
						bootbox.alert(json["error"].reason, function() {
							if(authenticate) {
								promptAccessDetails();
								alerted = false;
							}
						});
					}
				}
				setTimeout(function() {
					$('#update-sessions').click(updateSessions);
					$('#update-handles').click(updateHandles);
					$('#update-handle').removeClass('fa-spin').click(updateHandleInfo);
				}, 1000);
				return;
			}
			console.log("Got info:");
			console.log(json);
			handleInfo = json["info"];
			if($('#prettify')[0].checked) {
				prettyHandleInfo();
			} else {
				rawHandleInfo();
			}
			if(handleInfo["dump-to-pcap"] || handleInfo["dump-to-text2pcap"]) {
				$('#capture').attr('checked', true);
				$('#capturetext').html('Stop capture');
			}
			setTimeout(function() {
				$('#update-sessions').click(updateSessions);
				$('#update-handles').click(updateHandles);
				$('#update-handle').removeClass('fa-spin').click(updateHandleInfo);
			}, 1000);
			// Show checkboxes
			$('#options').removeClass('hide').show();
			// If the related box is checked, autorefresh this handle info every tot seconds
			if($('#autorefresh')[0].checked) {
				setTimeout(function() {
					if(updateHandle !== currentHandle) {
						// The handle changed in the meanwhile, don't autorefresh
						return;
					}
					if(!$('#autorefresh')[0].checked) {
						// Unchecked in the meantime
						return;
					}
					updateHandleInfo(true);
				}, 5000);
			}
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			$('#update-handles').removeClass('fa-spin').click(updateHandles);
			$('#update-sessions').click(updateSessions);
			$('#update-handle').click(updateHandleInfo);
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}

function rawHandleInfo() {
	// Just use <pre> and show the handle info as it is
	$('#handle-info').html('<pre>' + JSON.stringify(handleInfo, null, 4) + '</pre>');
}

function prettyHandleInfo() {
	// Prettify the handle info, processing it and turning it into tables
	$('#handle-info').html('<table class="table table-striped" id="handle-info-table"></table>');
	$('#options').hide();
	for(let k in handleInfo) {
		let v = handleInfo[k];
		if(k === "plugin_specific") {
			$('#handle-info').append(
				'<h4>Plugin specific details</h4>' +
				'<table class="table table-striped" id="plugin-specific">' +
				'</table>');
			for(let kk in v) {
				let vv = v[kk];
				$('#plugin-specific').append(
					'<tr>' +
					'	<td><b>' + kk + ':</b></td>' +
					'	<td>' + vv + '</td>' +
					'</tr>');
			}
		} else if(k === "flags") {
			$('#handle-info').append(
				'<h4>Flags</h4>' +
				'<table class="table table-striped" id="flags">' +
				'</table>');
			for(let kk in v) {
				let vv = v[kk];
				$('#flags').append(
					'<tr>' +
					'	<td><b>' + kk + ':</b></td>' +
					'	<td>' + vv + '</td>' +
					'</tr>');
			}
		} else if(k === "sdps") {
			localSdp = null;
			remoteSdp = null;
			$('#handle-info').append(
				'<h4>Session descriptions (SDP)</h4>' +
				'<table class="table table-striped" id="sdps">' +
				'</table>');
			for(let kk in v) {
				let vv = v[kk];
				if(kk === "local") {
					localSdp = vv;
				} else if(kk === "remote") {
					remoteSdp = vv;
				} else {
					// What? Skip
					continue;
				}
				$('#sdps').append(
					'<tr>' +
					'	<td><b>' + kk + ':</b></td>' +
					'	<td><a id="' + kk + '" href="#">' + vv.substring(0, 40) + '...</a></td>' +
					'</tr>');
				$('#' + kk).click(function(event) {
					event.preventDefault();
					let sdp = $(this).attr('id') === "local" ? localSdp : remoteSdp;
					bootbox.dialog({
						title: "SDP (" + $(this).attr('id') + ")",
						message: '<div style="max-height: ' + ($(window).height()*2/3) + 'px; overflow-y: auto;">' + sdp.split("\r\n").join("<br/>") + '</div>'
					});
				});
			}
		} else if(k === "streams") {
			$('#handle-info').append(
				'<h4>ICE streams</h4>' +
				'<div id="streams"></table>');
			for(let kk in v) {
				$('#streams').append(
					'<h5>Stream #' + (parseInt(kk)+1) + '</h5>' +
					'<table class="table table-striped" id="stream' + kk + '">' +
					'</table>');
				let vv = v[kk];
				console.log(vv);
				for(let sk in vv) {
					let sv = vv[sk];
					if(sk === "ssrc") {
						$('#stream' + kk).append(
							'<tr>' +
								'<td colspan="2">' +
									'<h6>SSRC</h6>' +
									'<table class="table" id="ssrc' + kk + '">' +
									'</table>' +
								'</td>' +
							'</tr>');
						for(let ssk in sv) {
							let ssv = sv[ssk];
							$('#ssrc' + kk).append(
								'<tr>' +
								'	<td><b>' + ssk + ':</b></td>' +
								'	<td>' + ssv + '</td>' +
								'</tr>');
						}
					} else if(sk === "components") {
						$('#stream' + kk).append(
							'<tr>' +
								'<td colspan="2">' +
									'<h6>Components of Stream #' + (parseInt(kk)+1) + '</h6>' +
									'<table class="table" id="components' + kk + '">' +
									'</table>' +
								'</td>' +
							'</tr>');
						for(let ssk in sv) {
							let ssv = sv[ssk];
							$('#components' + kk).append(
								'<tr>' +
									'<td colspan="2">' +
										'<h6>Component #' + (parseInt(ssk)+1) + '</h6>' +
										'<table class="table" id="stream' + kk + 'component' + ssk + '">' +
										'</table>' +
									'</td>' +
								'</tr>');
							for(let cssk in ssv) {
								let cssv = ssv[cssk];
								if(cssk === "local-candidates" || cssk === "remote-candidates") {
									let candidates = "<ul>";
									for(let c in cssv)
										candidates += "<li>" + cssv[c] + "</li>";
									candidates += "</ul>";
									$('#stream' + kk + 'component' + ssk).append(
										'<tr>' +
										'	<td><b>' + cssk + ':</b></td>' +
										'	<td>' + candidates + '</td>' +
										'</tr>');
								} else if(cssk === "dtls" || cssk === "in_stats" || cssk === "out_stats") {
									let dtls = '<table class="table">';
									for(let d in cssv) {
										dtls +=
											'<tr>' +
												'<td style="width:150px;"><b>' + d + '</b></td>' +
												'<td>' + cssv[d] + '</td>' +
											'</tr>';
									}
									dtls += '</table>';
									$('#stream' + kk + 'component' + ssk).append(
										'<tr>' +
										'	<td style="width:150px;"><b>' + cssk + ':</b></td>' +
										'	<td>' + dtls + '</td>' +
										'</tr>');
								} else {
									$('#stream' + kk + 'component' + ssk).append(
										'<tr>' +
										'	<td><b>' + cssk + ':</b></td>' +
										'	<td>' + cssv + '</td>' +
										'</tr>');
								}
							}
						}
					} else {
						$('#stream' + kk).append(
							'<tr>' +
							'	<td><b>' + sk + ':</b></td>' +
							'	<td>' + sv + '</td>' +
							'</tr>');
					}
				}
			}
		} else {
			$('#handle-info-table').append(
				'<tr>' +
				'	<td><b>' + k + ':</b></td>' +
				'	<td>' + v + '</td>' +
				'</tr>');
		}
	}
	$('#options').show();
}

// Tokens
function updateTokens() {
	$('#update-tokens').unbind('click').addClass('fa-spin');
	let request = { "janus": "list_tokens", "transaction": randomString(12), "admin_secret": secret };
	$.ajax({
		type: 'POST',
		url: server,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				let authenticate = (json["error"].code === 403);
				if(!authenticate || (authenticate && !prompting && !alerted)) {
					if(authenticate)
						alerted = true;
					bootbox.alert(json["error"].reason, function() {
						if(authenticate) {
							promptAccessDetails();
							alerted = false;
						}
					});
				}
				setTimeout(function() {
					$('#update-tokens').removeClass('fa-spin').click(updateTokens);
				}, 1000);
				return;
			}
			console.log("Got tokens:");
			console.log(json.data.tokens);
			setTimeout(function() {
				$('#update-tokens').removeClass('fa-spin').click(updateTokens);
			}, 1000);
			$('#auth-tokens').html(
				'<tr>' +
				'	<th>Token</th>' +
				'	<th>Permissions</th>' +
				'	<th></th>' +
				'</tr>');
			for(let index in json.data.tokens) {
				let t = json.data.tokens[index];
				let tokenPlugins = t.allowed_plugins.toString().replace(/,/g,'<br/>');
				$('#auth-tokens').append(
					'<tr>' +
					'	<td>' + t.token + '</td>' +
					'	<td>' + tokenPlugins + '</td>' +
					'	<td><button  id="' + t.token + '" type="button" class="btn btn-xs btn-danger">Remove token</button></td>' +
					'</tr>');
				$('#'+t.token).click(function() {
					let token = $(this).attr('id');
					bootbox.confirm("Are you sure you want to remove token " + token + "?", function(result) {
						if(result)
							removeToken(token);
					});
				});
			}
			$('#auth-tokens').append(
				'<tr>' +
				'	<td><input type="text" id="token" placeholder="Token to add" onkeypress="return checkEnter(this, event);" style="width: 100%;"></td>' +
				'	<td><div id="permissions"></div></td>' +
				'	<td><button id="addtoken" type="button" class="btn btn-xs btn-success">Add token</button></td>' +
				'</tr>');
			let pluginsCheckboxes = "";
			for(let i in plugins) {
				let plugin = plugins[i];
				pluginsCheckboxes +=
					'<div class="checkbox">' +
					'	<label>' +
					'		<input checked type="checkbox" value="' + plugin + '">' + plugin + '</input>' +
					'</div>';
			}
			$('#permissions').html(pluginsCheckboxes);
			$('#addtoken').click(function() {
				let token = $("#token").val().replace(/ /g,'');
				if(token === "") {
					bootbox.alert("Please insert a valid token string");
					return;
				}
				let checked = $(':checked');
				if(checked.length === 0) {
					bootbox.alert("Please allow the token access to at least a plugin");
					return;
				}
				let pluginPermissions = [];
				for(let i=0; i<checked.length; i++)
					pluginPermissions.push(checked[i].value);
				let text = "Are you sure you want to add the new token " + token + " with access to the following plugins?" +
					"<br/><ul>";
				for(let i in pluginPermissions)
					text += "<li>" + pluginPermissions[i] + "</li>";
				text += "</ul>";
				bootbox.confirm(text, function(result) {
					if(result)
						addToken(token, pluginPermissions);
				});
			});
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			$('#update-settings').removeClass('fa-spin').click(updateSettings);
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}

function addToken(token, permissions) {
	let request = { "janus": "add_token", "token": token, plugins: permissions, "transaction": randomString(12), "admin_secret": secret };
	sendTokenRequest(request);
}

function removeToken(token) {
	let request = { "janus": "remove_token", "token": token, "transaction": randomString(12), "admin_secret": secret };
	sendTokenRequest(request);
}

function sendTokenRequest(request) {
	console.log(request);
	$.ajax({
		type: 'POST',
		url: server,
		cache: false,
		contentType: "application/json",
		data: JSON.stringify(request),
		success: function(json) {
			if(json["janus"] !== "success") {
				console.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				let authenticate = (json["error"].code === 403);
				if(!authenticate || (authenticate && !prompting && !alerted)) {
					if(authenticate)
						alerted = true;
					bootbox.alert(json["error"].reason, function() {
						if(authenticate) {
							promptAccessDetails();
							alerted = false;
						}
					});
				}
				return;
			}
			updateTokens();
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}

// text2pcap and pcap requests
function captureTrafficPrompt() {
	bootbox.dialog({
		title: "Start capturing traffic",
		message:
			'<div class="form-content">' +
			'	<form class="form" role="form">' +
			'		<div class="form-group">' +
			'			<label for="type">Capture Type</label>' +
			'			<select class="form-control" id="type" name="type" value="pcal">' +
			'				<option value="pcap">pcap</option>' +
			'				<option value="text2pcap">text2pcap</option>' +
			'			</select>' +
			'		</div>' +
			'		<div class="form-group">' +
			'			<label for="extra">Folder to save in</label>' +
			'			<input type="text" class="form-control" id="folder" name="folder" placeholder="Insert a path to the target folder" value=""></input>' +
			'		</div>' +
			'		<div class="form-group">' +
			'			<label for="extra">Filename</label>' +
			'			<input type="text" class="form-control" id="filename" name="filename" placeholder="Insert the target filename" value=""></input>' +
			'		</div>' +
			'		<div class="form-group">' +
			'			<label for="extra">Truncate</label>' +
			'			<input type="text" class="form-control" id="truncate" name="truncate" placeholder="Bytes to truncate at (0 or omit to save the whole packet)" value=""></input>' +
			'		</div>' +
			'	</form>' +
			'</div>',
		buttons: [
			{
				label: "Start",
				className: "btn btn-primary pull-left",
				callback: function() {
					let text = $('#type').val() === "text2pcap";
					let folder = $('#folder').val() !== '' ? $('#folder').val() : undefined;
					let filename = $('#filename').val() !== '' ? $('#filename').val() : undefined;
					let truncate = parseInt($('#truncate').val());
					if(!truncate || isNaN(truncate))
						truncate = 0;
					captureTrafficRequest(true, text, folder, filename, truncate);
				}
			},
			{
				label: "Close",
				className: "btn btn-default pull-left",
				callback: function() {
					$('#capture').removeAttr('checked');
					$('#capturetext').html('Start capture');
				}
			}
		]
	});
}

function captureTrafficRequest(start, text, folder, filename, truncate) {
	let req = start ? ( text ? "start_text2pcap" : "start_pcap" ) :
		( text ? "stop_text2pcap" : "stop_pcap" )
	let request = { "janus": req, "transaction": randomString(12), "admin_secret": secret };
	if(start) {
		request["folder"] = folder;
		request["filename"] = filename;
		request["truncate"] = truncate;
	}
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
				if(start && json["error"].reason.indexOf('already') === -1) {
					$('#capture').removeAttr('checked');
					$('#capturetext').html('Start capture');
				}
				return;
			}
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			console.log(textStatus + ": " + errorThrown);	// FIXME
			if(!prompting && !alerted) {
				alerted = true;
				bootbox.alert("Couldn't contact the backend: is Janus down, or is the Admin/Monitor interface disabled?", function() {
					promptAccessDetails();
					alerted = false;
				});
			}
		},
		dataType: "json"
	});
}

// eslint-disable-next-line no-unused-vars
function checkEnter(field, event) {
	let theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if(theCode == 13) {
		if(field.id == 'token')
			$('#addtoken').click();
		else if(field.id.indexOf('attr') !== -1)
			$('#sendmsg').click();
		return false;
	} else {
		return true;
	}
}
