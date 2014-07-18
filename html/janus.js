// List of sessions
Janus.sessions = {};

Janus.noop = function() {};

// Initialization
Janus.init = function(options) {
	options = options || {};
	options.callback = (typeof options.callback == "function") ? options.callback : Janus.noop;
	if(Janus.initDone === true) {
		// Already initialized
		options.callback();
	} else {
		if(typeof console == "undefined" || typeof console.log == "undefined")
			console = { log: function() {} };
		// Console log (debugging disabled by default)
		Janus.log = (options.debug === true) ? console.log.bind(console) : Janus.noop;
		Janus.log("Initializing library");
		Janus.initDone = true;
		// Detect tab close
		window.onbeforeunload = function() {
			Janus.log("Closing window");
			for(var s in Janus.sessions) {
				Janus.log("Destroying session " + s);
				Janus.sessions[s].destroy();
			}
		}
		// Helper to add external JavaScript sources
		function addJs(src) {
			if(src === 'jquery.min.js') {
				if(window.jQuery) {
					// Already loaded
					options.callback();
					return;
				}
			}
			var oHead = document.getElementsByTagName('head').item(0);
			var oScript = document.createElement("script");
			oScript.type = "text/javascript";
			oScript.src = src;
			oScript.onload = function() {
				Janus.log("Library " + src + " loaded");
				if(src === 'jquery.min.js') {
					options.callback();
				}
			}
			oHead.appendChild(oScript);
		};

		addJs('adapter.js');
		addJs('jquery.min.js');
	}
};

// Helper method to check whether WebRTC is supported by this browser
Janus.isWebrtcSupported = function() {
	if(RTCPeerConnection === null || getUserMedia === null) {
		return false;
	}
	return true;
};

function Janus(gatewayCallbacks) {
	if(Janus.initDone === undefined) {
		gatewayCallbacks.error("Library not initialized");
		return {};
	}
	if(!Janus.isWebrtcSupported()) {
		gatewayCallbacks.error("WebRTC not supported by this browser");
		return {};
	}
	Janus.log("Library initialized: " + Janus.initDone);
	gatewayCallbacks = gatewayCallbacks || {};
	gatewayCallbacks.success = (typeof gatewayCallbacks.success == "function") ? gatewayCallbacks.success : jQuery.noop;
	gatewayCallbacks.error = (typeof gatewayCallbacks.error == "function") ? gatewayCallbacks.error : jQuery.noop;
	gatewayCallbacks.destroyed = (typeof gatewayCallbacks.destroyed == "function") ? gatewayCallbacks.destroyed : jQuery.noop;
	if(gatewayCallbacks.server === null || gatewayCallbacks.server === undefined) {
		gatewayCallbacks.error("Invalid gateway url");
		return {};
	}
	var websockets = false;
	var ws = null;
	var servers = null, serversIndex = 0;
	var server = gatewayCallbacks.server;
	if($.isArray(server)) {
		Janus.log("Multiple servers provided (" + server.length + "), will use the first that works");
		server = null;
		servers = gatewayCallbacks.server;
		Janus.log(servers);
	} else {
		if(server.indexOf("ws") === 0) {
			websockets = true;
			Janus.log("Using WebSockets to contact Janus");
		} else {
			websockets = false;
			Janus.log("Using REST API to contact Janus");
		}
		Janus.log(server);
	}
	var iceServers = gatewayCallbacks.iceServers;
	if(iceServers === undefined || iceServers === null)
		iceServers = [{"url": "stun:stun.l.google.com:19302"}];
	var maxev = null;
	if(gatewayCallbacks.max_poll_events !== undefined && gatewayCallbacks.max_poll_events !== null)
		maxev = gatewayCallbacks.max_poll_events;
	if(maxev < 1)
		maxev = 1;
	var connected = false;
	var sessionId = null;
	var pluginHandles = {};
	var that = this;
	var retries = 0;
	var transactions = {};
	createSession(gatewayCallbacks);

	// Public methods
	this.getServer = function() { return server; };
	this.isConnected = function() { return connected; };
	this.getSessionId = function() { return sessionId; };
	this.destroy = function(callbacks) { destroySession(callbacks); };
	this.attach = function(callbacks) { createHandle(callbacks); };
	
	// Private method to create random identifiers (e.g., transaction)
	function randomString(len) {
		charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		var randomString = '';
		for (var i = 0; i < len; i++) {
			var randomPoz = Math.floor(Math.random() * charSet.length);
			randomString += charSet.substring(randomPoz,randomPoz+1);
		}
		return randomString;
	}

	function eventHandler() {
		if(sessionId == null)
			return;
		Janus.log('Long poll...');
		if(!connected) {
			Janus.log("Is the gateway down? (connected=false)");
			return;
		}
		var longpoll = server + "/" + sessionId + "?rid=" + new Date().getTime();
		if(maxev !== undefined && maxev !== null)
			longpoll = longpoll + "&maxev=" + maxev;
		$.ajax({
			type: 'GET',
			url: longpoll,
			cache: false,
			timeout: 60000,	// FIXME
			success: handleEvent,
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.log(textStatus + ": " + errorThrown);
				//~ clearTimeout(timeoutTimer);
				retries++;
				if(retries > 3) {
					// Did we just lose the gateway? :-(
					connected = false;
					gatewayCallbacks.error("Lost connection to the gateway (is it down?)");
					return;
				}
				eventHandler();
			},
			dataType: "json"
		});
	}
	
	// Private event handler: this will trigger plugin callbacks, if set
	function handleEvent(json) {
		retries = 0;
		if(!websockets && sessionId !== undefined && sessionId !== null)
			setTimeout(eventHandler, 200);
		Janus.log("Got event on session " + sessionId);
		Janus.log(json);
		if(!websockets && $.isArray(json)) {
			// We got an array: it means we passed a maxev > 1, iterate on all objects
			for(var i=0; i<json.length; i++) {
				handleEvent(json[i]);
			}
			return;
		}
		if(json["janus"] === "keepalive") {
			// Nothing happened
			return;
		} else if(json["janus"] === "ack") {
			// Just an ack, ignore
			return;
		} else if(json["janus"] === "success") {
			// Success!
			var transaction = json["transaction"];
			if(transaction !== null && transaction !== undefined) {
				var reportSuccess = transactions[transaction];
				if(reportSuccess !== null && reportSuccess !== undefined) {
					reportSuccess(json);
				}
				transactions[transaction] = null;
			}
			return;
		} else if(json["janus"] === "hangup") {
			// A plugin asked the core to hangup a PeerConnection on one of our handles
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.log("Missing sender...");
				return;
			}
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.log("This handle is not attached to this session");
				return;
			}
			pluginHandle.hangup();
		} else if(json["janus"] === "detached") {
			// A plugin asked the core to detach one of our handles
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.log("Missing sender...");
				return;
			}
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.log("This handle is not attached to this session");
				return;
			}
			pluginHandle.ondetached();
			pluginHandle.detach();
		} else if(json["janus"] === "error") {
			// Oops, something wrong happened
			Janus.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
			var transaction = json["transaction"];
			if(transaction !== null && transaction !== undefined) {
				var reportSuccess = transactions[transaction];
				if(reportSuccess !== null && reportSuccess !== undefined) {
					reportSuccess(json);
				}
				transactions[transaction] = null;
			}
			return;
		} else if(json["janus"] === "event") {
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.log("Missing sender...");
				return;
			}
			var plugindata = json["plugindata"];
			if(plugindata === undefined || plugindata === null) {
				Janus.log("Missing plugindata...");
				return;
			}
			Janus.log("  -- Event is coming from " + sender + " (" + plugindata["plugin"] + ")");
			var data = plugindata["data"];
			Janus.log(data);
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.log("This handle is not attached to this session");
				return;
			}
			var jsep = json["jsep"];
			if(jsep !== undefined && jsep !== null) {
				Janus.log("Handling SDP as well...");
				Janus.log(jsep);
			}
			var callback = pluginHandle.onmessage;
			if(callback !== null && callback !== undefined) {
				Janus.log("Notifying application...");
				// Send to callback specified when attaching plugin handle
				callback(data, jsep);
			} else {
				// Send to generic callback (?)
				Janus.log("No provided notification callback");
			}
		} else {
			Janus.log("Unknown message '" + json["janus"] + "'");
		}
	}
	
	// Private helper to send keep-alive messages on WebSockets
	function keepAlive() {
		if(server === null || !websockets || !connected)
			return;
		setTimeout(keepAlive, 30000);
		var request = { "janus": "keepalive", "session_id": sessionId, "transaction": randomString(12) };
		ws.send(JSON.stringify(request));
	}

	// Private method to create a session
	function createSession(callbacks) {
		var transaction = randomString(12);
		var request = { "janus": "create", "transaction": transaction };
		if(server === null && $.isArray(servers)) {
			// We still need to find a working server from the list we were given
			server = servers[serversIndex];
			if(server.indexOf("ws") === 0) {
				websockets = true;
				Janus.log("Server #" + (serversIndex+1) + ": trying WebSockets to contact Janus");
			} else {
				websockets = false;
				Janus.log("Server #" + (serversIndex+1) + ": trying REST API to contact Janus");
			}
			Janus.log(server);
		}
		if(websockets) {
			ws = new WebSocket(server); 
			ws.onerror = function() {
				Janus.log("Error connecting to the Janus WebSockets server...");
				if($.isArray(servers)) {
					serversIndex++;
					if(serversIndex == servers.length) {
						// We tried all the servers the user gave us and they all failed
						callbacks.error("Error connecting to any of the provided Janus servers: Is the gateway down?");
						return;
					}
					// Let's try the next server
					server = null;
					setTimeout(function() { createSession(callbacks); }, 200);
					return;
				}
				callbacks.error("Error connecting to the Janus WebSockets server: Is the gateway down?");
			};
			ws.onopen = function() {
				// We need to be notified about the success
				transactions[transaction] = function(json) {
					Janus.log("Create session:");
					Janus.log(json);
					if(json["janus"] !== "success") {
						Janus.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
						callbacks.error(json["error"].reason);
						return;
					}
					setTimeout(keepAlive, 30000);
					connected = true;
					sessionId = json.data["id"];
					Janus.log("Created session: " + sessionId);
					Janus.sessions[sessionId] = that;
					callbacks.success();
				};
				ws.send(JSON.stringify(request));
			};
			ws.onmessage = function(event) {
				handleEvent(JSON.parse(event.data));
			};
			ws.onclose = function() {
				if(server === null || !connected)
					return;
				connected = false;
				// FIXME What if this is called when the page is closed?
				gatewayCallbacks.error("Lost connection to the gateway (is it down?)");
			};
			return;
		}
		$.ajax({
			type: 'POST',
			url: server,
			cache: false,
			contentType: "application/json",
			data: JSON.stringify(request),
			success: function(json) {
				Janus.log("Create session:");
				Janus.log(json);
				if(json["janus"] !== "success") {
					Janus.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
					callbacks.error(json["error"].reason);
					return;
				}
				connected = true;
				sessionId = json.data["id"];
				Janus.log("Created session: " + sessionId);
				Janus.sessions[sessionId] = that;
				eventHandler();
				callbacks.success();
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.log(textStatus + ": " + errorThrown);	// FIXME
				if($.isArray(servers)) {
					serversIndex++;
					if(serversIndex == servers.length) {
						// We tried all the servers the user gave us and they all failed
						callbacks.error("Error connecting to any of the provided Janus servers: Is the gateway down?");
						return;
					}
					// Let's try the next server
					server = null;
					setTimeout(function() { createSession(callbacks); }, 200);
					return;
				}
				if(errorThrown === "")
					callbacks.error(textStatus + ": Is the gateway down?");
				else
					callbacks.error(textStatus + ": " + errorThrown);
			},
			dataType: "json"
		});
	}

	// Private method to destroy a session
	function destroySession(callbacks, syncRequest) {
		syncRequest = (syncRequest === true);
		Janus.log("Destroying session " + sessionId + " (sync=" + syncRequest + ")");
		callbacks = callbacks || {};
		// FIXME This method triggers a success even when we fail
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		if(!connected) {
			Janus.log("Is the gateway down? (connected=false)");
			callbacks.success();
			return;
		}
		if(sessionId === undefined || sessionId === null) {
			Janus.log("No session to destroy");
			callbacks.success();
			gatewayCallbacks.destroyed();
			return;
		}
		delete Janus.sessions[sessionId];
		// Destroy all handles first
		for(ph in pluginHandles) {
			var phv = pluginHandles[ph];
			Janus.log("Destroying handle " + phv.id + " (" + phv.plugin + ")");
			destroyHandle(phv.id, null, syncRequest);
		}
		// Ok, go on
		var request = { "janus": "destroy", "transaction": randomString(12) };
		if(websockets) {
			request["session_id"] = sessionId;
			ws.send(JSON.stringify(request));
			callbacks.success();
			gatewayCallbacks.destroyed();
			return;
		}
		$.ajax({
			type: 'POST',
			url: server + "/" + sessionId,
			async: syncRequest,	// Sometimes we need false here, or destroying in onbeforeunload won't work
			cache: false,
			contentType: "application/json",
			data: JSON.stringify(request),
			success: function(json) {
				Janus.log("Destroyed session:");
				Janus.log(json);
				sessionId = null;
				connected = false;
				if(json["janus"] !== "success") {
					Janus.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				}
				callbacks.success();
				gatewayCallbacks.destroyed();
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.log(textStatus + ": " + errorThrown);	// FIXME
				// Reset everything anyway
				sessionId = null;
				connected = false;
				callbacks.success();
				gatewayCallbacks.destroyed();
			},
			dataType: "json"
		});
	}
	
	// Private method to create a plugin handle
	function createHandle(callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		callbacks.consentDialog = (typeof callbacks.consentDialog == "function") ? callbacks.consentDialog : jQuery.noop;
		callbacks.onmessage = (typeof callbacks.onmessage == "function") ? callbacks.onmessage : jQuery.noop;
		callbacks.onlocalstream = (typeof callbacks.onlocalstream == "function") ? callbacks.onlocalstream : jQuery.noop;
		callbacks.onremotestream = (typeof callbacks.onremotestream == "function") ? callbacks.onremotestream : jQuery.noop;
		callbacks.ondata = (typeof callbacks.ondata == "function") ? callbacks.ondata : jQuery.noop;
		callbacks.ondataopen = (typeof callbacks.ondataopen == "function") ? callbacks.ondataopen : jQuery.noop;
		callbacks.oncleanup = (typeof callbacks.oncleanup == "function") ? callbacks.oncleanup : jQuery.noop;
		callbacks.ondetached = (typeof callbacks.ondetached == "function") ? callbacks.ondetached : jQuery.noop;
		if(!connected) {
			Janus.log("Is the gateway down? (connected=false)");
			callbacks.error("Is the gateway down? (connected=false)");
			return;
		}
		var plugin = callbacks.plugin;
		if(plugin === undefined || plugin === null) {
			Janus.log("Invalid plugin");
			callbacks.error("Invalid plugin");
			return;
		}
		var transaction = randomString(12);
		var request = { "janus": "attach", "plugin": plugin, "transaction": transaction };
		if(websockets) {
			transactions[transaction] = function(json) {
				Janus.log("Create handle:");
				Janus.log(json);
				if(json["janus"] !== "success") {
					Janus.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
					callbacks.error("Ooops: " + json["error"].code + " " + json["error"].reason);
					return;
				}
				var handleId = json.data["id"];
				Janus.log("Created handle: " + handleId);
				var pluginHandle =
					{
						session : that,
						plugin : plugin,
						id : handleId,
						webrtcStuff : {
							started : false,
							myStream : null,
							mySdp : null,
							pc : null,
							dataChannel : null,
							dtmfSender : null,
							trickle : true,
							iceDone : false,
							sdpSent : false,
							bitrate : {
								value : null,
								bsnow : null,
								bsbefore : null,
								tsnow : null,
								tsbefore : null,
								timer : null
							}
						},
						getId : function() { return handleId; },
						getPlugin : function() { return plugin; },
						getBitrate : function() { return getBitrate(handleId); },
						send : function(callbacks) { sendMessage(handleId, callbacks); },
						data : function(callbacks) { sendData(handleId, callbacks); },
						dtmf : function(callbacks) { sendDtmf(handleId, callbacks); },
						consentDialog : callbacks.consentDialog,
						onmessage : callbacks.onmessage,
						createOffer : function(callbacks) { prepareWebrtc(handleId, callbacks); },
						createAnswer : function(callbacks) { prepareWebrtc(handleId, callbacks); },
						handleRemoteJsep : function(callbacks) { prepareWebrtcPeer(handleId, callbacks); },
						onlocalstream : callbacks.onlocalstream,
						onremotestream : callbacks.onremotestream,
						ondata : callbacks.ondata,
						ondataopen : callbacks.ondataopen,
						oncleanup : callbacks.oncleanup,
						ondetached : callbacks.ondetached,
						hangup : function() { cleanupWebrtc(handleId); },
						detach : function(callbacks) { destroyHandle(handleId, callbacks); },
					}
				pluginHandles[handleId] = pluginHandle;
				callbacks.success(pluginHandle);
			};
			request["session_id"] = sessionId;
			ws.send(JSON.stringify(request));
			return;
		}
		$.ajax({
			type: 'POST',
			url: server + "/" + sessionId,
			cache: false,
			contentType: "application/json",
			data: JSON.stringify(request),
			success: function(json) {
				Janus.log("Create handle:");
				Janus.log(json);
				if(json["janus"] !== "success") {
					Janus.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
					callbacks.error("Ooops: " + json["error"].code + " " + json["error"].reason);
					return;
				}
				var handleId = json.data["id"];
				Janus.log("Created handle: " + handleId);
				var pluginHandle =
					{
						session : that,
						plugin : plugin,
						id : handleId,
						webrtcStuff : {
							started : false,
							myStream : null,
							mySdp : null,
							pc : null,
							dataChannel : null,
							dtmfSender : null,
							trickle : true,
							iceDone : false,
							sdpSent : false,
							bitrate : {
								value : null,
								bsnow : null,
								bsbefore : null,
								tsnow : null,
								tsbefore : null,
								timer : null
							}
						},
						getId : function() { return handleId; },
						getPlugin : function() { return plugin; },
						getBitrate : function() { return getBitrate(handleId); },
						send : function(callbacks) { sendMessage(handleId, callbacks); },
						data : function(callbacks) { sendData(handleId, callbacks); },
						dtmf : function(callbacks) { sendDtmf(handleId, callbacks); },
						consentDialog : callbacks.consentDialog,
						onmessage : callbacks.onmessage,
						createOffer : function(callbacks) { prepareWebrtc(handleId, callbacks); },
						createAnswer : function(callbacks) { prepareWebrtc(handleId, callbacks); },
						handleRemoteJsep : function(callbacks) { prepareWebrtcPeer(handleId, callbacks); },
						onlocalstream : callbacks.onlocalstream,
						onremotestream : callbacks.onremotestream,
						ondata : callbacks.ondata,
						ondataopen : callbacks.ondataopen,
						oncleanup : callbacks.oncleanup,
						ondetached : callbacks.ondetached,
						hangup : function() { cleanupWebrtc(handleId); },
						detach : function(callbacks) { destroyHandle(handleId, callbacks); }
					}
				pluginHandles[handleId] = pluginHandle;
				callbacks.success(pluginHandle);
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.log(textStatus + ": " + errorThrown);	// FIXME
			},
			dataType: "json"
		});
	}

	// Private method to send a message
	function sendMessage(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		if(!connected) {
			Janus.log("Is the gateway down? (connected=false)");
			callbacks.error("Is the gateway down? (connected=false)");
			return;
		}
		var message = callbacks.message;
		var jsep = callbacks.jsep;
		var request = { "janus": "message", "body": message, "transaction": randomString(12) };
		if(jsep !== null && jsep !== undefined)
			request.jsep = jsep;
		Janus.log("Sending message to plugin (handle=" + handleId + "):");
		Janus.log(request);
		if(websockets) {
			request["session_id"] = sessionId;
			request["handle_id"] = handleId;
			ws.send(JSON.stringify(request));
			return;
		}
		$.ajax({
			type: 'POST',
			url: server + "/" + sessionId + "/" + handleId,
			cache: false,
			contentType: "application/json",
			data: JSON.stringify(request),
			success: function(json) {
				Janus.log(json);
				Janus.log("Message sent!");
				if(json["janus"] !== "ack") {
					Janus.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
					callbacks.error(json["error"].code + " " + json["error"].reason);
					return;
				}
				callbacks.success();
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.log(textStatus + ": " + errorThrown);	// FIXME
				callbacks.error(textStatus + ": " + errorThrown);
			},
			dataType: "json"
		});
	}

	// Private method to send a trickle candidate
	function sendTrickleCandidate(handleId, candidate) {
		if(!connected) {
			Janus.log("Is the gateway down? (connected=false)");
			return;
		}
		var request = { "janus": "trickle", "candidate": candidate, "transaction": randomString(12) };
		Janus.log("Sending trickle candidate (handle=" + handleId + "):");
		Janus.log(request);
		if(websockets) {
			request["session_id"] = sessionId;
			request["handle_id"] = handleId;
			ws.send(JSON.stringify(request));
			return;
		}
		$.ajax({
			type: 'POST',
			url: server + "/" + sessionId + "/" + handleId,
			cache: false,
			contentType: "application/json",
			data: JSON.stringify(request),
			success: function(json) {
				Janus.log(json);
				Janus.log("Candidate sent!");
				if(json["janus"] !== "ack") {
					Janus.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
					return;
				}
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.log(textStatus + ": " + errorThrown);	// FIXME
			},
			dataType: "json"
		});
	}

	// Private method to send a data channel message
	function sendData(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		if(config.dataChannel === null || config.dataChannel === undefined) {
			Janus.log("Invalid data channel");
			callbacks.error("Invalid data channel");
			return;
		}
		var text = callbacks.text;
		if(text === null || text === undefined) {
			Janus.log("Invalid text");
			callbacks.error("Invalid text");
			return;
		}
		Janus.log("Sending string on data channel: " + text); 
		config.dataChannel.send(text);
		callbacks.success();
	}

	// Private method to send a DTMF tone
	function sendDtmf(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		if(config.dtmfSender === null || config.dtmfSender === undefined) {
			// Create the DTMF sender, if possible
			if(config.myStream !== undefined && config.myStream !== null) {
				var tracks = config.myStream.getAudioTracks();
				if(tracks !== null && tracks !== undefined && tracks.length > 0) {
					var local_audio_track = tracks[0];
					config.dtmfSender = config.pc.createDTMFSender(local_audio_track);
					Janus.log("Created DTMF Sender");
					config.dtmfSender.ontonechange = function(tone) { Janus.log("Sent DTMF tone: " + tone.tone); };
				}
			}
			if(config.dtmfSender === null || config.dtmfSender === undefined) {
				Janus.log("Invalid DTMF configuration");
				callbacks.error("Invalid DTMF configuration");
				return;
			}
		}
		var dtmf = callbacks.dtmf;
		if(dtmf === null || dtmf === undefined) {
			Janus.log("Invalid DTMF parameters");
			callbacks.error("Invalid DTMF parameters");
			return;
		}
		var tones = dtmf.tones;
		if(tones === null || tones === undefined) {
			Janus.log("Invalid DTMF string");
			callbacks.error("Invalid DTMF string");
			return;
		}
		var duration = dtmf.duration;
		if(duration === null || duration === undefined)
			duration = 500;	// We choose 500ms as the default duration for a tone 
		var gap = dtmf.gap;
		if(gap === null || gap === undefined)
			gap = 50;	// We choose 50ms as the default gap between tones
		Janus.log("Sending DTMF string " + tones + " (duration " + duration + "ms, gap " + gap + "ms"); 
		config.dtmfSender.insertDTMF(tones, duration, gap);
	}

	// Private method to destroy a plugin handle
	function destroyHandle(handleId, callbacks, syncRequest) {
		syncRequest = (syncRequest === true);
		Janus.log("Destroying handle " + handleId + " (sync=" + syncRequest + ")");
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		cleanupWebrtc(handleId);
		if(!connected) {
			Janus.log("Is the gateway down? (connected=false)");
			callbacks.error("Is the gateway down? (connected=false)");
			return;
		}
		var request = { "janus": "detach", "transaction": randomString(12) };
		if(websockets) {
			request["session_id"] = sessionId;
			request["handle_id"] = handleId;
			ws.send(JSON.stringify(request));
			var pluginHandle = pluginHandles[handleId];
			delete pluginHandles[handleId];
			callbacks.success();
			return;
		}
		$.ajax({
			type: 'POST',
			url: server + "/" + sessionId + "/" + handleId,
			async: syncRequest,	// Sometimes we need false here, or destroying in onbeforeunload won't work
			cache: false,
			contentType: "application/json",
			data: JSON.stringify(request),
			success: function(json) {
				Janus.log("Destroyed handle:");
				Janus.log(json);
				if(json["janus"] !== "success") {
					Janus.log("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				}
				var pluginHandle = pluginHandles[handleId];
				delete pluginHandles[handleId];
				callbacks.success();
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.log(textStatus + ": " + errorThrown);	// FIXME
				// We cleanup anyway
				var pluginHandle = pluginHandles[handleId];
				delete pluginHandles[handleId];
				callbacks.success();
			},
			dataType: "json"
		});
	}
	
	// WebRTC stuff
	function streamsDone(handleId, jsep, media, callbacks, stream) {
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		if(stream !== null && stream !== undefined)
			Janus.log(stream);
		config.myStream = stream;
		Janus.log("streamsDone:");
		if(stream !== null && stream !== undefined)
			Janus.log(stream);
		var pc_config = {"iceServers": iceServers};
		//~ var pc_constraints = {'mandatory': {'MozDontOfferDataChannel':true}};
		var pc_constraints = {
			"optional": [{"DtlsSrtpKeyAgreement": true}]
		};
		Janus.log("Creating PeerConnection:");
		Janus.log(pc_constraints);
		config.pc = new RTCPeerConnection(pc_config, pc_constraints);
		Janus.log(config.pc);
		if(config.pc.getStats && webrtcDetectedBrowser == "chrome")	// FIXME
			config.bitrate.value = "0 kbps";
		Janus.log("Preparing local SDP and gathering candidates (trickle=" + config.trickle + ")"); 
		config.pc.onicecandidate = function(event) {
			if (event.candidate == null) {
				Janus.log("End of candidates.");
				config.iceDone = true;
				if(config.trickle === true) {
					// Notify end of candidates
					sendTrickleCandidate(handleId, null);
				} else {
					// No trickle, time to send the complete SDP (including all candidates) 
					sendSDP(handleId, callbacks);
				}
			} else {
				Janus.log("candidates: " + JSON.stringify(event.candidate));
				if(config.trickle === true) {
					// Send candidate
					sendTrickleCandidate(handleId, event.candidate);
				}
			}
		};
		if(stream !== null && stream !== undefined) {
			Janus.log('Adding local stream');
			config.pc.addStream(stream);
			pluginHandle.onlocalstream(stream);
		}
		config.pc.onaddstream = function(remoteStream) {
			Janus.log("Handling Remote Stream:");
			Janus.log(remoteStream);
			// Start getting the bitrate, if getStats is supported
			if(config.pc.getStats && webrtcDetectedBrowser == "chrome") {	// FIXME
				// http://webrtc.googlecode.com/svn/trunk/samples/js/demos/html/constraints-and-stats.html
				Janus.log("Starting bitrate monitor");
				config.bitrate.timer = setInterval(function() {
					//~ config.pc.getStats(config.pc.getRemoteStreams()[0].getVideoTracks()[0], function(stats) {
					config.pc.getStats(function(stats) {
						var results = stats.result();
						for(var i=0; i<results.length; i++) {
							var res = results[i];
							if(res.type == 'ssrc' && res.stat('googFrameHeightReceived')) {
								config.bitrate.bsnow = res.stat('bytesReceived');
								config.bitrate.tsnow = res.timestamp;
								if(config.bitrate.bsbefore === null || config.bitrate.tsbefore === null) {
									// Skip this round
									config.bitrate.bsbefore = config.bitrate.bsnow;
									config.bitrate.tsbefore = config.bitrate.tsnow;
								} else {
									// Calculate bitrate
									var bitRate = Math.round((config.bitrate.bsnow - config.bitrate.bsbefore) * 8 / (config.bitrate.tsnow - config.bitrate.tsbefore));
									config.bitrate.value = bitRate + ' kbits/sec';
									//~ Janus.log("Estimated bitrate is " + config.bitrate.value);
									config.bitrate.bsbefore = config.bitrate.bsnow;
									config.bitrate.tsbefore = config.bitrate.tsnow;
								}
							}
						}
					});
				}, 1000);
			}
			pluginHandle.onremotestream(remoteStream.stream);
		};
		// Any data channel to create?
		if(isDataEnabled(media)) {
			Janus.log("Creating data channel");
			var onDataChannelMessage = function(event) {
				Janus.log('Received message on data channel: ' + event.data);
				pluginHandle.ondata(event.data);	// FIXME
			}
			var onDataChannelStateChange = function() {
				Janus.log('State change on data channel: ' + config.dataChannel.readyState);
				if(config.dataChannel.readyState === 'open') {
					pluginHandle.ondataopen();	// FIXME
				}
			}
			var onDataChannelError = function(error) {
				Janus.log('Got error on data channel:');
				Janus.log(error);
				// TODO
			}
			// Until we implement the proxying of open requests within the Janus core, we open a channel ourselves whatever the case
			config.dataChannel = config.pc.createDataChannel("JanusDataChannel", {ordered:false});	// FIXME Add options (ordered, maxRetransmits, etc.)
			config.dataChannel.onmessage = onDataChannelMessage;
			config.dataChannel.onopen = onDataChannelStateChange;
			config.dataChannel.onclose = onDataChannelStateChange;
			config.dataChannel.onerror = onDataChannelError;
		}
		// Create offer/answer now
		if(jsep === null || jsep === undefined) {
			createOffer(handleId, media, callbacks);
		} else {
			config.pc.setRemoteDescription(
					new RTCSessionDescription(jsep),
					function() {
						Janus.log("Remote description accepted!");
						createAnswer(handleId, media, callbacks);
					}, callbacks.error);
		}
	}

	function prepareWebrtc(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : webrtcError;
		var jsep = callbacks.jsep;
		var media = callbacks.media;
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		// Are we updating a session?
		if(config.pc !== undefined && config.pc !== null) {
			Janus.log("Updating existing media session");
			// Create offer/answer now
			if(jsep === null || jsep === undefined) {
				createOffer(handleId, media, callbacks);
			} else {
				config.pc.setRemoteDescription(
						new RTCSessionDescription(jsep),
						function() {
							Janus.log("Remote description accepted!");
							createAnswer(handleId, media, callbacks);
						}, callbacks.error);
			}
			return;
		} 
		config.trickle = isTrickleEnabled(callbacks.trickle);
		if(isAudioSendEnabled(media) || isVideoSendEnabled(media)) {
			var constraints = { mandatory: {}, optional: []};
			pluginHandle.consentDialog(true);
			var videoSupport = isVideoSendEnabled(media);
			if(videoSupport === true && media != undefined && media != null) {
				if(media.video === 'lowres') {
					// Add a video constraint (320x240)
					if(!navigator.mozGetUserMedia) {
						videoSupport = {"mandatory": {"maxHeight": "240", "maxWidth": "320"}, "optional": []};
						Janus.log("Adding media constraint (low-res video)");
						Janus.log(videoSupport);
					} else {
						Janus.log("Firefox doesn't support media constraints at the moment, ignoring low-res video");
					}
				} else if(media.video === 'hires') {
					// Add a video constraint (1280x720)
					if(!navigator.mozGetUserMedia) {
						videoSupport = {"mandatory": {"minHeight": "720", "minWidth": "1280"}, "optional": []};
						Janus.log("Adding media constraint (hi-res video)");
						Janus.log(videoSupport);
					} else {
						Janus.log("Firefox doesn't support media constraints at the moment, ignoring hi-res video");
					}
				} else if(media.video === 'screen') {
					// Not a webcam, but screen capture
					if(window.location.protocol !== 'https:') {
						// Screen sharing mandates HTTPS
						Janus.log("Screen sharing only works on HTTPS, try the https:// version of this page");
						pluginHandle.consentDialog(false);
						callbacks.error("Screen sharing only works on HTTPS, try the https:// version of this page");
						return;
					}
					if(!navigator.mozGetUserMedia) {
						videoSupport = {"mandatory": {"chromeMediaSource": "screen", "maxHeight": "720", "maxWidth": "1280"}, "optional": []};
						Janus.log("Adding media constraint (screen capture)");
						Janus.log(videoSupport);
					} else {
						Janus.log("Firefox doesn't support screen sharing at the moment");
						pluginHandle.consentDialog(false);
						callbacks.error("Firefox doesn't support screen sharing at the moment");
						return;
					}
				}
			}
			getUserMedia(
				{audio:isAudioSendEnabled(media), video:videoSupport},
				function(stream) { pluginHandle.consentDialog(false); streamsDone(handleId, jsep, media, callbacks, stream); },
				function(error) { pluginHandle.consentDialog(false); callbacks.error(error); });
		} else {
			// No need to do a getUserMedia, create offer/answer right away
			streamsDone(handleId, jsep, media, callbacks);
		}
	}

	function prepareWebrtcPeer(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : webrtcError;
		var jsep = callbacks.jsep;
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		if(jsep !== undefined && jsep !== null) {
			if(config.pc === null) {
				Janus.log("Wait, no PeerConnection?? if this is an answer, use createAnswer and not handleRemoteJsep");
				callbacks.error("No PeerConnection: if this is an answer, use createAnswer and not handleRemoteJsep");
				return;
			}
			config.pc.setRemoteDescription(
					new RTCSessionDescription(jsep),
					function() {
						Janus.log("Remote description accepted!");
						callbacks.success();
					}, callbacks.error);
		} else {
			callbacks.error("Invalid JSEP");
		}
	}

	function createOffer(handleId, media, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		Janus.log("Creating offer (iceDone=" + config.iceDone + ")");
		var mediaConstraints = {
			'mandatory': {
				'OfferToReceiveAudio':isAudioRecvEnabled(media), 
				'OfferToReceiveVideo':isVideoRecvEnabled(media)
			}
		};
		Janus.log(mediaConstraints);
		config.pc.createOffer(
			function(offer) {
				Janus.log(offer);
				if(config.mySdp === null || config.mySdp === undefined) {
					Janus.log("Setting local description");
					config.mySdp = offer.sdp;
					config.pc.setLocalDescription(offer);
				}
				if(!config.iceDone && !config.trickle) {
					// Don't do anything until we have all candidates
					Janus.log("Waiting for all candidates...");
					return;
				}
				if(config.sdpSent) {
					Janus.log("Offer already sent, not sending it again");
					return;
				}
				Janus.log("Offer ready");
				Janus.log(callbacks);
				config.sdpSent = true;
				callbacks.success(offer);
			}, callbacks.error, mediaConstraints);
	}
	
	function createAnswer(handleId, media, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		Janus.log("Creating answer (iceDone=" + config.iceDone + ")");
		var mediaConstraints = {
			'mandatory': {
				'OfferToReceiveAudio':isAudioRecvEnabled(media), 
				'OfferToReceiveVideo':isVideoRecvEnabled(media)
			}
		};
		Janus.log(mediaConstraints);
		config.pc.createAnswer(
			function(answer) {
				Janus.log(answer);
				if(config.mySdp === null || config.mySdp === undefined) {
					Janus.log("Setting local description");
					config.mySdp = answer.sdp;
					config.pc.setLocalDescription(answer);
				}
				if(!config.iceDone && !config.trickle) {
					// Don't do anything until we have all candidates
					Janus.log("Waiting for all candidates...");
					return;
				}
				if(config.sdpSent) {	// FIXME badly
					Janus.log("Answer already sent, not sending it again");
					return;
				}
				config.sdpSent = true;
				callbacks.success(answer);
			}, callbacks.error, mediaConstraints);
	}

	function sendSDP(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		Janus.log("Sending offer/answer SDP...");
		if(config.mySdp === null || config.mySdp === undefined) {
			Janus.log("Local SDP instance is invalid, not sending anything...");
			return;
		}
		config.mySdp = config.pc.localDescription;
		if(config.sdpSent) {
			Janus.log("Offer/Answer SDP already sent, not sending it again");
			return;
		}
		Janus.log(callbacks);
		config.sdpSent = true;
		callbacks.success(config.mySdp);
	}

	function getBitrate(handleId) {
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		//~ Janus.log(pluginHandle);
		//~ Janus.log(config);
		//~ Janus.log(config.bitrate);
		if(config.bitrate.value === undefined || config.bitrate.value === null)
			return "Feature unsupported by browser";
		return config.bitrate.value;
	}
	
	function webrtcError(error) {
		Janus.log("WebRTC error:");
		Janus.log(error);
	}

	function cleanupWebrtc(handleId) {
		Janus.log("Cleaning WebRTC stuff");
		var pluginHandle = pluginHandles[handleId];
		var config = pluginHandle.webrtcStuff;
		// Cleanup
		if(config.bitrate.timer)
			clearInterval(config.bitrate.timer);
		config.bitrate.timer = null;
		config.bitrate.bsnow = null;
		config.bitrate.bsbefore = null;
		config.bitrate.tsnow = null;
		config.bitrate.tsbefore = null;
		config.bitrate.value = null;
		if(config.myStream !== null && config.myStream !== undefined) {
			Janus.log("Stopping local stream");
			config.myStream.stop();
		}
		config.myStream = null;
		// Close PeerConnection
		try {
			config.pc.close();
		} catch(e) {
			// Do nothing
		}
		config.pc = null;
		config.mySdp = null;
		config.iceDone = false;
		config.sdpSent = false;
		config.dataChannel = null;
		config.dtmfSender = null;
		pluginHandle.oncleanup();
	}

	// Helper methods to parse a media object
	function isAudioSendEnabled(media) {
		Janus.log("isAudioSendEnabled:");
		Janus.log(media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.audio === false)
			return false;	// Generic audio has precedence
		if(media.audioSend === undefined || media.audioSend === null)
			return true;	// Default
		return (media.audioSend === true);
	}

	function isAudioRecvEnabled(media) {
		Janus.log("isAudioRecvEnabled:");
		Janus.log(media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.audio === false)
			return false;	// Generic audio has precedence
		if(media.audioRecv === undefined || media.audioRecv === null)
			return true;	// Default
		return (media.audioRecv === true);
	}

	function isVideoSendEnabled(media) {
		Janus.log("isVideoSendEnabled:");
		Janus.log(media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.video === false)
			return false;	// Generic video has precedence
		if(media.videoSend === undefined || media.videoSend === null)
			return true;	// Default
		return (media.videoSend === true);
	}

	function isVideoRecvEnabled(media) {
		Janus.log("isVideoRecvEnabled:");
		Janus.log(media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.video === false)
			return false;	// Generic video has precedence
		if(media.videoRecv === undefined || media.videoRecv === null)
			return true;	// Default
		return (media.videoRecv === true);
	}

	function isDataEnabled(media) {
		Janus.log("isDataEnabled:");
		Janus.log(media);
		if(media === undefined || media === null)
			return false;	// Default
		return (media.data === true);
	}

	function isTrickleEnabled(trickle) {
		Janus.log("isTrickleEnabled:");
		Janus.log(trickle);
		if(trickle === undefined || trickle === null)
			return true;	// Default is true
		return (trickle === true);
	}
};
