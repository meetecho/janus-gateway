// List of sessions
Janus.sessions = {};

// Screensharing Chrome Extension ID
Janus.extensionId = "hapfgfdkleiggjjpfpenajgdnfckjpaj";
Janus.isExtensionEnabled = function() {
	if(window.navigator.userAgent.match('Chrome')) {
		var chromever = parseInt(window.navigator.userAgent.match(/Chrome\/(.*) /)[1], 10);
		var maxver = 33;
		if(window.navigator.userAgent.match('Linux'))
			maxver = 35;	// "known" crash in chrome 34 and 35 on linux
		if(chromever >= 26 && chromever <= maxver) {
			// Older versions of Chrome don't support this extension-based approach, so lie
			return true;
		}
		return ($('#janus-extension-installed').length > 0);
	} else {
		// Firefox of others, no need for the extension (but this doesn't mean it will work)
		return true;
	}
};

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
		// Console logging (all debugging disabled by default)
		Janus.trace = Janus.noop;
		Janus.debug = Janus.noop;
		Janus.log = Janus.noop;
		Janus.warn = Janus.noop;
		Janus.error = Janus.noop;
		if(options.debug === true || options.debug === "all") {
			// Enable all debugging levels
			Janus.trace = console.trace.bind(console);
			Janus.debug = console.debug.bind(console);
			Janus.log = console.log.bind(console);
			Janus.warn = console.warn.bind(console);
			Janus.error = console.error.bind(console);
		} else if($.isArray(options.debug)) {
			for(var i in options.debug) {
				var d = options.debug[i];
				switch(d) {
					case "trace":
						Janus.trace = console.trace.bind(console);
						break;
					case "debug":
						Janus.debug = console.debug.bind(console);
						break;
					case "log":
						Janus.log = console.log.bind(console);
						break;
					case "warn":
						Janus.warn = console.warn.bind(console);
						break;
					case "error":
						Janus.error = console.error.bind(console);
						break;
					default:
						console.error("Unknown debugging option '" + d + "' (supported: 'trace', 'debug', 'log', warn', 'error')");
						break;
				}
			}
		}
		Janus.log("Initializing library");
		Janus.initDone = true;
		// Detect tab close
		window.onbeforeunload = function() {
			Janus.log("Closing window");
			for(var s in Janus.sessions) {
				if(Janus.sessions[s] !== null && Janus.sessions[s] !== undefined &&
						Janus.sessions[s].destroyOnUnload) {
					Janus.log("Destroying session " + s);
					Janus.sessions[s].destroy();
				}
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
			if(src === 'adapter.js') {
				if(window.RTCPeerConnection) {
					// Already loaded
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
		Janus.debug(servers);
	} else {
		if(server.indexOf("ws") === 0) {
			websockets = true;
			Janus.log("Using WebSockets to contact Janus: " + server);
		} else {
			websockets = false;
			Janus.log("Using REST API to contact Janus: " + server);
		}
	}
	var iceServers = gatewayCallbacks.iceServers;
	if(iceServers === undefined || iceServers === null)
		iceServers = [{"url": "stun:stun.l.google.com:19302"}];
	// Whether IPv6 candidates should be gathered
	var ipv6Support = gatewayCallbacks.ipv6;
	if(ipv6Support === undefined || ipv6Support === null)
		ipv6Support = false;
	// Optional max events
	var maxev = null;
	if(gatewayCallbacks.max_poll_events !== undefined && gatewayCallbacks.max_poll_events !== null)
		maxev = gatewayCallbacks.max_poll_events;
	if(maxev < 1)
		maxev = 1;
	// Token to use (only if the token based authentication mechanism is enabled)
	var token = null;
	if(gatewayCallbacks.token !== undefined && gatewayCallbacks.token !== null)
		token = gatewayCallbacks.token;
	// API secret to use (only if the shared API secret is enabled)
	var apisecret = null;
	if(gatewayCallbacks.apisecret !== undefined && gatewayCallbacks.apisecret !== null)
		apisecret = gatewayCallbacks.apisecret;
	// Whether we should destroy this session when onbeforeunload is called
	this.destroyOnUnload = true;
	if(gatewayCallbacks.destroyOnUnload !== undefined && gatewayCallbacks.destroyOnUnload !== null)
		this.destroyOnUnload = (gatewayCallbacks.destroyOnUnload === true);

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
		Janus.debug('Long poll...');
		if(!connected) {
			Janus.warn("Is the gateway down? (connected=false)");
			return;
		}
		var longpoll = server + "/" + sessionId + "?rid=" + new Date().getTime();
		if(maxev !== undefined && maxev !== null)
			longpoll = longpoll + "&maxev=" + maxev;
		if(token !== null && token !== undefined)
			longpoll = longpoll + "&token=" + token;
		if(apisecret !== null && apisecret !== undefined)
			longpoll = longpoll + "&apisecret=" + apisecret;
		$.ajax({
			type: 'GET',
			url: longpoll,
			cache: false,
			timeout: 60000,	// FIXME
			success: handleEvent,
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);
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
		Janus.debug("Got event on session " + sessionId);
		Janus.debug(json);
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
			// Just an ack, we can probably ignore
			var transaction = json["transaction"];
			if(transaction !== null && transaction !== undefined) {
				var reportSuccess = transactions[transaction];
				if(reportSuccess !== null && reportSuccess !== undefined) {
					reportSuccess(json);
				}
				delete transactions[transaction];
			}
			return;
		} else if(json["janus"] === "success") {
			// Success!
			var transaction = json["transaction"];
			if(transaction !== null && transaction !== undefined) {
				var reportSuccess = transactions[transaction];
				if(reportSuccess !== null && reportSuccess !== undefined) {
					reportSuccess(json);
				}
				delete transactions[transaction];
			}
			return;
		} else if(json["janus"] === "webrtcup") {
			// The PeerConnection with the gateway is up! FIXME Should we notify this?
			return;
		} else if(json["janus"] === "hangup") {
			// A plugin asked the core to hangup a PeerConnection on one of our handles
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.warn("Missing sender...");
				return;
			}
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.warn("This handle is not attached to this session");
				return;
			}
			pluginHandle.hangup();
		} else if(json["janus"] === "detached") {
			// A plugin asked the core to detach one of our handles
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.warn("Missing sender...");
				return;
			}
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.warn("This handle is not attached to this session");
				return;
			}
			pluginHandle.ondetached();
			pluginHandle.detach();
		} else if(json["janus"] === "error") {
			// Oops, something wrong happened
			Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
			var transaction = json["transaction"];
			if(transaction !== null && transaction !== undefined) {
				var reportSuccess = transactions[transaction];
				if(reportSuccess !== null && reportSuccess !== undefined) {
					reportSuccess(json);
				}
				delete transactions[transaction];
			}
			return;
		} else if(json["janus"] === "event") {
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.warn("Missing sender...");
				return;
			}
			var plugindata = json["plugindata"];
			if(plugindata === undefined || plugindata === null) {
				Janus.warn("Missing plugindata...");
				return;
			}
			Janus.debug("  -- Event is coming from " + sender + " (" + plugindata["plugin"] + ")");
			var data = plugindata["data"];
			Janus.debug(data);
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.warn("This handle is not attached to this session");
				return;
			}
			var jsep = json["jsep"];
			if(jsep !== undefined && jsep !== null) {
				Janus.debug("Handling SDP as well...");
				Janus.debug(jsep);
			}
			var callback = pluginHandle.onmessage;
			if(callback !== null && callback !== undefined) {
				Janus.debug("Notifying application...");
				// Send to callback specified when attaching plugin handle
				callback(data, jsep);
			} else {
				// Send to generic callback (?)
				Janus.debug("No provided notification callback");
			}
		} else {
			Janus.warn("Unknown message '" + json["janus"] + "'");
		}
	}
	
	// Private helper to send keep-alive messages on WebSockets
	function keepAlive() {
		if(server === null || !websockets || !connected)
			return;
		setTimeout(keepAlive, 30000);
		var request = { "janus": "keepalive", "session_id": sessionId, "transaction": randomString(12) };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = a;
		ws.send(JSON.stringify(request));
	}

	// Private method to create a session
	function createSession(callbacks) {
		var transaction = randomString(12);
		var request = { "janus": "create", "transaction": transaction };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		if(server === null && $.isArray(servers)) {
			// We still need to find a working server from the list we were given
			server = servers[serversIndex];
			if(server.indexOf("ws") === 0) {
				websockets = true;
				Janus.log("Server #" + (serversIndex+1) + ": trying WebSockets to contact Janus (" + server + ")");
			} else {
				websockets = false;
				Janus.log("Server #" + (serversIndex+1) + ": trying REST API to contact Janus (" + server + ")");
			}
		}
		if(websockets) {
			ws = new WebSocket(server, 'janus-protocol'); 
			ws.onerror = function() {
				Janus.error("Error connecting to the Janus WebSockets server... " + server);
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
					Janus.debug(json);
					if(json["janus"] !== "success") {
						Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
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
				Janus.debug(json);
				if(json["janus"] !== "success") {
					Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
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
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
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
			Janus.warn("Is the gateway down? (connected=false)");
			callbacks.success();
			return;
		}
		if(sessionId === undefined || sessionId === null) {
			Janus.warn("No session to destroy");
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
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
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
				Janus.debug(json);
				sessionId = null;
				connected = false;
				if(json["janus"] !== "success") {
					Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				}
				callbacks.success();
				gatewayCallbacks.destroyed();
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
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
			Janus.warn("Is the gateway down? (connected=false)");
			callbacks.error("Is the gateway down? (connected=false)");
			return;
		}
		var plugin = callbacks.plugin;
		if(plugin === undefined || plugin === null) {
			Janus.error("Invalid plugin");
			callbacks.error("Invalid plugin");
			return;
		}
		var transaction = randomString(12);
		var request = { "janus": "attach", "plugin": plugin, "transaction": transaction };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		if(websockets) {
			transactions[transaction] = function(json) {
				Janus.debug(json);
				if(json["janus"] !== "success") {
					Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
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
							streamExternal : false,
							remoteStream : null,
							mySdp : null,
							pc : null,
							dataChannel : null,
							dtmfSender : null,
							trickle : true,
							iceDone : false,
							sdpSent : false,
							volume : {
								value : null,
								timer : null
							},
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
						getVolume : function() { return getVolume(handleId); },
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
				Janus.debug(json);
				if(json["janus"] !== "success") {
					Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
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
							streamExternal : false,
							remoteStream : null,
							mySdp : null,
							pc : null,
							dataChannel : null,
							dtmfSender : null,
							trickle : true,
							iceDone : false,
							sdpSent : false,
							volume : {
								value : null,
								timer : null
							},
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
						getVolume : function() { return getVolume(handleId); },
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
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
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
			Janus.warn("Is the gateway down? (connected=false)");
			callbacks.error("Is the gateway down? (connected=false)");
			return;
		}
		var message = callbacks.message;
		var jsep = callbacks.jsep;
		var transaction = randomString(12);
		var request = { "janus": "message", "body": message, "transaction": transaction };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		if(jsep !== null && jsep !== undefined)
			request.jsep = jsep;
		Janus.debug("Sending message to plugin (handle=" + handleId + "):");
		Janus.debug(request);
		if(websockets) {
			request["session_id"] = sessionId;
			request["handle_id"] = handleId;
			transactions[transaction] = function(json) {
				Janus.debug("Message sent!");
				Janus.debug(json);
				if(json["janus"] === "success") {
					// We got a success, must have been a synchronous transaction
					var plugindata = json["plugindata"];
					if(plugindata === undefined || plugindata === null) {
						Janus.warn("Request succeeded, but missing plugindata...");
						callbacks.success();
						return;
					}
					Janus.log("Synchronous transaction successful (" + plugindata["plugin"] + ")");
					var data = plugindata["data"];
					Janus.debug(data);
					callbacks.success(data);
					return;
				} else if(json["janus"] !== "ack") {
					// Not a success and not an ack, must be an error
					if(json["error"] !== undefined && json["error"] !== null) {
						Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
						callbacks.error(json["error"].code + " " + json["error"].reason);
					} else {
						Janus.error("Unknown error");	// FIXME
						callbacks.error("Unknown error");
					}
					return;
				}
				// If we got here, the plugin decided to handle the request asynchronously
				callbacks.success();
			};
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
				Janus.debug("Message sent!");
				Janus.debug(json);
				if(json["janus"] === "success") {
					// We got a success, must have been a synchronous transaction
					var plugindata = json["plugindata"];
					if(plugindata === undefined || plugindata === null) {
						Janus.warn("Request succeeded, but missing plugindata...");
						callbacks.success();
						return;
					}
					Janus.log("Synchronous transaction successful (" + plugindata["plugin"] + ")");
					var data = plugindata["data"];
					Janus.debug(data);
					callbacks.success(data);
					return;
				} else if(json["janus"] !== "ack") {
					// Not a success and not an ack, must be an error
					if(json["error"] !== undefined && json["error"] !== null) {
						Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
						callbacks.error(json["error"].code + " " + json["error"].reason);
					} else {
						Janus.error("Unknown error");	// FIXME
						callbacks.error("Unknown error");
					}
					return;
				}
				// If we got here, the plugin decided to handle the request asynchronously
				callbacks.success();
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
				callbacks.error(textStatus + ": " + errorThrown);
			},
			dataType: "json"
		});
	}

	// Private method to send a trickle candidate
	function sendTrickleCandidate(handleId, candidate) {
		if(!connected) {
			Janus.warn("Is the gateway down? (connected=false)");
			return;
		}
		var request = { "janus": "trickle", "candidate": candidate, "transaction": randomString(12) };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		Janus.debug("Sending trickle candidate (handle=" + handleId + "):");
		Janus.debug(request);
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
				Janus.debug("Candidate sent!");
				Janus.debug(json);
				if(json["janus"] !== "ack") {
					Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
					return;
				}
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
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
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = pluginHandle.webrtcStuff;
		var text = callbacks.text;
		if(text === null || text === undefined) {
			Janus.warn("Invalid text");
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
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = pluginHandle.webrtcStuff;
		if(config.dtmfSender === null || config.dtmfSender === undefined) {
			// Create the DTMF sender, if possible
			if(config.myStream !== undefined && config.myStream !== null) {
				var tracks = config.myStream.getAudioTracks();
				if(tracks !== null && tracks !== undefined && tracks.length > 0) {
					var local_audio_track = tracks[0];
					config.dtmfSender = config.pc.createDTMFSender(local_audio_track);
					Janus.log("Created DTMF Sender");
					config.dtmfSender.ontonechange = function(tone) { Janus.debug("Sent DTMF tone: " + tone.tone); };
				}
			}
			if(config.dtmfSender === null || config.dtmfSender === undefined) {
				Janus.warn("Invalid DTMF configuration");
				callbacks.error("Invalid DTMF configuration");
				return;
			}
		}
		var dtmf = callbacks.dtmf;
		if(dtmf === null || dtmf === undefined) {
			Janus.warn("Invalid DTMF parameters");
			callbacks.error("Invalid DTMF parameters");
			return;
		}
		var tones = dtmf.tones;
		if(tones === null || tones === undefined) {
			Janus.warn("Invalid DTMF string");
			callbacks.error("Invalid DTMF string");
			return;
		}
		var duration = dtmf.duration;
		if(duration === null || duration === undefined)
			duration = 500;	// We choose 500ms as the default duration for a tone 
		var gap = dtmf.gap;
		if(gap === null || gap === undefined)
			gap = 50;	// We choose 50ms as the default gap between tones
		Janus.debug("Sending DTMF string " + tones + " (duration " + duration + "ms, gap " + gap + "ms"); 
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
			Janus.warn("Is the gateway down? (connected=false)");
			callbacks.error("Is the gateway down? (connected=false)");
			return;
		}
		var request = { "janus": "detach", "transaction": randomString(12) };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		if(websockets) {
			request["session_id"] = sessionId;
			request["handle_id"] = handleId;
			ws.send(JSON.stringify(request));
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
				Janus.debug(json);
				if(json["janus"] !== "success") {
					Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				}
				delete pluginHandles[handleId];
				callbacks.success();
			},
			error: function(XMLHttpRequest, textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
				// We cleanup anyway
				delete pluginHandles[handleId];
				callbacks.success();
			},
			dataType: "json"
		});
	}
	
	// WebRTC stuff
	function streamsDone(handleId, jsep, media, callbacks, stream) {
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = pluginHandle.webrtcStuff;
		Janus.debug("streamsDone:", stream);
		config.myStream = stream;
		var pc_config = {"iceServers": iceServers};
		//~ var pc_constraints = {'mandatory': {'MozDontOfferDataChannel':true}};
		var pc_constraints = {
			"optional": [{"DtlsSrtpKeyAgreement": true}]
		};
		if(ipv6Support === true) {
			// FIXME This is only supported in Chrome right now
			// For support in Firefox track this: https://bugzilla.mozilla.org/show_bug.cgi?id=797262 
			pc_constraints.optional.push({"googIPv6":true});
		}
		Janus.log("Creating PeerConnection");
		Janus.debug(pc_constraints);
		config.pc = new RTCPeerConnection(pc_config, pc_constraints);
		Janus.debug(config.pc);
		if(config.pc.getStats) {	// FIXME
			config.volume.value = 0;
			config.bitrate.value = "0 kbits/sec";
		}
		Janus.log("Preparing local SDP and gathering candidates (trickle=" + config.trickle + ")"); 
		config.pc.onicecandidate = function(event) {
			if (event.candidate == null ||
					(webrtcDetectedBrowser === 'edge' && event.candidate.candidate.indexOf('endOfCandidates') > 0)) {
				Janus.log("End of candidates.");
				config.iceDone = true;
				if(config.trickle === true) {
					// Notify end of candidates
					sendTrickleCandidate(handleId, {"completed": true});
				} else {
					// No trickle, time to send the complete SDP (including all candidates) 
					sendSDP(handleId, callbacks);
				}
			} else {
				// JSON.stringify doesn't work on some WebRTC objects anymore
				// See https://code.google.com/p/chromium/issues/detail?id=467366
				var candidate = {
					"candidate": event.candidate.candidate,
					"sdpMid": event.candidate.sdpMid,
					"sdpMLineIndex": event.candidate.sdpMLineIndex
				};
				Janus.debug("candidates: " + JSON.stringify(candidate));
				if(config.trickle === true) {
					// Send candidate
					sendTrickleCandidate(handleId, candidate);
				}
			}
		};
		if(stream !== null && stream !== undefined) {
			Janus.log('Adding local stream');
			config.pc.addStream(stream);
			pluginHandle.onlocalstream(stream);
		}
		config.pc.onaddstream = function(remoteStream) {
			Janus.log("Handling Remote Stream");
			Janus.debug(remoteStream);
			config.remoteStream = remoteStream;
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
				var dcState = config.dataChannel !== null ? config.dataChannel.readyState : "null";
				Janus.log('State change on data channel: ' + dcState);
				if(dcState === 'open') {
					pluginHandle.ondataopen();	// FIXME
				}
			}
			var onDataChannelError = function(error) {
				Janus.error('Got error on data channel:', error);
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
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
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
		// Was a MediaStream object passed, or do we need to take care of that?
		if(callbacks.stream !== null && callbacks.stream !== undefined) {
			var stream = callbacks.stream;
			Janus.log("MediaStream provided by the application");
			Janus.debug(stream);
			// Skip the getUserMedia part
			config.streamExternal = true;
			streamsDone(handleId, jsep, media, callbacks, stream);
			return;
		}
		config.trickle = isTrickleEnabled(callbacks.trickle);
		if(isAudioSendEnabled(media) || isVideoSendEnabled(media)) {
			var constraints = { mandatory: {}, optional: []};
			pluginHandle.consentDialog(true);
			var videoSupport = isVideoSendEnabled(media);
			if(videoSupport === true && media != undefined && media != null) {
				if(media.video && media.video != 'screen') {
					var width = 0;
					var height = 0, maxHeight = 0;
					if(media.video === 'lowres') {
						// Small resolution, 4:3
						height = 240;
						maxHeight = 240;
						width = 320;
					} else if(media.video === 'lowres-16:9') {
						// Small resolution, 16:9
						height = 180;
						maxHeight = 180;
						width = 320;
					} else if(media.video === 'hires' || media.video === 'hires-16:9' ) {
						// High resolution is only 16:9
						height = 720;
						maxHeight = 720;
						width = 1280;
						if(navigator.mozGetUserMedia) {
							var firefoxVer = parseInt(window.navigator.userAgent.match(/Firefox\/(.*)/)[1], 10);
							if(firefoxVer < 38) {
								// Unless this is and old Firefox, which doesn't support it
								Janus.warn(media.video + " unsupported, falling back to stdres (old Firefox)");
								height = 480;
								maxHeight = 480;
								width  = 640;
							}
						}
					} else if(media.video === 'stdres') {
						// Normal resolution, 4:3
						height = 480;
						maxHeight = 480;
						width  = 640;
					} else if(media.video === 'stdres-16:9') {
						// Normal resolution, 16:9
						height = 360;
						maxHeight = 360;
						width = 640;
					} else {
						Janus.log("Default video setting (" + media.video + ") is stdres 4:3");
						height = 480;
						maxHeight = 480;
						width = 640;
					}
					Janus.log("Adding media constraint " + media.video);
					if(navigator.mozGetUserMedia) {
						var firefoxVer = parseInt(window.navigator.userAgent.match(/Firefox\/(.*)/)[1], 10);
						if(firefoxVer < 38) {
							videoSupport = {
								'require': ['height', 'width'],
								'height': {'max': maxHeight, 'min': height},
								'width':  {'max': width,  'min': width}
							};
						} else {
							// http://stackoverflow.com/questions/28282385/webrtc-firefox-constraints/28911694#28911694
							// https://github.com/meetecho/janus-gateway/pull/246
							videoSupport = {
								'height': {'ideal': height},
								'width':  {'ideal': width}
							};
						}
					} else {
						videoSupport = {
						    'mandatory': {
						        'maxHeight': maxHeight,
						        'minHeight': height,
						        'maxWidth':  width,
						        'minWidth':  width
						    },
						    'optional': []
						};
					}
					Janus.debug(videoSupport);
				} else if(media.video === 'screen') {
					// Not a webcam, but screen capture
					if(window.location.protocol !== 'https:') {
						// Screen sharing mandates HTTPS
						Janus.warn("Screen sharing only works on HTTPS, try the https:// version of this page");
						pluginHandle.consentDialog(false);
						callbacks.error("Screen sharing only works on HTTPS, try the https:// version of this page");
						return;
					}
					// We're going to try and use the extension for Chrome 34+, the old approach
					// for older versions of Chrome, or the experimental support in Firefox 33+
					var cache = {};
					function callbackUserMedia (error, stream) {
						pluginHandle.consentDialog(false);
						if(error) {
							callbacks.error(error);
						} else {
							streamsDone(handleId, jsep, media, callbacks, stream);
						}
					};
					function getScreenMedia(constraints, gsmCallback) {
						Janus.log("Adding media constraint (screen capture)");
						Janus.debug(constraints);
						getUserMedia(constraints,
							function(stream) {
								gsmCallback(null, stream);
							},
							function(error) {
								pluginHandle.consentDialog(false);
								gsmCallback(error);
							}
						);
					};
					if(window.navigator.userAgent.match('Chrome')) {
						var chromever = parseInt(window.navigator.userAgent.match(/Chrome\/(.*) /)[1], 10);
						var maxver = 33;
						if(window.navigator.userAgent.match('Linux'))
							maxver = 35;	// "known" crash in chrome 34 and 35 on linux
						if(chromever >= 26 && chromever <= maxver) {
							// Chrome 26->33 requires some awkward chrome://flags manipulation
							constraints = {
								video: {
									mandatory: {
										googLeakyBucket: true,
										maxWidth: window.screen.width,
										maxHeight: window.screen.height,
										maxFrameRate: 3,
										chromeMediaSource: 'screen'
									}
								},
								audio: isAudioSendEnabled(media)
							};
							getScreenMedia(constraints, callbackUserMedia);
						} else {
							// Chrome 34+ requires an extension
							var pending = window.setTimeout(
								function () {
									error = new Error('NavigatorUserMediaError');
									error.name = 'The required Chrome extension is not installed: click <a href="#">here</a> to install it. (NOTE: this will need you to refresh the page)';
									pluginHandle.consentDialog(false);
									return callbacks.error(error);
								}, 1000);
							cache[pending] = [callbackUserMedia, null];
							window.postMessage({ type: 'janusGetScreen', id: pending }, '*');
						}
					} else if (window.navigator.userAgent.match('Firefox')) {
						var ffver = parseInt(window.navigator.userAgent.match(/Firefox\/(.*)/)[1], 10);
						if(ffver >= 33) {
							// Firefox 33+ has experimental support for screen sharing
							constraints = {
								video: {
									mozMediaSource: 'window',
									mediaSource: 'window'
								},
								audio: isAudioSendEnabled(media)
							};
							getScreenMedia(constraints, function (err, stream) {
								callbackUserMedia(err, stream);
								// Workaround for https://bugzilla.mozilla.org/show_bug.cgi?id=1045810
								if (!err) {
									var lastTime = stream.currentTime;
									var polly = window.setInterval(function () {
										if(!stream)
											window.clearInterval(polly);
										if(stream.currentTime == lastTime) {
											window.clearInterval(polly);
											if(stream.onended) {
												stream.onended();
											}
										}
										lastTime = stream.currentTime;
									}, 500);
								}
							});
						} else {
							var error = new Error('NavigatorUserMediaError');
							error.name = 'Your version of Firefox does not support screen sharing, please install Firefox 33 (or more recent versions)';
							pluginHandle.consentDialog(false);
							callbacks.error(error);
							return;
						}
					}

					// Wait for events from the Chrome Extension
					window.addEventListener('message', function (event) {
						if(event.origin != window.location.origin)
							return;
						if(event.data.type == 'janusGotScreen' && cache[event.data.id]) {
							var data = cache[event.data.id];
							var callback = data[0];
							delete cache[event.data.id];

							if (event.data.sourceId === '') {
								// user canceled
								var error = new Error('NavigatorUserMediaError');
								error.name = 'You cancelled the request for permission, giving up...';
								pluginHandle.consentDialog(false);
								callbacks.error(error);
							} else {
								constraints = {
									audio: isAudioSendEnabled(media),
									video: {
										mandatory: {
										chromeMediaSource: 'desktop',
										maxWidth: window.screen.width,
										maxHeight: window.screen.height,
										maxFrameRate: 3
									},
									optional: [
										{googLeakyBucket: true},
										{googTemporalLayeredScreencast: true}
									]
								}};
								constraints.video.mandatory.chromeMediaSourceId = event.data.sourceId;
								getScreenMedia(constraints, callback);
							}
						} else if (event.data.type == 'janusGetScreenPending') {
							window.clearTimeout(event.data.id);
						}
					});
				}
			}
			// If we got here, we're not screensharing
			if(media === null || media === undefined || media.video !== 'screen') {
				// Check whether all media sources are actually available or not
				// as per https://github.com/meetecho/janus-gateway/pull/114
				MediaStreamTrack.getSources(function(sources) {
					var audioExist = sources.some(function(source) {
						return source.kind === 'audio';
					}),
					videoExist = sources.some(function(source) {
						return source.kind === 'video';
					});

					// FIXME Should we really give up, or just assume recvonly for both?
					if(!audioExist && !videoExist) {
						pluginHandle.consentDialog(false);
						callbacks.error('No capture device found');
						return false;
					}

					getUserMedia(
						{audio: audioExist && isAudioSendEnabled(media), video: videoExist ? videoSupport : false},
						function(stream) { pluginHandle.consentDialog(false); streamsDone(handleId, jsep, media, callbacks, stream); },
						function(error) { pluginHandle.consentDialog(false); callbacks.error(error); });
				});

			}
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
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = pluginHandle.webrtcStuff;
		if(jsep !== undefined && jsep !== null) {
			if(config.pc === null) {
				Janus.warn("Wait, no PeerConnection?? if this is an answer, use createAnswer and not handleRemoteJsep");
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
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = pluginHandle.webrtcStuff;
		Janus.log("Creating offer (iceDone=" + config.iceDone + ")");
		// https://code.google.com/p/webrtc/issues/detail?id=3508
		var mediaConstraints = null;
		if(webrtcDetectedBrowser == "firefox" || webrtcDetectedBrowser == "edge") {
			mediaConstraints = {
				'offerToReceiveAudio':isAudioRecvEnabled(media), 
				'offerToReceiveVideo':isVideoRecvEnabled(media)
			};
		} else {
			mediaConstraints = {
				'mandatory': {
					'OfferToReceiveAudio':isAudioRecvEnabled(media), 
					'OfferToReceiveVideo':isVideoRecvEnabled(media)
				}
			};
		}
		Janus.debug(mediaConstraints);
		config.pc.createOffer(
			function(offer) {
				Janus.debug(offer);
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
				Janus.debug(callbacks);
				config.sdpSent = true;
				// JSON.stringify doesn't work on some WebRTC objects anymore
				// See https://code.google.com/p/chromium/issues/detail?id=467366
				var jsep = {
					"type": offer.type,
					"sdp": offer.sdp
				};
				callbacks.success(jsep);
			}, callbacks.error, mediaConstraints);
	}
	
	function createAnswer(handleId, media, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = pluginHandle.webrtcStuff;
		Janus.log("Creating answer (iceDone=" + config.iceDone + ")");
		var mediaConstraints = null;
		if(webrtcDetectedBrowser == "firefox" || webrtcDetectedBrowser == "edge") {
			mediaConstraints = {
				'offerToReceiveAudio':isAudioRecvEnabled(media), 
				'offerToReceiveVideo':isVideoRecvEnabled(media)
			};
		} else {
			mediaConstraints = {
				'mandatory': {
					'OfferToReceiveAudio':isAudioRecvEnabled(media), 
					'OfferToReceiveVideo':isVideoRecvEnabled(media)
				}
			};
		}
		Janus.debug(mediaConstraints);
		config.pc.createAnswer(
			function(answer) {
				Janus.debug(answer);
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
				// JSON.stringify doesn't work on some WebRTC objects anymore
				// See https://code.google.com/p/chromium/issues/detail?id=467366
				var jsep = {
					"type": answer.type,
					"sdp": answer.sdp
				};
				callbacks.success(jsep);
			}, callbacks.error, mediaConstraints);
	}

	function sendSDP(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : jQuery.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : jQuery.noop;
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle, not sending anything");
			return;
		}
		var config = pluginHandle.webrtcStuff;
		Janus.log("Sending offer/answer SDP...");
		if(config.mySdp === null || config.mySdp === undefined) {
			Janus.warn("Local SDP instance is invalid, not sending anything...");
			return;
		}
		config.mySdp = config.pc.localDescription;
		if(config.sdpSent) {
			Janus.log("Offer/Answer SDP already sent, not sending it again");
			return;
		}
		Janus.debug(callbacks);
		config.sdpSent = true;
		callbacks.success(config.mySdp);
	}

	function getVolume(handleId) {
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			return 0;
		}
		var config = pluginHandle.webrtcStuff;
		// Start getting the volume, if getStats is supported
		if(config.pc.getStats && webrtcDetectedBrowser == "chrome") {	// FIXME
			if(config.remoteStream === null || config.remoteStream === undefined) {
				Janus.warn("Remote stream unavailable");
				return 0;
			}
			// http://webrtc.googlecode.com/svn/trunk/samples/js/demos/html/constraints-and-stats.html
			if(config.volume.timer === null || config.volume.timer === undefined) {
				Janus.log("Starting volume monitor");
				config.volume.timer = setInterval(function() {
					config.pc.getStats(function(stats) {
						var results = stats.result();
						for(var i=0; i<results.length; i++) {
							var res = results[i];
							if(res.type == 'ssrc' && res.stat('audioOutputLevel')) {
								config.volume.value = res.stat('audioOutputLevel');
							}
						}
					});
				}, 200);
				return 0;	// We don't have a volume to return yet
			}
			return config.volume.value;
		} else {
			Janus.log("Getting the remote volume unsupported by browser");
			return 0;
		}
	}
	
	function getBitrate(handleId) {
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			return "Invalid handle";
		}
		var config = pluginHandle.webrtcStuff;
		if(config.pc === null || config.pc === undefined)
			return "Invalid PeerConnection";
		// Start getting the bitrate, if getStats is supported
		if(config.pc.getStats && webrtcDetectedBrowser == "chrome") {
			// Do it the Chrome way
			if(config.remoteStream === null || config.remoteStream === undefined) {
				Janus.warn("Remote stream unavailable");
				return "Remote stream unavailable";
			}
			// http://webrtc.googlecode.com/svn/trunk/samples/js/demos/html/constraints-and-stats.html
			if(config.bitrate.timer === null || config.bitrate.timer === undefined) {
				Janus.log("Starting bitrate timer (Chrome)");
				config.bitrate.timer = setInterval(function() {
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
				return "0 kbits/sec";	// We don't have a bitrate value yet
			}
			return config.bitrate.value;
		} else if(config.pc.getStats && webrtcDetectedBrowser == "firefox") {
			// Do it the Firefox way
			if(config.remoteStream === null || config.remoteStream === undefined
					|| config.remoteStream.stream === null || config.remoteStream.stream === undefined) {
				Janus.warn("Remote stream unavailable");
				return "Remote stream unavailable";
			}
			var videoTracks = config.remoteStream.stream.getVideoTracks();
			if(videoTracks === null || videoTracks === undefined || videoTracks.length < 1) {
				Janus.warn("No video track");
				return "No video track";
			}
			// https://github.com/muaz-khan/getStats/blob/master/getStats.js
			if(config.bitrate.timer === null || config.bitrate.timer === undefined) {
				Janus.log("Starting bitrate timer (Firefox)");
				config.bitrate.timer = setInterval(function() {
					// We need a helper callback
					var cb = function(res) {
						if(res === null || res === undefined ||
								res.inbound_rtp_video_1 == null || res.inbound_rtp_video_1 == null) {
							config.bitrate.value = "Missing inbound_rtp_video_1";
							return;
						}
						config.bitrate.bsnow = res.inbound_rtp_video_1.bytesReceived;
						config.bitrate.tsnow = res.inbound_rtp_video_1.timestamp;
						if(config.bitrate.bsbefore === null || config.bitrate.tsbefore === null) {
							// Skip this round
							config.bitrate.bsbefore = config.bitrate.bsnow;
							config.bitrate.tsbefore = config.bitrate.tsnow;
						} else {
							// Calculate bitrate
							var bitRate = Math.round((config.bitrate.bsnow - config.bitrate.bsbefore) * 8 / (config.bitrate.tsnow - config.bitrate.tsbefore));
							config.bitrate.value = bitRate + ' kbits/sec';
							config.bitrate.bsbefore = config.bitrate.bsnow;
							config.bitrate.tsbefore = config.bitrate.tsnow;
						}
					};
					// Actually get the stats
					config.pc.getStats(videoTracks[0], function(stats) {
						cb(stats);
					}, cb);
				}, 1000);
				return "0 kbits/sec";	// We don't have a bitrate value yet
			}
			return config.bitrate.value;
		} else {
			Janus.warn("Getting the video bitrate unsupported by browser");
			return "Feature unsupported by browser";
		}
	}
	
	function webrtcError(error) {
		Janus.error("WebRTC error:", error);
	}

	function cleanupWebrtc(handleId) {
		Janus.log("Cleaning WebRTC stuff");
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined) {
			// Nothing to clean
			return;
		}
		var config = pluginHandle.webrtcStuff;
		if(config !== null && config !== undefined) {
			// Cleanup
			config.remoteStream = null;
			if(config.volume.timer)
				clearInterval(config.volume.timer);
			config.volume.value = null;
			if(config.bitrate.timer)
				clearInterval(config.bitrate.timer);
			config.bitrate.timer = null;
			config.bitrate.bsnow = null;
			config.bitrate.bsbefore = null;
			config.bitrate.tsnow = null;
			config.bitrate.tsbefore = null;
			config.bitrate.value = null;
			try {
				// Try a MediaStream.stop() first
				if(!config.streamExternal && config.myStream !== null && config.myStream !== undefined) {
					Janus.log("Stopping local stream");
					config.myStream.stop();
				}
			} catch(e) {
				// Do nothing if this fails
			}
			try {
				// Try a MediaStreamTrack.stop() for each track as well
				if(!config.streamExternal && config.myStream !== null && config.myStream !== undefined) {
					Janus.log("Stopping local stream tracks");
					var tracks = config.myStream.getTracks();
					for(var i in tracks) {
						var mst = tracks[i];
						Janus.log(mst);
						if(mst !== null && mst !== undefined)
							mst.stop();
					}
				}
			} catch(e) {
				// Do nothing if this fails
			}
			config.streamExternal = false;
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
		}
		pluginHandle.oncleanup();
	}

	// Helper methods to parse a media object
	function isAudioSendEnabled(media) {
		Janus.debug("isAudioSendEnabled:", media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.audio === false)
			return false;	// Generic audio has precedence
		if(media.audioSend === undefined || media.audioSend === null)
			return true;	// Default
		return (media.audioSend === true);
	}

	function isAudioRecvEnabled(media) {
		Janus.debug("isAudioRecvEnabled:", media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.audio === false)
			return false;	// Generic audio has precedence
		if(media.audioRecv === undefined || media.audioRecv === null)
			return true;	// Default
		return (media.audioRecv === true);
	}

	function isVideoSendEnabled(media) {
		Janus.debug("isVideoSendEnabled:", media);
		if(webrtcDetectedBrowser == "edge") {
			Janus.warn("Edge doesn't support compatible video yet");
			return false;
		}
		if(media === undefined || media === null)
			return true;	// Default
		if(media.video === false)
			return false;	// Generic video has precedence
		if(media.videoSend === undefined || media.videoSend === null)
			return true;	// Default
		return (media.videoSend === true);
	}

	function isVideoRecvEnabled(media) {
		Janus.debug("isVideoRecvEnabled:", media);
		if(webrtcDetectedBrowser == "edge") {
			Janus.warn("Edge doesn't support compatible video yet");
			return false;
		}
		if(media === undefined || media === null)
			return true;	// Default
		if(media.video === false)
			return false;	// Generic video has precedence
		if(media.videoRecv === undefined || media.videoRecv === null)
			return true;	// Default
		return (media.videoRecv === true);
	}

	function isDataEnabled(media) {
		Janus.debug("isDataEnabled:", media);
		if(webrtcDetectedBrowser == "edge") {
			Janus.warn("Edge doesn't support data channels yet");
			return false;
		}
		if(media === undefined || media === null)
			return false;	// Default
		return (media.data === true);
	}

	function isTrickleEnabled(trickle) {
		Janus.debug("isTrickleEnabled:", trickle);
		if(trickle === undefined || trickle === null)
			return true;	// Default is true
		return (trickle === true);
	}
};
