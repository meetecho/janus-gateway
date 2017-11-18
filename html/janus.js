/*
	The MIT License (MIT)

	Copyright (c) 2016 Meetecho

	Permission is hereby granted, free of charge, to any person obtaining
	a copy of this software and associated documentation files (the "Software"),
	to deal in the Software without restriction, including without limitation
	the rights to use, copy, modify, merge, publish, distribute, sublicense,
	and/or sell copies of the Software, and to permit persons to whom the
	Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included
	in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
	THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
	ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
	OTHER DEALINGS IN THE SOFTWARE.
 */

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
		return Janus.checkJanusExtension();
	} else {
		// Firefox of others, no need for the extension (but this doesn't mean it will work)
		return true;
	}
};

Janus.useDefaultDependencies = function (deps) {
	var f = (deps && deps.fetch) || fetch;
	var p = (deps && deps.Promise) || Promise;
	var socketCls = (deps && deps.WebSocket) || WebSocket;
	return {
		newWebSocket: function(server, proto) { return new socketCls(server, proto); },
		isArray: function(arr) { return Array.isArray(arr); },
		checkJanusExtension: function() { return document.querySelector('#janus-extension-installed') !== null; },
		webRTCAdapter: (deps && deps.adapter) || adapter,
		httpAPICall: function(url, options) {
			var fetchOptions = {method: options.verb, cache: 'no-cache'};
			if(options.withCredentials !== undefined) {
				fetchOptions.credentials = options.withCredentials === true ? 'include' : (options.withCredentials ? options.withCredentials : 'omit');
			}
			if(options.body !== undefined) {
				fetchOptions.body = JSON.stringify(options.body);
			}

			var fetching = f(url, fetchOptions).catch(function(error) {
				return p.reject({message: 'Probably a network error, is the gateway down?', error: error});
			});

			/*
			 * fetch() does not natively support timeouts.
			 * Work around this by starting a timeout manually, and racing it agains the fetch() to see which thing resolves first.
			 */

			if(options.timeout !== undefined) {
				var timeout = new p(function(resolve, reject) {
					var timerId = setTimeout(function() {
						clearTimeout(timerId);
						return reject({message: 'Request timed out', timeout: options.timeout});
					}, options.timeout);
				});
				fetching = p.race([fetching,timeout]);
			}

			fetching.then(function(response) {
				if(response.ok) {
					if(typeof(options.success) === typeof(Janus.noop)) {
						return response.json().then(function(parsed) {
							options.success(parsed);
						}).catch(function(error) {
							return p.reject({message: 'Failed to parse response body', error: error, response: response});
						});
					}
				}
				else {
					return p.reject({message: 'API call failed', response: response});
				}
			}).catch(function(error) {
				if(typeof(options.error) === typeof(Janus.noop)) {
					options.error(error.message || '<< internal error >>', error);
				}
			});

			return fetching;
		}
	}
};

Janus.useOldDependencies = function (deps) {
	var jq = (deps && deps.jQuery) || jQuery;
	var socketCls = (deps && deps.WebSocket) || WebSocket;
	return {
		newWebSocket: function(server, proto) { return new socketCls(server, proto); },
		isArray: function(arr) { return jq.isArray(arr); },
		checkJanusExtension: function() { return jq('#janus-extension-installed').length > 0; },
		webRTCAdapter: (deps && deps.adapter) || adapter,
		httpAPICall: function(url, options) {
			var payload = options.body !== undefined ? {
				contentType: 'application/json',
				data: JSON.stringify(options.body)
			} : {};
			var credentials = options.withCredentials !== undefined ? {xhrFields: {withCredentials: options.withCredentials}} : {};

			return jq.ajax(jq.extend(payload, credentials, {
				url: url,
				type: options.verb,
				cache: false,
				dataType: 'json',
				async: options.async,
				timeout: options.timeout,
				success: function(result) {
					if(typeof(options.success) === typeof(Janus.noop)) {
						options.success(result);
					}
				},
				error: function(xhr, status, err) {
					if(typeof(options.error) === typeof(Janus.noop)) {
						options.error(status, err);
					}
				}
			}));
		},
	};
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
		Janus.vdebug = Janus.noop;
		Janus.log = Janus.noop;
		Janus.warn = Janus.noop;
		Janus.error = Janus.noop;
		if(options.debug === true || options.debug === "all") {
			// Enable all debugging levels
			Janus.trace = console.trace.bind(console);
			Janus.debug = console.debug.bind(console);
			Janus.vdebug = console.debug.bind(console);
			Janus.log = console.log.bind(console);
			Janus.warn = console.warn.bind(console);
			Janus.error = console.error.bind(console);
		} else if(Array.isArray(options.debug)) {
			for(var i in options.debug) {
				var d = options.debug[i];
				switch(d) {
					case "trace":
						Janus.trace = console.trace.bind(console);
						break;
					case "debug":
						Janus.debug = console.debug.bind(console);
						break;
					case "vdebug":
						Janus.vdebug = console.debug.bind(console);
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
						console.error("Unknown debugging option '" + d + "' (supported: 'trace', 'debug', 'vdebug', 'log', warn', 'error')");
						break;
				}
			}
		}
		Janus.log("Initializing library");

		var usedDependencies = options.dependencies || Janus.useDefaultDependencies();
		Janus.isArray = usedDependencies.isArray;
		Janus.webRTCAdapter = usedDependencies.webRTCAdapter;
		Janus.httpAPICall = usedDependencies.httpAPICall;
		Janus.checkJanusExtension = usedDependencies.checkJanusExtension;
		Janus.newWebSocket = usedDependencies.newWebSocket;

		// Helper method to enumerate devices
		Janus.listDevices = function(callback, config) {
			callback = (typeof callback == "function") ? callback : Janus.noop;
			if (config == null) config = { audio: true, video: true };
			if(navigator.mediaDevices) {
				navigator.mediaDevices.getUserMedia(config)
				.then(function(stream) {
					navigator.mediaDevices.enumerateDevices().then(function(devices) {
						Janus.debug(devices);
						callback(devices);
						// Get rid of the now useless stream
						try {
							var tracks = stream.getTracks();
							for(var i in tracks) {
								var mst = tracks[i];
								if(mst !== null && mst !== undefined)
									mst.stop();
							}
						} catch(e) {}
					});
				})
				.catch(function(err) {
					Janus.error(err);
					callback([]);
				});
			} else {
				Janus.warn("navigator.mediaDevices unavailable");
				callback([]);
			}
		}
		// Helper methods to attach/reattach a stream to a video element (previously part of adapter.js)
		Janus.attachMediaStream = function(element, stream) {
			if(Janus.webRTCAdapter.browserDetails.browser === 'chrome') {
				var chromever = Janus.webRTCAdapter.browserDetails.version;
				if(chromever >= 43) {
					element.srcObject = stream;
				} else if(typeof element.src !== 'undefined') {
					element.src = URL.createObjectURL(stream);
				} else {
					Janus.error("Error attaching stream to element");
				}
			} else {
				element.srcObject = stream;
			}
		};
		Janus.reattachMediaStream = function(to, from) {
			if(Janus.webRTCAdapter.browserDetails.browser === 'chrome') {
				var chromever = Janus.webRTCAdapter.browserDetails.version;
				if(chromever >= 43) {
					to.srcObject = from.srcObject;
				} else if(typeof to.src !== 'undefined') {
					to.src = from.src;
				} else {
					Janus.error("Error reattaching stream to element");
				}
			} else {
				to.srcObject = from.srcObject;
			}
		};
		// Detect tab close: make sure we don't loose existing onbeforeunload handlers
		var oldOBF = window.onbeforeunload;
		window.onbeforeunload = function() {
			Janus.log("Closing window");
			for(var s in Janus.sessions) {
				if(Janus.sessions[s] !== null && Janus.sessions[s] !== undefined &&
						Janus.sessions[s].destroyOnUnload) {
					Janus.log("Destroying session " + s);
					Janus.sessions[s].destroy({asyncRequest: false});
				}
			}
			if(oldOBF && typeof oldOBF == "function")
				oldOBF();
		}
		Janus.initDone = true;
		options.callback();
	}
};

// Helper method to check whether WebRTC is supported by this browser
Janus.isWebrtcSupported = function() {
	return window.RTCPeerConnection !== undefined && window.RTCPeerConnection !== null &&
		navigator.getUserMedia !== undefined && navigator.getUserMedia !== null;
};

// Helper method to create random identifiers (e.g., transaction)
Janus.randomString = function(len) {
	var charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	var randomString = '';
	for (var i = 0; i < len; i++) {
		var randomPoz = Math.floor(Math.random() * charSet.length);
		randomString += charSet.substring(randomPoz,randomPoz+1);
	}
	return randomString;
}


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
	gatewayCallbacks.success = (typeof gatewayCallbacks.success == "function") ? gatewayCallbacks.success : Janus.noop;
	gatewayCallbacks.error = (typeof gatewayCallbacks.error == "function") ? gatewayCallbacks.error : Janus.noop;
	gatewayCallbacks.destroyed = (typeof gatewayCallbacks.destroyed == "function") ? gatewayCallbacks.destroyed : Janus.noop;
	if(gatewayCallbacks.server === null || gatewayCallbacks.server === undefined) {
		gatewayCallbacks.error("Invalid gateway url");
		return {};
	}
	var websockets = false;
	var ws = null;
	var wsHandlers = {};
	var wsKeepaliveTimeoutId = null;

	var servers = null, serversIndex = 0;
	var server = gatewayCallbacks.server;
	if(Janus.isArray(server)) {
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
		iceServers = [{urls: "stun:stun.l.google.com:19302"}];
	var iceTransportPolicy = gatewayCallbacks.iceTransportPolicy;
	var bundlePolicy = gatewayCallbacks.bundlePolicy;
	// Whether IPv6 candidates should be gathered
	var ipv6Support = gatewayCallbacks.ipv6;
	if(ipv6Support === undefined || ipv6Support === null)
		ipv6Support = false;
	// Whether we should enable the withCredentials flag for XHR requests
	var withCredentials = false;
	if(gatewayCallbacks.withCredentials !== undefined && gatewayCallbacks.withCredentials !== null)
		withCredentials = gatewayCallbacks.withCredentials === true;
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
		Janus.httpAPICall(longpoll, {
			verb: 'GET',
			withCredentials: withCredentials,
			success: handleEvent,
			timeout: 60000,	// FIXME
			error: function(textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);
				retries++;
				if(retries > 3) {
					// Did we just lose the gateway? :-(
					connected = false;
					gatewayCallbacks.error("Lost connection to the gateway (is it down?)");
					return;
				}
				eventHandler();
			}
		});
	}

	// Private event handler: this will trigger plugin callbacks, if set
	function handleEvent(json, skipTimeout) {
		retries = 0;
		if(!websockets && sessionId !== undefined && sessionId !== null && skipTimeout !== true)
			setTimeout(eventHandler, 200);
		if(!websockets && Janus.isArray(json)) {
			// We got an array: it means we passed a maxev > 1, iterate on all objects
			for(var i=0; i<json.length; i++) {
				handleEvent(json[i], true);
			}
			return;
		}
		if(json["janus"] === "keepalive") {
			// Nothing happened
			Janus.vdebug("Got a keepalive on session " + sessionId);
			return;
		} else if(json["janus"] === "ack") {
			// Just an ack, we can probably ignore
			Janus.debug("Got an ack on session " + sessionId);
			Janus.debug(json);
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
			Janus.debug("Got a success on session " + sessionId);
			Janus.debug(json);
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
			// The PeerConnection with the gateway is up! Notify this
			Janus.debug("Got a webrtcup event on session " + sessionId);
			Janus.debug(json);
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.warn("Missing sender...");
				return;
			}
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.debug("This handle is not attached to this session");
				return;
			}
			pluginHandle.webrtcState(true);
			return;
		} else if(json["janus"] === "hangup") {
			// A plugin asked the core to hangup a PeerConnection on one of our handles
			Janus.debug("Got a hangup event on session " + sessionId);
			Janus.debug(json);
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.warn("Missing sender...");
				return;
			}
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.debug("This handle is not attached to this session");
				return;
			}
			pluginHandle.webrtcState(false, json["reason"]);
			pluginHandle.hangup();
		} else if(json["janus"] === "detached") {
			// A plugin asked the core to detach one of our handles
			Janus.debug("Got a detached event on session " + sessionId);
			Janus.debug(json);
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.warn("Missing sender...");
				return;
			}
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				// Don't warn here because destroyHandle causes this situation.
				return;
			}
			pluginHandle.detached = true;
			pluginHandle.ondetached();
			pluginHandle.detach();
		} else if(json["janus"] === "media") {
			// Media started/stopped flowing
			Janus.debug("Got a media event on session " + sessionId);
			Janus.debug(json);
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.warn("Missing sender...");
				return;
			}
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.debug("This handle is not attached to this session");
				return;
			}
			pluginHandle.mediaState(json["type"], json["receiving"]);
		} else if(json["janus"] === "slowlink") {
			Janus.debug("Got a slowlink event on session " + sessionId);
			Janus.debug(json);
			// Trouble uplink or downlink
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				Janus.warn("Missing sender...");
				return;
			}
			var pluginHandle = pluginHandles[sender];
			if(pluginHandle === undefined || pluginHandle === null) {
				Janus.debug("This handle is not attached to this session");
				return;
			}
			pluginHandle.slowLink(json["uplink"], json["nacks"]);
		} else if(json["janus"] === "error") {
			// Oops, something wrong happened
			Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
			Janus.debug(json);
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
			Janus.debug("Got a plugin event on session " + sessionId);
			Janus.debug(json);
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
			Janus.warn("Unkown message/event  '" + json["janus"] + "' on session " + sessionId);
			Janus.debug(json);
		}
	}

	// Private helper to send keep-alive messages on WebSockets
	function keepAlive() {
		if(server === null || !websockets || !connected)
			return;
		wsKeepaliveTimeoutId = setTimeout(keepAlive, 30000);
		var request = { "janus": "keepalive", "session_id": sessionId, "transaction": Janus.randomString(12) };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		ws.send(JSON.stringify(request));
	}

	// Private method to create a session
	function createSession(callbacks) {
		var transaction = Janus.randomString(12);
		var request = { "janus": "create", "transaction": transaction };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		if(server === null && Janus.isArray(servers)) {
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
			ws = Janus.newWebSocket(server, 'janus-protocol');
			wsHandlers = {
				'error': function() {
					Janus.error("Error connecting to the Janus WebSockets server... " + server);
					if (Janus.isArray(servers)) {
						serversIndex++;
						if (serversIndex == servers.length) {
							// We tried all the servers the user gave us and they all failed
							callbacks.error("Error connecting to any of the provided Janus servers: Is the gateway down?");
							return;
						}
						// Let's try the next server
						server = null;
						setTimeout(function() {
							createSession(callbacks);
						}, 200);
						return;
					}
					callbacks.error("Error connecting to the Janus WebSockets server: Is the gateway down?");
				},

				'open': function() {
					// We need to be notified about the success
					transactions[transaction] = function(json) {
						Janus.debug(json);
						if (json["janus"] !== "success") {
							Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
							callbacks.error(json["error"].reason);
							return;
						}
						wsKeepaliveTimeoutId = setTimeout(keepAlive, 30000);
						connected = true;
						sessionId = json.data["id"];
						Janus.log("Created session: " + sessionId);
						Janus.sessions[sessionId] = that;
						callbacks.success();
					};
					ws.send(JSON.stringify(request));
				},

				'message': function(event) {
					handleEvent(JSON.parse(event.data));
				},

				'close': function() {
					if (server === null || !connected) {
						return;
					}
					connected = false;
					// FIXME What if this is called when the page is closed?
					gatewayCallbacks.error("Lost connection to the gateway (is it down?)");
				}
			};

			for(var eventName in wsHandlers) {
				ws.addEventListener(eventName, wsHandlers[eventName]);
			}

			return;
		}
		Janus.httpAPICall(server, {
			verb: 'POST',
			withCredentials: withCredentials,
			body: request,
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
			error: function(textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
				if(Janus.isArray(servers)) {
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
			}
		});
	}

	// Private method to destroy a session
	function destroySession(callbacks) {
		callbacks = callbacks || {};
		// FIXME This method triggers a success even when we fail
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
		var asyncRequest = true;
		if(callbacks.asyncRequest !== undefined && callbacks.asyncRequest !== null)
			asyncRequest = (callbacks.asyncRequest === true);
		Janus.log("Destroying session " + sessionId + " (async=" + asyncRequest + ")");
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
		// No need to destroy all handles first, Janus will do that itself
		var request = { "janus": "destroy", "transaction": Janus.randomString(12) };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		if(websockets) {
			request["session_id"] = sessionId;

			var unbindWebSocket = function() {
				for(var eventName in wsHandlers) {
					ws.removeEventListener(eventName, wsHandlers[eventName]);
				}
				ws.removeEventListener('message', onUnbindMessage);
				ws.removeEventListener('error', onUnbindError);
				if(wsKeepaliveTimeoutId) {
					clearTimeout(wsKeepaliveTimeoutId);
				}
			};

			var onUnbindMessage = function(event){
				var data = JSON.parse(event.data);
				if(data.session_id == request.session_id && data.transaction == request.transaction) {
					unbindWebSocket();
					callbacks.success();
					gatewayCallbacks.destroyed();
				}
			};
			var onUnbindError = function(event) {
				unbindWebSocket();
				callbacks.error("Failed to destroy the gateway: Is the gateway down?");
				gatewayCallbacks.destroyed();
			};

			ws.addEventListener('message', onUnbindMessage);
			ws.addEventListener('error', onUnbindError);

			ws.send(JSON.stringify(request));
			return;
		}
		Janus.httpAPICall(server + "/" + sessionId, {
			verb: 'POST',
			async: asyncRequest,	// Sometimes we need false here, or destroying in onbeforeunload won't work
			withCredentials: withCredentials,
			body: request,
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
			error: function(textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
				// Reset everything anyway
				sessionId = null;
				connected = false;
				callbacks.success();
				gatewayCallbacks.destroyed();
			}
		});
	}

	// Private method to create a plugin handle
	function createHandle(callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : Janus.noop;
		callbacks.consentDialog = (typeof callbacks.consentDialog == "function") ? callbacks.consentDialog : Janus.noop;
		callbacks.iceState = (typeof callbacks.iceState == "function") ? callbacks.iceState : Janus.noop;
		callbacks.mediaState = (typeof callbacks.mediaState == "function") ? callbacks.mediaState : Janus.noop;
		callbacks.webrtcState = (typeof callbacks.webrtcState == "function") ? callbacks.webrtcState : Janus.noop;
		callbacks.slowLink = (typeof callbacks.slowLink == "function") ? callbacks.slowLink : Janus.noop;
		callbacks.onmessage = (typeof callbacks.onmessage == "function") ? callbacks.onmessage : Janus.noop;
		callbacks.onlocalstream = (typeof callbacks.onlocalstream == "function") ? callbacks.onlocalstream : Janus.noop;
		callbacks.onremotestream = (typeof callbacks.onremotestream == "function") ? callbacks.onremotestream : Janus.noop;
		callbacks.ondata = (typeof callbacks.ondata == "function") ? callbacks.ondata : Janus.noop;
		callbacks.ondataopen = (typeof callbacks.ondataopen == "function") ? callbacks.ondataopen : Janus.noop;
		callbacks.oncleanup = (typeof callbacks.oncleanup == "function") ? callbacks.oncleanup : Janus.noop;
		callbacks.ondetached = (typeof callbacks.ondetached == "function") ? callbacks.ondetached : Janus.noop;
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
		var opaqueId = callbacks.opaqueId;
		var transaction = Janus.randomString(12);
		var request = { "janus": "attach", "plugin": plugin, "opaque_id": opaqueId, "transaction": transaction };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		// If we know the browser supports BUNDLE and/or rtcp-mux, let's advertise those right away
		if(Janus.webRTCAdapter.browserDetails.browser == "chrome" || Janus.webRTCAdapter.browserDetails.browser == "firefox" ||
				Janus.webRTCAdapter.browserDetails.browser == "safari") {
			request["force-bundle"] = true;
			request["force-rtcp-mux"] = true;
		}
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
						detached : false,
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
						isAudioMuted : function() { return isMuted(handleId, false); },
						muteAudio : function() { return mute(handleId, false, true); },
						unmuteAudio : function() { return mute(handleId, false, false); },
						isVideoMuted : function() { return isMuted(handleId, true); },
						muteVideo : function() { return mute(handleId, true, true); },
						unmuteVideo : function() { return mute(handleId, true, false); },
						getBitrate : function() { return getBitrate(handleId); },
						send : function(callbacks) { sendMessage(handleId, callbacks); },
						data : function(callbacks) { sendData(handleId, callbacks); },
						dtmf : function(callbacks) { sendDtmf(handleId, callbacks); },
						consentDialog : callbacks.consentDialog,
						iceState : callbacks.iceState,
						mediaState : callbacks.mediaState,
						webrtcState : callbacks.webrtcState,
						slowLink : callbacks.slowLink,
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
						hangup : function(sendRequest) { cleanupWebrtc(handleId, sendRequest === true); },
						detach : function(callbacks) { destroyHandle(handleId, callbacks); }
					}
				pluginHandles[handleId] = pluginHandle;
				callbacks.success(pluginHandle);
			};
			request["session_id"] = sessionId;
			ws.send(JSON.stringify(request));
			return;
		}
		Janus.httpAPICall(server + "/" + sessionId, {
			verb: 'POST',
			withCredentials: withCredentials,
			body: request,
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
						detached : false,
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
						isAudioMuted : function() { return isMuted(handleId, false); },
						muteAudio : function() { return mute(handleId, false, true); },
						unmuteAudio : function() { return mute(handleId, false, false); },
						isVideoMuted : function() { return isMuted(handleId, true); },
						muteVideo : function() { return mute(handleId, true, true); },
						unmuteVideo : function() { return mute(handleId, true, false); },
						getBitrate : function() { return getBitrate(handleId); },
						send : function(callbacks) { sendMessage(handleId, callbacks); },
						data : function(callbacks) { sendData(handleId, callbacks); },
						dtmf : function(callbacks) { sendDtmf(handleId, callbacks); },
						consentDialog : callbacks.consentDialog,
						iceState : callbacks.iceState,
						mediaState : callbacks.mediaState,
						webrtcState : callbacks.webrtcState,
						slowLink : callbacks.slowLink,
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
						hangup : function(sendRequest) { cleanupWebrtc(handleId, sendRequest === true); },
						detach : function(callbacks) { destroyHandle(handleId, callbacks); }
					}
				pluginHandles[handleId] = pluginHandle;
				callbacks.success(pluginHandle);
			},
			error: function(textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
			}
		});
	}

	// Private method to send a message
	function sendMessage(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : Janus.noop;
		if(!connected) {
			Janus.warn("Is the gateway down? (connected=false)");
			callbacks.error("Is the gateway down? (connected=false)");
			return;
		}
		var message = callbacks.message;
		var jsep = callbacks.jsep;
		var transaction = Janus.randomString(12);
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
		Janus.httpAPICall(server + "/" + sessionId + "/" + handleId, {
			verb: 'POST',
			withCredentials: withCredentials,
			body: request,
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
			error: function(textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
				callbacks.error(textStatus + ": " + errorThrown);
			}
		});
	}

	// Private method to send a trickle candidate
	function sendTrickleCandidate(handleId, candidate) {
		if(!connected) {
			Janus.warn("Is the gateway down? (connected=false)");
			return;
		}
		var request = { "janus": "trickle", "candidate": candidate, "transaction": Janus.randomString(12) };
		if(token !== null && token !== undefined)
			request["token"] = token;
		if(apisecret !== null && apisecret !== undefined)
			request["apisecret"] = apisecret;
		Janus.vdebug("Sending trickle candidate (handle=" + handleId + "):");
		Janus.vdebug(request);
		if(websockets) {
			request["session_id"] = sessionId;
			request["handle_id"] = handleId;
			ws.send(JSON.stringify(request));
			return;
		}
		Janus.httpAPICall(server + "/" + sessionId + "/" + handleId, {
			verb: 'POST',
			withCredentials: withCredentials,
			body: request,
			success: function(json) {
				Janus.vdebug("Candidate sent!");
				Janus.vdebug(json);
				if(json["janus"] !== "ack") {
					Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
					return;
				}
			},
			error: function(textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
			}
		});
	}

	// Private method to send a data channel message
	function sendData(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : Janus.noop;
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
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : Janus.noop;
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
		Janus.debug("Sending DTMF string " + tones + " (duration " + duration + "ms, gap " + gap + "ms)");
		config.dtmfSender.insertDTMF(tones, duration, gap);
	}

	// Private method to destroy a plugin handle
	function destroyHandle(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : Janus.noop;
		Janus.warn(callbacks);
		var asyncRequest = true;
		if(callbacks.asyncRequest !== undefined && callbacks.asyncRequest !== null)
			asyncRequest = (callbacks.asyncRequest === true);
		Janus.log("Destroying handle " + handleId + " (async=" + asyncRequest + ")");
		cleanupWebrtc(handleId);
		if (pluginHandles[handleId].detached) {
			// Plugin was already detached by Janus, calling detach again will return a handle not found error, so just exit here
			delete pluginHandles[handleId];
			callbacks.success();
			return;
		}
		if(!connected) {
			Janus.warn("Is the gateway down? (connected=false)");
			callbacks.error("Is the gateway down? (connected=false)");
			return;
		}
		var request = { "janus": "detach", "transaction": Janus.randomString(12) };
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
		Janus.httpAPICall(server + "/" + sessionId + "/" + handleId, {
			verb: 'POST',
			async: asyncRequest,	// Sometimes we need false here, or destroying in onbeforeunload won't work
			withCredentials: withCredentials,
			body: request,
			success: function(json) {
				Janus.log("Destroyed handle:");
				Janus.debug(json);
				if(json["janus"] !== "success") {
					Janus.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
				}
				delete pluginHandles[handleId];
				callbacks.success();
			},
			error: function(textStatus, errorThrown) {
				Janus.error(textStatus + ": " + errorThrown);	// FIXME
				// We cleanup anyway
				delete pluginHandles[handleId];
				callbacks.success();
			}
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
		var pc_config = {"iceServers": iceServers, "iceTransportPolicy": iceTransportPolicy, "bundlePolicy": bundlePolicy};
		//~ var pc_constraints = {'mandatory': {'MozDontOfferDataChannel':true}};
		var pc_constraints = {
			"optional": [{"DtlsSrtpKeyAgreement": true}]
		};
		if(ipv6Support === true) {
			// FIXME This is only supported in Chrome right now
			// For support in Firefox track this: https://bugzilla.mozilla.org/show_bug.cgi?id=797262
			pc_constraints.optional.push({"googIPv6":true});
		}
		// Any custom constraint to add?
		if(callbacks.rtcConstraints && typeof callbacks.rtcConstraints === 'object') {
			Janus.debug("Adding custom PeerConnection constraints:", callbacks.rtcConstraints);
			for(var i in callbacks.rtcConstraints) {
				pc_constraints.optional.push(callbacks.rtcConstraints[i]);
			}
		}
		if(Janus.webRTCAdapter.browserDetails.browser === "edge") {
			// This is Edge, enable BUNDLE explicitly
			pc_config.bundlePolicy = "max-bundle";
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
		config.pc.oniceconnectionstatechange = function(e) {
			if(config.pc)
				pluginHandle.iceState(config.pc.iceConnectionState);
		};
		config.pc.onicecandidate = function(event) {
			if (event.candidate == null ||
					(Janus.webRTCAdapter.browserDetails.browser === 'edge' && event.candidate.candidate.indexOf('endOfCandidates') > 0)) {
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
				if(config.trickle === true) {
					// Send candidate
					sendTrickleCandidate(handleId, candidate);
				}
			}
		};
		if(stream !== null && stream !== undefined) {
			Janus.log('Adding local stream');
			stream.getTracks().forEach(function(track) { config.pc.addTrack(track, stream); });
			pluginHandle.onlocalstream(stream);
		}
		config.pc.ontrack = function(event) {
			Janus.log("Handling Remote Track");
			Janus.debug(event);
			if(!event.streams)
				return;
			config.remoteStream = event.streams[0];
			pluginHandle.onremotestream(config.remoteStream);
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
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
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
		config.trickle = isTrickleEnabled(callbacks.trickle);
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
		if(isAudioSendEnabled(media) || isVideoSendEnabled(media)) {
			var constraints = { mandatory: {}, optional: []};
			pluginHandle.consentDialog(true);
			var audioSupport = isAudioSendEnabled(media);
			if(audioSupport === true && media != undefined && media != null) {
				if(typeof media.audio === 'object') {
					audioSupport = media.audio;
				}
			}
			var videoSupport = isVideoSendEnabled(media);
			if(videoSupport === true && media != undefined && media != null) {
				var simulcast = callbacks.simulcast === true ? true : false;
				if(simulcast && !jsep && (media.video === undefined || media.video === false))
					media.video = "hires";
				if(media.video && media.video != 'screen' && media.video != 'window') {
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
						Janus.log("Default video setting is stdres 4:3");
						height = 480;
						maxHeight = 480;
						width = 640;
					}
					Janus.log("Adding media constraint:", media.video);
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
					if(typeof media.video === 'object') {
						videoSupport = media.video;
					}
					Janus.debug(videoSupport);
				} else if(media.video === 'screen' || media.video === 'window') {
					if(!media.screenshareFrameRate) {
						media.screenshareFrameRate = 3;
					}
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
							callbacks.error({code: error.code, name: error.name, message: error.message});
						} else {
							streamsDone(handleId, jsep, media, callbacks, stream);
						}
					};
					function getScreenMedia(constraints, gsmCallback, useAudio) {
						Janus.log("Adding media constraint (screen capture)");
						Janus.debug(constraints);
						navigator.mediaDevices.getUserMedia(constraints)
							.then(function(stream) { 
								if(useAudio){
									navigator.mediaDevices.getUserMedia({ audio: true, video: false })
									.then(function (audioStream) {
										stream.addTrack(audioStream.getAudioTracks()[0]);
										gsmCallback(null, stream);
									})
								} else {
									gsmCallback(null, stream);
								} 
							})
							.catch(function(error) { pluginHandle.consentDialog(false); gsmCallback(error); });
					};
					if(Janus.webRTCAdapter.browserDetails.browser === 'chrome') {
						var chromever = Janus.webRTCAdapter.browserDetails.version;
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
										minFrameRate: media.screenshareFrameRate,
										maxFrameRate: media.screenshareFrameRate,
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
									mozMediaSource: media.video,
									mediaSource: media.video
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
									audio: false,
									video: {
										mandatory: {
											chromeMediaSource: 'desktop',
											maxWidth: window.screen.width,
											maxHeight: window.screen.height,
											minFrameRate: media.screenshareFrameRate,
											maxFrameRate: media.screenshareFrameRate,
										},
										optional: [
											{googLeakyBucket: true},
											{googTemporalLayeredScreencast: true}
										]
									}
								};
								constraints.video.mandatory.chromeMediaSourceId = event.data.sourceId;
								getScreenMedia(constraints, callback, isAudioSendEnabled(media));
							}
						} else if (event.data.type == 'janusGetScreenPending') {
							window.clearTimeout(event.data.id);
						}
					});
					return;
				}
			}
			// If we got here, we're not screensharing
			if(media === null || media === undefined || media.video !== 'screen') {
				// Check whether all media sources are actually available or not
				navigator.mediaDevices.enumerateDevices().then(function(devices) {
					var audioExist = devices.some(function(device) {
						return device.kind === 'audioinput';
					}),
					videoExist = devices.some(function(device) {
						return device.kind === 'videoinput';
					});

					// Check whether a missing device is really a problem
					var audioSend = isAudioSendEnabled(media);
					var videoSend = isVideoSendEnabled(media);
					var needAudioDevice = isAudioSendRequired(media);
					var needVideoDevice = isVideoSendRequired(media);
					if(audioSend || videoSend || needAudioDevice || needVideoDevice) {
						// We need to send either audio or video
						var haveAudioDevice = audioSend ? audioExist : false;
						var haveVideoDevice = videoSend ? videoExist : false;
						if(!haveAudioDevice && !haveVideoDevice) {
							// FIXME Should we really give up, or just assume recvonly for both?
							pluginHandle.consentDialog(false);
							callbacks.error('No capture device found');
							return false;
						} else if(!haveAudioDevice && needAudioDevice) {
							pluginHandle.consentDialog(false);
							callbacks.error('Audio capture is required, but no capture device found');
							return false;
						} else if(!haveVideoDevice && needVideoDevice) {
							pluginHandle.consentDialog(false);
							callbacks.error('Video capture is required, but no capture device found');
							return false;
						}
					}

					navigator.mediaDevices.getUserMedia({
						audio: audioExist ? audioSupport : false,
						video: videoExist ? videoSupport : false
					})
					.then(function(stream) { pluginHandle.consentDialog(false); streamsDone(handleId, jsep, media, callbacks, stream); })
					.catch(function(error) { pluginHandle.consentDialog(false); callbacks.error({code: error.code, name: error.name, message: error.message}); });
				})
				.catch(function(error) {
					pluginHandle.consentDialog(false);
					callbacks.error('enumerateDevices error', error);
				});
			}
		} else {
			// No need to do a getUserMedia, create offer/answer right away
			streamsDone(handleId, jsep, media, callbacks);
		}
	}

	function prepareWebrtcPeer(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
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
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : Janus.noop;
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = pluginHandle.webrtcStuff;
		var simulcast = callbacks.simulcast === true ? true : false;
		if(!simulcast) {
			Janus.log("Creating offer (iceDone=" + config.iceDone + ")");
		} else {
			Janus.log("Creating offer (iceDone=" + config.iceDone + ", simulcast=" + simulcast + ")");
		}
		// https://code.google.com/p/webrtc/issues/detail?id=3508
		var mediaConstraints = null;
		if(Janus.webRTCAdapter.browserDetails.browser == "firefox" || Janus.webRTCAdapter.browserDetails.browser == "edge") {
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
		// Check if this is Firefox and we've been asked to do simulcasting
		var sendVideo = isVideoSendEnabled(media);
		if(sendVideo && simulcast && Janus.webRTCAdapter.browserDetails.browser === "firefox") {
			// FIXME Based on https://gist.github.com/voluntas/088bc3cc62094730647b
			Janus.log("Enabling Simulcasting for Firefox (RID)");
			var sender = config.pc.getSenders()[1];
			Janus.log(sender);
			var parameters = sender.getParameters();
			Janus.log(parameters);
			sender.setParameters({encodings: [
				{ rid: "high", active: true, priority: "high", maxBitrate: 1000000 },
				{ rid: "medium", active: true, priority: "medium", maxBitrate: 300000 },
				{ rid: "low", active: true, priority: "low", maxBitrate: 100000 }
			]});
		}
		config.pc.createOffer(
			function(offer) {
				Janus.debug(offer);
				if(config.mySdp === null || config.mySdp === undefined) {
					Janus.log("Setting local description");
					if(sendVideo && simulcast) {
						// This SDP munging only works with Chrome
						if(Janus.webRTCAdapter.browserDetails.browser === "chrome") {
							Janus.log("Enabling Simulcasting for Chrome (SDP munging)");
							offer.sdp = mungeSdpForSimulcasting(offer.sdp);
						} else if(Janus.webRTCAdapter.browserDetails.browser !== "firefox") {
							Janus.warn("simulcast=true, but this is not Chrome nor Firefox, ignoring");
						}
					}
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
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : Janus.noop;
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = pluginHandle.webrtcStuff;
		var simulcast = callbacks.simulcast === true ? true : false;
		if(!simulcast) {
			Janus.log("Creating answer (iceDone=" + config.iceDone + ")");
		} else {
			Janus.log("Creating answer (iceDone=" + config.iceDone + ", simulcast=" + simulcast + ")");
		}
		var mediaConstraints = null;
		if(Janus.webRTCAdapter.browserDetails.browser == "firefox" || Janus.webRTCAdapter.browserDetails.browser == "edge") {
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
		// Check if this is Firefox and we've been asked to do simulcasting
		var sendVideo = isVideoSendEnabled(media);
		if(sendVideo && simulcast && Janus.webRTCAdapter.browserDetails.browser === "firefox") {
			// FIXME Based on https://gist.github.com/voluntas/088bc3cc62094730647b
			Janus.log("Enabling Simulcasting for Firefox (RID)");
			var sender = config.pc.getSenders()[1];
			Janus.log(sender);
			var parameters = sender.getParameters();
			Janus.log(parameters);
			sender.setParameters({encodings: [
				{ rid: "high", active: true, priority: "high", maxBitrate: 1000000 },
				{ rid: "medium", active: true, priority: "medium", maxBitrate: 300000 },
				{ rid: "low", active: true, priority: "low", maxBitrate: 100000 }
			]});
		}
		config.pc.createAnswer(
			function(answer) {
				Janus.debug(answer);
				if(config.mySdp === null || config.mySdp === undefined) {
					Janus.log("Setting local description");
					if(sendVideo && simulcast) {
						// This SDP munging only works with Chrome
						if(Janus.webRTCAdapter.browserDetails.browser === "chrome") {
							// FIXME Apparently trying to simulcast when answering breaks video in Chrome...
							//~ Janus.log("Enabling Simulcasting for Chrome (SDP munging)");
							//~ answer.sdp = mungeSdpForSimulcasting(answer.sdp);
							Janus.warn("simulcast=true, but this is an answer, and video breaks in Chrome if we enable it");
						} else if(Janus.webRTCAdapter.browserDetails.browser !== "firefox") {
							Janus.warn("simulcast=true, but this is not Chrome nor Firefox, ignoring");
						}
					}
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
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : Janus.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : Janus.noop;
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
		config.mySdp = {
			"type": config.pc.localDescription.type,
			"sdp": config.pc.localDescription.sdp
		};
		if(config.sdpSent) {
			Janus.log("Offer/Answer SDP already sent, not sending it again");
			return;
		}
		if(config.trickle === false)
			config.mySdp["trickle"] = false;
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
		if(config.pc.getStats && Janus.webRTCAdapter.browserDetails.browser == "chrome") {	// FIXME
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

	function isMuted(handleId, video) {
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			return true;
		}
		var config = pluginHandle.webrtcStuff;
		if(config.pc === null || config.pc === undefined) {
			Janus.warn("Invalid PeerConnection");
			return true;
		}
		if(config.myStream === undefined || config.myStream === null) {
			Janus.warn("Invalid local MediaStream");
			return true;
		}
		if(video) {
			// Check video track
			if(config.myStream.getVideoTracks() === null
					|| config.myStream.getVideoTracks() === undefined
					|| config.myStream.getVideoTracks().length === 0) {
				Janus.warn("No video track");
				return true;
			}
			return !config.myStream.getVideoTracks()[0].enabled;
		} else {
			// Check audio track
			if(config.myStream.getAudioTracks() === null
					|| config.myStream.getAudioTracks() === undefined
					|| config.myStream.getAudioTracks().length === 0) {
				Janus.warn("No audio track");
				return true;
			}
			return !config.myStream.getAudioTracks()[0].enabled;
		}
	}

	function mute(handleId, video, mute) {
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			Janus.warn("Invalid handle");
			return false;
		}
		var config = pluginHandle.webrtcStuff;
		if(config.pc === null || config.pc === undefined) {
			Janus.warn("Invalid PeerConnection");
			return false;
		}
		if(config.myStream === undefined || config.myStream === null) {
			Janus.warn("Invalid local MediaStream");
			return false;
		}
		if(video) {
			// Mute/unmute video track
			if(config.myStream.getVideoTracks() === null
					|| config.myStream.getVideoTracks() === undefined
					|| config.myStream.getVideoTracks().length === 0) {
				Janus.warn("No video track");
				return false;
			}
			config.myStream.getVideoTracks()[0].enabled = mute ? false : true;
			return true;
		} else {
			// Mute/unmute audio track
			if(config.myStream.getAudioTracks() === null
					|| config.myStream.getAudioTracks() === undefined
					|| config.myStream.getAudioTracks().length === 0) {
				Janus.warn("No audio track");
				return false;
			}
			config.myStream.getAudioTracks()[0].enabled = mute ? false : true;
			return true;
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
		if(config.pc.getStats) {
			if(config.bitrate.timer === null || config.bitrate.timer === undefined) {
				Janus.log("Starting bitrate timer (via getStats)");
				config.bitrate.timer = setInterval(function() {
					config.pc.getStats()
						.then(function(stats) {
							stats.forEach(function (res) {
								if(!res)
									return;
								var inStats = false;
								// Check if these are statistics on incoming media
								if((res.mediaType === "video" || res.id.toLowerCase().indexOf("video") > -1) &&
										res.type === "inbound-rtp" && res.id.indexOf("rtcp") < 0) {
									// New stats
									inStats = true;
								} else if(res.type == 'ssrc' && res.bytesReceived &&
										(res.googCodecName === "VP8" || res.googCodecName === "")) {
									// Older Chromer versions
									inStats = true;
								}
								// Parse stats now
								if(inStats) {
									config.bitrate.bsnow = res.bytesReceived;
									config.bitrate.tsnow = res.timestamp;
									if(config.bitrate.bsbefore === null || config.bitrate.tsbefore === null) {
										// Skip this round
										config.bitrate.bsbefore = config.bitrate.bsnow;
										config.bitrate.tsbefore = config.bitrate.tsnow;
									} else {
										// Calculate bitrate
										var timePassed = config.bitrate.tsnow - config.bitrate.tsbefore;
										if(Janus.webRTCAdapter.browserDetails.browser == "safari")
											timePassed = timePassed/1000;	// Apparently the timestamp is in microseconds, in Safari
										var bitRate = Math.round((config.bitrate.bsnow - config.bitrate.bsbefore) * 8 / timePassed);
										config.bitrate.value = bitRate + ' kbits/sec';
										//~ Janus.log("Estimated bitrate is " + config.bitrate.value);
										config.bitrate.bsbefore = config.bitrate.bsnow;
										config.bitrate.tsbefore = config.bitrate.tsnow;
									}
								}
							});
						});
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

	function cleanupWebrtc(handleId, hangupRequest) {
		Janus.log("Cleaning WebRTC stuff");
		var pluginHandle = pluginHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined) {
			// Nothing to clean
			return;
		}
		var config = pluginHandle.webrtcStuff;
		if(config !== null && config !== undefined) {
			if(hangupRequest === true) {
				// Send a hangup request (we don't really care about the response)
				var request = { "janus": "hangup", "transaction": Janus.randomString(12) };
				if(token !== null && token !== undefined)
					request["token"] = token;
				if(apisecret !== null && apisecret !== undefined)
					request["apisecret"] = apisecret;
				Janus.debug("Sending hangup request (handle=" + handleId + "):");
				Janus.debug(request);
				if(websockets) {
					request["session_id"] = sessionId;
					request["handle_id"] = handleId;
					ws.send(JSON.stringify(request));
				} else {
					Janus.httpAPICall(server + "/" + sessionId + "/" + handleId, {
						verb: 'POST',
						withCredentials: withCredentials,
						data: request
					});
				}
			}
			// Cleanup stack
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
				// Try a MediaStreamTrack.stop() for each track
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

	// Helper method to munge an SDP to enable simulcasting (Chrome only)
	function mungeSdpForSimulcasting(sdp) {
		// Let's munge the SDP to add the attributes for enabling simulcasting
		// (based on https://gist.github.com/ggarber/a19b4c33510028b9c657)
		var lines = sdp.split("\r\n");
		var video = false;
		var ssrc = [ -1 ], ssrc_fid = -1;
		var cname = null, msid = null, mslabel = null, label = null;
		var insertAt = -1;
		for(var i=0; i<lines.length; i++) {
			var mline = lines[i].match(/m=(\w+) */);
			if(mline) {
				var medium = mline[1];
				if(medium === "video") {
					// New video m-line: make sure it's the first one
					if(ssrc[0] < 0) {
						video = true;
					} else {
						// We're done, let's add the new attributes here
						insertAt = i;
						break;
					}
				} else {
					// New non-video m-line: do we have what we were looking for?
					if(ssrc[0] > -1) {
						// We're done, let's add the new attributes here
						insertAt = i;
						break;
					}
				}
				continue;
			}
			if(!video)
				continue;
			var fid = lines[i].match(/a=ssrc-group:FID (\d+) (\d+)/);
			if(fid) {
				ssrc[0] = fid[1];
				ssrc_fid = fid[2];
				lines.splice(i, 1); i--;
				continue;
			}
			if(ssrc[0]) {
				var match = lines[i].match('a=ssrc:' + ssrc[0] + ' cname:(.+)')
				if(match) {
					cname = match[1];
				}
				match = lines[i].match('a=ssrc:' + ssrc[0] + ' msid:(.+)')
				if(match) {
					msid = match[1];
				}
				match = lines[i].match('a=ssrc:' + ssrc[0] + ' mslabel:(.+)')
				if(match) {
					mslabel = match[1];
				}
				match = lines[i].match('a=ssrc:' + ssrc + ' label:(.+)')
				if(match) {
					label = match[1];
				}
				if(lines[i].indexOf('a=ssrc:' + ssrc_fid) === 0) {
					lines.splice(i, 1); i--;
					continue;
				}
				if(lines[i].indexOf('a=ssrc:' + ssrc[0]) === 0) {
					lines.splice(i, 1); i--;
					continue;
				}
			}
			if(lines[i].length == 0) {
				lines.splice(i, 1); i--;
				continue;
			}
		}
		if(ssrc[0] < 0) {
			// Couldn't find a FID attribute, let's just take the first video SSRC we find
			insertAt = -1;
			video = false;
			for(var i=0; i<lines.length; i++) {
				var mline = lines[i].match(/m=(\w+) */);
				if(mline) {
					var medium = mline[1];
					if(medium === "video") {
						// New video m-line: make sure it's the first one
						if(ssrc[0] < 0) {
							video = true;
						} else {
							// We're done, let's add the new attributes here
							insertAt = i;
							break;
						}
					} else {
						// New non-video m-line: do we have what we were looking for?
						if(ssrc[0] > -1) {
							// We're done, let's add the new attributes here
							insertAt = i;
							break;
						}
					}
					continue;
				}
				if(!video)
					continue;
				if(ssrc[0] < 0) {
					var value = lines[i].match(/a=ssrc:(\d+)/);
					if(value) {
						ssrc[0] = value[1];
						lines.splice(i, 1); i--;
						continue;
					}
				} else {
					var match = lines[i].match('a=ssrc:' + ssrc[0] + ' cname:(.+)')
					if(match) {
						cname = match[1];
					}
					match = lines[i].match('a=ssrc:' + ssrc[0] + ' msid:(.+)')
					if(match) {
						msid = match[1];
					}
					match = lines[i].match('a=ssrc:' + ssrc[0] + ' mslabel:(.+)')
					if(match) {
						mslabel = match[1];
					}
					match = lines[i].match('a=ssrc:' + ssrc + ' label:(.+)')
					if(match) {
						label = match[1];
					}
					if(lines[i].indexOf('a=ssrc:' + ssrc_fid) === 0) {
						lines.splice(i, 1); i--;
						continue;
					}
					if(lines[i].indexOf('a=ssrc:' + ssrc[0]) === 0) {
						lines.splice(i, 1); i--;
						continue;
					}
				}
				if(lines[i].length == 0) {
					lines.splice(i, 1); i--;
					continue;
				}
			}
		}
		if(ssrc[0] < 0) {
			// Still nothing, let's just return the SDP we were asked to munge
			Janus.warn("Couldn't find the video SSRC, simulcasting NOT enabled");
			return sdp;
		}
		if(insertAt < 0) {
			// Append at the end
			insertAt = lines.length;
		}
		// Generate a couple of SSRCs
		ssrc[1] = Math.floor(Math.random()*0xFFFFFFFF);
		ssrc[2] = Math.floor(Math.random()*0xFFFFFFFF);
		// Add attributes to the SDP
		for(var i=0; i<ssrc.length; i++) {
			if(cname) {
				lines.splice(insertAt, 0, 'a=ssrc:' + ssrc[i] + ' cname:' + cname);
				insertAt++;
			}
			if(msid) {
				lines.splice(insertAt, 0, 'a=ssrc:' + ssrc[i] + ' msid:' + msid);
				insertAt++;
			}
			if(mslabel) {
				lines.splice(insertAt, 0, 'a=ssrc:' + ssrc[i] + ' mslabel:' + msid);
				insertAt++;
			}
			if(label) {
				lines.splice(insertAt, 0, 'a=ssrc:' + ssrc[i] + ' label:' + msid);
				insertAt++;
			}
		}
		lines.splice(insertAt, 0, 'a=ssrc-group:SIM ' + ssrc[0] + ' ' + ssrc[1] + ' ' + ssrc[2]);
		sdp = lines.join("\r\n");
		if(!sdp.endsWith("\r\n"))
			sdp += "\r\n";
		return sdp;
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

	function isAudioSendRequired(media) {
		Janus.debug("isAudioSendRequired:", media);
		if(media === undefined || media === null)
			return false;	// Default
		if(media.audio === false || media.audioSend === false)
			return false;	// If we're not asking to capture audio, it's not required
		if(media.failIfNoAudio === undefined || media.failIfNoAudio === null)
			return false;	// Default
		return (media.failIfNoAudio === true);
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
		if(media === undefined || media === null)
			return true;	// Default
		if(media.video === false)
			return false;	// Generic video has precedence
		if(media.videoSend === undefined || media.videoSend === null)
			return true;	// Default
		return (media.videoSend === true);
	}

	function isVideoSendRequired(media) {
		Janus.debug("isVideoSendRequired:", media);
		if(media === undefined || media === null)
			return false;	// Default
		if(media.video === false || media.videoSend === false)
			return false;	// If we're not asking to capture video, it's not required
		if(media.failIfNoVideo === undefined || media.failIfNoVideo === null)
			return false;	// Default
		return (media.failIfNoVideo === true);
	}

	function isVideoRecvEnabled(media) {
		Janus.debug("isVideoRecvEnabled:", media);
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
		if(Janus.webRTCAdapter.browserDetails.browser == "edge") {
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
