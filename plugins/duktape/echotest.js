// This is a simple example of an echo test application built in JavaScript,
// and conceived to be used in conjunction with the janus_duktape.c plugin.
// Obviously, it must NOT be confused with the echotest.js in the html
// folder, which contains the JavaScript code for the web demo instead...

// Example details
name = "echotest.js";

// Let's add more info to errors
Error.prototype.toString = function () {
	return this.name + ': ' + this.message + ' (at line ' + this.lineNumber + ')';
};
// Let's add a prefix to all console.log lines
var originalConsoleLog = console.log;
console.log = function() {
	args = [];
	args.push('[\x1b[36m' + name + '\x1b[0m] ');
	for(var i=0; i<arguments.length; i++) {
		args.push(arguments[i]);
	}
	originalConsoleLog.apply(console, args);
};
console.log("Loading script...");

// We'll import our own hacky SDP parser, so we'll need the folder from the core
var folder = getModulesFolder();
console.log('Modules folder:', folder);

// To require external modules with Duktape, we need a modSearch function:
// https://github.com/svaarala/duktape-wiki/blob/master/HowtoModules.md
Duktape.modSearch = function(id) {
	console.log('Loading module:', id);
	// We read the file from the folder the core returned
	var res = readFile(folder + '/' + id + '.js');
	if(typeof res === 'string') {
		console.log('Module loaded');
		return res;
	}
	throw new Error('Module not found: ' + id);
}

// Let's import our ugly SDP parser now
var sdpUtils = require("janus-sdp");

// State and properties
var sessions = {};
var tasks = [];

// Just for fun, let's override the plugin info with our own
function getVersion() {
	return 12;
}
function getVersionString() {
	return "0.0.12";
}
function getDescription() {
	return "This is echotest.js, a JavaScript/Duktape based clone of janus.plugin.echotest";
}
function getName() {
	return "JavaScript based EchoTest";
}
function getAuthor() {
	return "Lorenzo Miniero";
}
function getPackage() {
	return "janus.plugin.echojs";
}

// Methods
function init(config) {
	// This is where we initialize the plugin, for static properties
	console.log("Initializing...")
	if(config) {
		console.log("Configuration file provided (" + config + "), but we don't need it");
	}
	console.log("Initialized");
	// Just for fun (and to showcase the feature), let's send an event to handlers:
	// notice how the first argument is 0, meaning this event is not tied to any session
	var event = { event: "loaded", script: name };
	notifyEvent(0, JSON.stringify(event));
}

function destroy() {
	// This is where we deinitialize the plugin, when Janus shuts down
	console.log("Deinitialized");
}

function createSession(id) {
	// Keep track of a new session
	console.log("Created new session:", id);
	sessions[id] = { id: id, lua: name };
	// By default, we accept and relay all streams
	configureMedium(id, "audio", "in", true);
	configureMedium(id, "audio", "out", true);
	configureMedium(id, "video", "in", true);
	configureMedium(id, "video", "out", true);
	configureMedium(id, "data", "in", true);
	configureMedium(id, "data", "out", true);
}

function destroySession(id) {
	// A Janus plugin session has gone
	console.log("Destroyed session:", id)
	hangupMedia(id);
	delete sessions[id];
}

function querySession(id) {
	// Return info on a session
	console.log("Queried session:", id)
	var s = sessions[id];
	if(!s)
		return null;
	var info = { script: s["lua"], id: s["id"] };
	return JSON.stringify(info);
}

function handleMessage(id, tr, msg, jsep) {
	// Handle a message, synchronously or asynchronously, and return
	// something accordingly: if it's the latter, we'll do a coroutine
	console.log("Handling message for session:", id)
	var s = sessions[id];
	if(!s) {
		// Session not found: return value is a negative integer
		return -1;
	}
	// Decode the message JSON string
	var msgT = JSON.parse(msg);
	// Let's return a synchronous response if there's no jsep, asynchronous otherwise
	if(!jsep) {
		var res = processRequest(id, msgT);
		var response = { echotest: "response", result: "ok" };
		if(res < 0)
			response["result"] = "error";
		// Synchronous response: return value is a JSON string
		return JSON.stringify(response);
	} else {
		// Decode the JSEP JSON string too
		var jsepT = JSON.parse(jsep);
		// We'll need a coroutine here: the scheduler will resume it later
		tasks.push({ id: id, tr: tr, msg: msgT, jsep: jsepT });
		// Return explaining that this is will be handled asynchronously
		pokeScheduler();
		// Asynchronous response: return value is a positive integer
		return 1;
	}
}

function handleAdminMessage(message) {
	// This is just to showcase how you can handle incoming messages
	// coming from the Admin API: we return the same message as a test
	console.log("Got admin message:", message);
	return message;
}

function setupMedia(id) {
	// WebRTC is now available
	console.log("WebRTC PeerConnection is up for session:", id);
	// Attach the session's stream to itself (echo test)
	addRecipient(id, id);
}

function hangupMedia(id) {
	// WebRTC not available anymore
	console.log("WebRTC PeerConnection is down for session:", id);
	// Detach the stream
	removeRecipient(id, id);
	// Clear some flags
	var s = sessions[id];
	if(s) {
		s.audioCodec = null;
		s.videoCodec = null;
	}
}

function incomingTextData(id, buf, len) {
	// Relaying RTP/RTCP in JavaScript makes no sense, but just for fun
	// we handle data channel messages ourselves to manipulate them
	var edit = "[" + name + "] --> " + buf;
	relayTextData(id, edit, edit.length);
}

function incomingBinaryData(id, buf, len) {
	// If the data we're getting is binary, send it back as it is
	relayBinaryData(id, buf, len);
}

function dataReady(id) {
	// This callback is invoked when the datachannel first becomes
	// available (meaning you should never send data before it has been
	// invoked at least once), but also when the datachannel is ready to
	// receive more data (buffers are empty), which means it can be used
	// to throttle outgoing data and not send too much at a time.
}

function resumeScheduler() {
	// This is the function responsible for resuming coroutines associated
	// with whatever is relevant to the JS script, e.g., for this script,
	// with asynchronous requests: if you're handling async stuff yourself,
	// you're free not to use this and just return, but the C Duktape plugin
	// expects this method to exist so it MUST be present, even if empty
	console.log("Resuming coroutines");
	for(var index in tasks) {
		var task = tasks[index];
		processAsync(task);
	}
	console.log("Coroutines resumed");
	tasks = [];
}

// We use this internal method to process an API request
function processRequest(id, msg) {
	if(!msg) {
		console.log("Invalid request");
		return -1;
	}
	// We implement most of the existing EchoTest API messages, here
	if(msg["audio"] === true) {
		configureMedium(id, "audio", "in", true);
		configureMedium(id, "audio", "out", true);
	} else if(msg["audio"] === false) {
		configureMedium(id, "audio", "in", false);
		configureMedium(id, "audio", "out", false);
	}
	if(msg["video"] === true) {
		configureMedium(id, "video", "in", true);
		configureMedium(id, "video", "out", true);
		sendPli(id);
	} else if(msg["video"] === false) {
		configureMedium(id, "video", "in", false);
		configureMedium(id, "video", "out", false);
	}
	if(msg["data"] === true) {
		configureMedium(id, "data", "in", true);
		configureMedium(id, "data", "out", true);
	} else if(msg["data"] === false) {
		configureMedium(id, "data", "in", false);
		configureMedium(id, "data", "out", false);
	}
	if(msg["bitrate"] !== null && msg["bitrate"] !== undefined) {
		setBitrate(id, msg["bitrate"]);
	}
	if(msg["record"] === true) {
		var fnbase = msg["filename"];
		if(!fnbase) {
			fnbase = "duktape-echotest-" + id + "-" + new Date().getTime();
		}
		// For the sake of simplicity, we're assuming Opus/VP8 here; in
		// practice, you'll need to check what was negotiated. If you
		// want the codec-specific info to be saved to the .mjr file as
		// well, you'll need to add the '/fmtp=<info>' to the codec name,
		// e.g.:    "vp9/fmtp=profile-id=2"
		startRecording(id,
			"audio", "opus", "/tmp", fnbase + "-audio",
			"video", "vp8", "/tmp", fnbase + "-video",
			"data", "text", "/tmp", fnbase + "-data"
		);
	} else if(msg["record"] === false) {
		stopRecording(id, "audio", "video", "data");
	}
	return 0;
}

// We use this other function to process asynchronous requests
function processAsync(task) {
	// We'll only execute this when the scheduler resumes a task
	var id = task.id;
	var tr = task.tr;
	var msg = task.msg;
	var jsep = task.jsep;
	console.log("Handling async message for session:", id);
	var s = sessions[id];
	if(!s) {
		console.log("Can't handle async message: no such session");
		return;
	}
	var offer = sdpUtils.parse(jsep.sdp)
	console.log("Got offer:", offer);
	var answer = sdpUtils.generateAnswer(offer, { audio: true, video: true, data: true,
		audioCodec: msg["audiocodec"], videoCodec: msg["videocodec"],
		vp9Profile: msg["videoprofile"], h264Profile: msg["videoprofile"] });
	console.log("Generated answer:", answer);
	console.log("Processing request:", msg);
	processRequest(id, msg);
	console.log("Pushing event:");
	var event = { echotest: "event", result: "ok" };
	console.log("  --", event);
	var jsepanswer = { type: "answer", sdp: sdpUtils.render(answer) };
	console.log("  --", jsepanswer);
	pushEvent(id, tr, JSON.stringify(event), JSON.stringify(jsepanswer));
	// Just for fun (and to showcase the feature), let's send an event to handlers;
	// notice how we pass the id now, meaning this event is tied to a specific session
	event = { event: "processed", request: msg };
	notifyEvent(id, JSON.stringify(event));
}

// Done
console.log("Script loaded");
