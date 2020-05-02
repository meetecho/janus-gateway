// This is a simple example of an videoroom test application built in JavaScript,
// and conceived to be used in conjunction with the janus_duktape.c plugin.
// Obviously, it must NOT be confused with the videoroomjs.js in the html
// folder, which contains the JavaScript code for the web demo instead...

// Example details
var name = "duktape-videoroomjs";
var janusServer = "webconf.yourcompany.net";

// Let's add more info to errors
Error.prototype.toString = function () {
	return this.name + ': ' + this.message + ' (at line ' + this.lineNumber + ')';
};
// Let's add a prefix to all console.log lines
var originalConsoleLog = console.log;
console.log = function() {
	args = [];
	args.push('[\x1b[36m' + name + '\x1b[0m] JSlog');
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
};

// Let's import our ugly SDP parser now
var sdpUtils = require("janus-sdp");

// State and properties
var sessions = {};
var tasks = [];
var publishers = [];
var rooms ={};

// Just for fun, let's override the plugin info with our own
function getVersion() {
	return 12;
}
function getVersionString() {
	return "0.0.12";
}
function getDescription() {
	return "This is videoroom.js, a JavaScript/Duktape based clone of janus.plugin.videoroomjs";
}
function getName() {
	return "JavaScript based videoroom";
}
function getAuthor() {
	return "Shlomi Gutman";
}
function getPackage() {
	return "janus.plugin.videoroomjs";
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
	var session =  getSession(id);
	// By default, we accept and relay all streams
	configureMedium(id, "audio", "in", true);
	configureMedium(id, "audio", "out", true);
	configureMedium(id, "video", "in", true);
	configureMedium(id, "video", "out", true);
	configureMedium(id, "data", "in", true);
	configureMedium(id, "data", "out", true);
	console.log("sessions",sessions)
}

function destroySession(id) {
	// A Janus plugin session has gone
	var session = getSession(id);
	console.log("Destroyed session:", id);

	var room = getRoom(session.room);
	room.publishers = room.publishers.filter(function(publisher) {return publisher !== id});
	if(room.publishers.length===0){
		delete rooms[session.room]
	}else {
		setRoom(room);
	}
	hangupMedia(id);
	delete sessions[id];
	return 0;
}

function querySession(id) {
	// Return info on a session
	console.log("Queried session:", id);
	var s = getSession(id);
	return JSON.stringify(s);
}

function handleMessage(id, tr, msg, jsep) {
	// Handle a message, synchronously or asynchronously, and return
	// something accordingly: if it's the latter, we'll do a coroutine
	console.log("Handling incoming message for session:", id,msg);
//	console.log( tr, msg, jsep)
	var s = sessions[id];
	// need to change for external source when adding one
	if(!s) {
		// Session not found: return value is a negative integer

		return -1;
	}
	// Decode the message JSON string
	var msgT = JSON.parse(msg);
	// Let's return a synchronous response if there's no jsep, asynchronous otherwise
	if(!jsep) {
		var response = {
			videoroom: "response",
			result: "ok"
		};
		if(msgT.request==="join"){
			if (msgT.ptype === "publisher"){
				//must have room if we whant to start publish somewhere ...
				if(!msgT.room)msgT.room=1234;
				var room = getRoom(msgT.room)
				var session = getSession(id)
				session.display=msgT.display;
				session.room = msgT.room;
				var responseJoined = {
					videoroom: "joined",
					room: room.roomId,
					description: room.roomName,
					id:id
				};
				tasks.push({ id: id, tr: tr, msg: responseJoined, jsep: null });
				room.publishers.forEach(function (publisher) {
						var publishersArray = [session];
						event = { videoroom:"event", event: "newPublisher", publishers:publishersArray, newPublisher:id };
						console.log("sending",publisher,event);
						//pushEvent(publisher, null, JSON.stringify(event));
						tasks.push({ id: publisher, tr: null , msg: event, jsep: null });
				});
				room.publishers.push(id);
				setRoom(room);
				setSession(session)
				pokeScheduler();
				console.log("rooms !!!!!!!!!!!",rooms);
				console.log("sessions !!!!!!!!!!!",sessions);
				//	pushEvent(id, tr, JSON.stringify(response), null);
				return 1;
			}
			else if (msgT.ptype === "subscriber"){
				console.log("subscriber addRecipient", msgT.feed,id);
				console.log("Join request ......",msgT);
				var session = getSession(id);
				var sessionFeed = getSession(msgT.feed);
				sessionFeed.subscribers.push(id);
				session.publishers.push(msgT.feed);
				setSession(session);
				setSession(sessionFeed);
				addRecipient(msgT.feed,id);
				sendPli(msgT.feed);
				var sdpOffer =  sdpUtils.generateOffer({ audio: true, video: true});
				var responseJoined = {
					videoroom: "attached",
					room: 1234,
					description: "Demo Room",
					id:msgT.feed
				};
				tasks.push({ id: id, tr: tr, msg: responseJoined, jsepOffer: sdpOffer });
				pokeScheduler();
				return 1;
			}
		}
		return JSON.stringify(response);
	}
	else{
		if(msgT.request==="start"){
			var responseStart ={
				videoroom: "response",
				result: "ok"
			};
			console.log("Replay to start no sdp !!!",responseStart);
			return JSON.stringify(responseStart);
		}else if(msgT.request==="configure"){
			var res = processRequest(id, msgT);
		}
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
	//addRecipient(id, id);
	//console.log("sessions",sessions);
	var session = getSession(id);
	var publishersArray = getRoomPublishers(session.room);
	var event = { event: "media", publishers:publishersArray, newPublisher:id };
	session.isConnected=true;
	setSession(session);
	notifyEvent(id, JSON.stringify(event));
}

function hangupMedia(id) {
	// WebRTC not available anymore
	console.log("WebRTC PeerConnection is down for session:", id);

	unpublishedEvent = {videoroom: "event", room: 1234, unpublished: id ,janusServer:janusServer};
	notifyEvent(id, JSON.stringify(unpublishedEvent));
	var session = getSession(id);
	// Detach the stream from all subscribers
	session.subscribers.forEach(function (subcriber) {
	console.log("Removing subscriber " , subcriber," from ",id);
		var sessionSubcriber = getSession(subcriber);
		sessionSubcriber.publishers=sessionSubcriber.publishers.filter(function(publisher) {return publisher !== id});
		removeRecipient(id, subcriber);
		setSession(sessionSubcriber);
		tasks.push({ id: subcriber, tr: null, msg: unpublishedEvent, jsep: null });
		pokeScheduler();

	});
	// Clear some flags

	session.audioCodec = null;
	session.videoCodec = null;
	session.subscribers=[];
	session.isConnected =false
	setSession(session);
}

function incomingTextData(id, buf, len) {
	// Relaying RTP/RTCP in JavaScript makes no sense, but just for fun
	// we handle data channel messages ourselves to manipulate them
	var edit = "[" + name + "]incomingTextData --> " + buf;
	relayTextData(id, edit, edit.length);
}

function incomingBinaryData(id, buf, len) {
	// If the data we're getting is binary, send it back as it is
	relayBinaryData(id, buf, len);
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
	console.log("Lets Confihure the diffrents Media.. ..");

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
			fnbase = "duktape-videoroom-" + id + "-" + new Date().getTime();
		}
		startRecording(id,
			"audio", "opus", "/tmp", fnbase + "-audio",
			"video", "vp8", "/tmp", fnbase + "-video",
			"data", "text", "/tmp", fnbase + "-data"
		);
	} else if(msg["record"] === false) {
		stopRecording(id, "audio", "video", "data");
	}
	tasks.push({ id: id, tr: null, msg: null, jsep: null });
	// Return explaining that this is will be handled asynchronously
	pokeScheduler();
	return 1;
}

// We use this other function to process asynchronous requests
function processAsync(task) {
	// We'll only execute this when the scheduler resumes a task
	var id = task.id;
	var tr = task.tr;
	var msg = task.msg;
	var jsep = task.jsep;
	var jsepOffer = task.jsepOffer;
	var session = getSession(id);
	if(jsep){
		console.log("Handling async message for session:", id,task.msg);
		if(!session) {
			console.log("Can't handle async message: no such session");
			return;
		}
		var offer = sdpUtils.parse(jsep.sdp);
		//hardCode for now to do : to take out of massege ...
		if(session.audioCodec)session.audioCodec = "opus";
		if(session.videoCodec)session.videoCodec = "vp8";

		console.log("Got offer:", offer);
		var answer = sdpUtils.generateAnswer(offer, { audio: true, video: true, data: true });
		console.log("Generated answer:", answer);
		console.log("Processing request:", msg);
		processRequest(id, msg);
		console.log("Pushing event:");
		var event = { videoroom: "event", result: "ok",video_codec:session.videoCodec,audio_codec:session.audioCodec};
		console.log("  --", event);
		var jsepanswer = { type: "answer", sdp: sdpUtils.render(answer) };
		console.log("  --", jsepanswer);

		pushEvent(id, tr, JSON.stringify(event), JSON.stringify(jsepanswer));
		// Just for fun (and to showcase the feature), let's send an event to handlers;
		// notice how we pass the id now, meaning this event is tied to a specific session
		event = { event: "processed", request: msg };
		notifyEvent(id, JSON.stringify(event));
		setSession(session)

	}else if(jsepOffer){

		var jsepOfferReplay = { type: "offer", sdp: sdpUtils.render(jsepOffer) };
		pushEvent(id, tr, JSON.stringify(msg), JSON.stringify(jsepOfferReplay));
	}
	else{
		if(!msg)msg={ videoroom: "event", result: "ok" ,publishers:getRoomPublishersArray(session.room,id)};
		if(!session.private_Id){
			session.private_Id=getRndInteger(100000, 999999);
			setSession(session)
		}
		msg.private_Id=session.private_Id;
		console.log("Pushing Evente to ",id);
		console.log("Event ",msg);
		pushEvent(id, tr, JSON.stringify(msg), null);
	}
}
/*
function getObjectValues(obj){
	arr=[];
	Object.keys(obj).forEach(function (key) {
		arr.push(obj[key]);
	});
	return arr;
}*/
// Done
console.log("Script loaded");
function getRndInteger(min, max) {
	return Math.floor(Math.random() * (max - min + 1) ) + min;
}
/*
function getOtherPublishers(id) {
	var publishersData = [];
	var publishersRealevent  = publishers.filter(function(publisher) {return publisher !== id});
	publishersRealevent.forEach(function (pubId) {
		publishersData.push(sessions[pubId])
	});
	return publishersData;
}*/

function getRoomPublishers(roomId,filterPublisher) {
	var roomObj ={};
	var room = getRoom(roomId);
	room.publishers.forEach(function (publisher) {
		if(publisher!==filterPublisher)roomObj[publisher]=sessions[publisher];
	})
	return roomObj
}
function getRoomPublishersArray(roomId,filterPublisher) {
	var pulisherArray =[];
	var room = getRoom(roomId);
	room.publishers.forEach(function (publisher) {
		if(publisher!==filterPublisher)pulisherArray.push(sessions[publisher]);
	})
	return pulisherArray
}

function getRoom(roomId) {
	var room =  null ;
	if(rooms[roomId]){
		room=rooms[roomId];
	}else {
		// new room template
		var newRoomTemplate =  {roomId :0 , roomName : "" , publishers : [], sessions:[] }
		room =  newRoomTemplate ;
		room.roomId=roomId
		rooms[roomId] = room;
	}
	return room
}
function getSession(sessionID) {
	var session =  null ;
	if(sessions[sessionID]){
		session=sessions[sessionID];
	}else {
		// Objects Templates
		var  newSessionTemplate= { id: 0, janusServer: janusServer,room: 0 ,subscribers:[],publishers:[],isConnected:false } ;
		// new session template
		session =  newSessionTemplate ;
		session.id=sessionID;
		sessions[sessionID] = session;
		console.log("New session was burn !!!! ",sessionID,session)
	}
	return session
}
function setSession(session) {
	sessions[session.id]=session;
	console.log("session was update  !!!! ",session.id,session)
}
function setRoom(room) {
	rooms[room.roomId]=room;
}
