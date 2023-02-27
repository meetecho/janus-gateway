/* eslint-disable no-unused-vars */

// We use this shared JavaScript file as a simple way to have all demos
// refer to the same settings, e.g., in terms of which server to connect
// to or which STUN/TURN servers to use. This is helpful any time Janus
// and its demos need to be deployed in a different environment, and
// so all demos can be installed as are, by just updating the settings.js
// file accordingly to account for the custom changes.
//
// We make use of this 'server' variable to provide the address of the
// Janus API backend. By default, in this example we assume that Janus is
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
// If you want to use the WebSockets frontend to Janus, instead (which
// is what we recommend, since they're more efficient than the long polling
// we do with HTTP), you'll have to pass a different kind of address, e.g.:
//
// 		var server = "ws://" + window.location.hostname + ":8188";
//
// Of course this assumes that support for WebSockets has been built in
// when compiling the server. Notice that the "ws://" prefix assumes
// plain HTTP usage, so "wss://" should be used instead when using
// WebSockets on HTTPS.//
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

// When creating a Janus object, we can also specify which STUN/TURN
// servers we'd like to use to gather additional candidates. This is
// done by passing an "iceServers" property when creating the Janus
// object, meaning that the same set of servers will be used for all
// PeerConnections that will be initialized within the context of the
// new Janus session. When no iceServers object is provided, the janus.js
// library automatically uses the free Google STUN servers, which means
// it's equivalent to setting:
//
//		var iceServers = [{urls: "stun:stun.l.google.com:19302"}];
//
// Here are some examples of how an iceServers field may look like to
// support TURN instead. Notice that, when a TURN server is configured,
// there's no need to set a STUN one as well, since the TURN server will
// be automatically contacted as a STUN server too, meaning it will be
// used to gather both server reflexive and relay candidates.
//
//		var iceServers = [{urls: "turn:yourturnserver.com:3478", username: "janususer", credential: "januspwd"}]
//		var iceServers: [{urls: "turn:yourturnserver.com:443?transport=tcp", username: "janususer", credential: "januspwd"}]
//		var iceServers: [{urls: "turns:yourturnserver.com:443?transport=tcp", username: "janususer", credential: "januspwd"}]
//
// By default we leave the iceServers variable empty, which again means
// janus.js will fallback to the Google STUN server by default:
//
var iceServers = null;
