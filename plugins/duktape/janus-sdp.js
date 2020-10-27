// Set of utilities for parsing, processing && managing Janus SDPs in JS,
// as the C Janus SDP utils that Janus provides are unavailable otherwise

var JANUSSDP = {};

JANUSSDP.parse = function(text) {
	if(!text)
		return null;
	var lines = text.split("\r\n");
	var sdp = [];
	for(var index in lines) {
		var line = lines[index];
		var t = line.substring(0, 1);
		var ll = line.substring(2);
		var sc = ll.indexOf(":");
		var n, v;
		if(sc < 0) {
			n = ll;
		} else {
			n = ll.substring(0, sc);
			v = ll.substring(sc+1);
		}
		sdp.push({ type: t, name: n, value: v });
	}
	return sdp;
}

JANUSSDP.render = function(sdp) {
	if(!sdp)
		return null;
	var sdpString = "";
	for(var index in sdp) {
		var a = sdp[index];
		if(!a.value) {
			sdpString += a.type + "=" + a.name + "\r\n";
		} else {
			sdpString += a.type + "=" + a.name + ":" + a.value + "\r\n";
		}
	}
	return sdpString;
}

JANUSSDP.findPayloadType = function(sdp, codec, profile) {
	if(!sdp || !codec)
		return -1
	var pt = -1;
	var codecUpper = codec.toUpperCase();
	var codecLower = codec.toLowerCase();
	var checkProfile = false;
	for(var index in sdp) {
		var a = sdp[index];
		if(checkProfile && a.name === "fmtp" && a.value) {
			checkProfile = false;
			if(codec === "vp9") {
				if(a.value.indexOf("profile-level="+profile) != -1) {
					// Found
					break;
				}
			} else if(codec === "h264") {
				if(a.value.indexOf("profile-level-id="+profile.toLowerCase()) != -1 ||
						a.value.indexOf("profile-level-id="+profile.toUpperCase()) != -1) {
					// Found
					break;
				}
			}
		} else if(a.name === "rtpmap" && a.value) {
			if(a.value.indexOf(codecLower) != -1 || a.value.indexOf(codecUpper) !== -1) {
				pt = parseInt(a.value);
				if(!profile) {
					// We're done
					break;
				} else {
					// We need to make sure the profile matches
					checkProfile = true;
				}
			}
		}
	}
	return pt;
}

JANUSSDP.findCodec = function(sdp, pt) {
	if(!sdp || pt === null || pt === undefined)
		return -1;
	if(pt === 0) {
		return "pcmu";
	} else if(pt === 8) {
		return "pcma";
	} else if(pt === 9) {
		return "g722";
	}
	var codec = null;
	for(var index in sdp) {
		var a = sdp[index];
		if(a.name === "rtpmap" && a.value) {
			var n = parseInt(a.value);
			if(n === pt) {
				if(a.value.indexOf("vp8") !== -1 || a.value.indexOf("VP8") !== -1) {
					codec = "vp8";
				} else if(a.value.indexOf("vp9") !== -1 || a.value.indexOf("VP9") !== -1) {
					codec = "vp9";
				} else if(a.value.indexOf("h264") !== -1 || a.value.indexOf("H264") !== -1) {
					codec = "h264";
				} else if(a.value.indexOf("opus") !== -1 || a.value.indexOf("OPUS") !== -1) {
					codec = "opus";
				} else if(a.value.indexOf("multiopus") !== -1 || a.value.indexOf("MULTIOPUS") !== -1) {
					codec = "multiopus";
				} else if(a.value.indexOf("pcmu") !== -1 || a.value.indexOf("PCMU") !== -1) {
					codec = "pcmu";
				} else if(a.value.indexOf("pcma") !== -1 || a.value.indexOf("PCMA") !== -1) {
					codec = "pcma";
				} else if(a.value.indexOf("isac16") !== -1 || a.value.indexOf("ISAC16") !== -1) {
					codec = "isac16";
				} else if(a.value.indexOf("isac32") !== -1 || a.value.indexOf("ISAC32") !== -1) {
					codec = "isac32";
				} else if(a.value.indexOf("telephone-event") !== -1 || a.value.indexOf("TELEPHONE-EVENT") !== -1) {
					codec = "isac32";
				}
				break;
			}
		}
	}
	return codec;
}

JANUSSDP.removePayloadType = function(sdp, pt) {
	if(!sdp || pt === null || pt === undefined)
		return;
	for(var index=0; index<sdp.length; index++) {
		var a = sdp[index];
		if(a.type === "m") {
			var m = a.name.replace(" " + pt + " ", " ");
			if(m)
				a.name = m;
			a.name += "\r\n";
			m = a.name.replace(" " + pt + "\r\n", "\r\n");
			if(m)
				a.name = m;
			a.name = a.name.replace("\r\n", "");
		} else if(a.type === "a" && a.value) {
			var n = parseInt(a.value);
			if(n === pt) {
				sdp.splice(index, 1);
				index--;
			}
		}
	}
}

JANUSSDP.generateOffer = function(options) {
	// Let's set some defaults for the options, in case none were given
	options = options || {};
	if(options.audio === null || options.audio === undefined)
		options.audio = true;
	if(options.audio === true && (options.audioPt === null || options.audioPt === undefined))
		options.audioPt = 111;
	if(options.audio === true) {
		if(!options.audioCodec)
			options.audioCodec = "opus";
		if(options.audioCodec === "opus") {
			options.audioRtpmap = "opus/48000/2";
		} else if(options.audioCodec === "multiopus") {
			options.audioRtpmap = "multiopus/48000/6";
		} else if(options.audioCodec === "pcmu") {
			options.audioRtpmap = "PCMU/8000";
			options.audioPt = 0;
		} else if(options.audioCodec === "pcma") {
			options.audioRtpmap = "PCMA/8000";
			options.audioPt = 8;
		} else if(options.audioCodec === "g722") {
			options.audioRtpmap = "G722/8000";
			options.audioPt = 9;
		} else if(options.audioCodec === "isac16") {
			options.audioRtpmap = "ISAC/16000";
		} else if(options.audioCodec === "isac32") {
			options.audioRtpmap = "ISAC/32000";
		} else {
			// Unsupported codec
			options.audio = false;
		}
	}
	if(!options.audioDir)
		options.audioDir = "sendrecv";
	if(options.video === null || options.video === undefined)
		options.video = true;
	if(options.video === true && (options.videoPt === null || options.videoPt === undefined))
		options.videoPt = 96;
	if(options.video === true) {
		if(!options.videoCodec)
			options.videoCodec = "vp8";
		if(options.videoCodec === "vp8") {
			options.videoRtpmap = "VP8/90000";
		} else if(options.videoCodec === "vp9") {
			options.videoRtpmap = "VP9/90000";
		} else if(options.videoCodec === "h264") {
			options.videoRtpmap = "H264/90000";
		} else {
			// Unsupported codec
			options.video = false;
		}
	}
	if(!options.videoDir)
		options.videoDir = "sendrecv";
	if(!options.videoRtcpfb)
		options.videoRtcpfb = true;
	if(options.data === null || options.data === undefined)
		options.data = false;
	if(options.data)
		options.dataDir = "sendrecv";
	if(!options.address)
		options.address = "127.0.0.1";
	if(options.ipv6 !== true && options.ipv6 !== false)
		options.ipv6 = false;
	if(!options.sessionName)
		options.sessionName = "Janus Duktape session";
	// Do we have enough for an offer?
	if(!options.audio && !options.video && !options.data)
		return null;
	// Let's prepare the offer
	var offer = [];
	// Let's start from the session-level attributes
	offer.push({ type: "v", name: "0" });
	offer.push({ type: "o", name: "- " + Math.floor(Math.random(4294967296)) + " 1 IN " +
		(options.ipv6 ? "IP6 " : "IP4 ") + options.address });
	offer.push({ type: "s", name: options.sessionName });
	offer.push({ type: "t", name: "0 0" });
	offer.push({ type: "c", name: "IN " + (options.ipv6 ? "IP6 " : "IP4 ") + options.address });
	// Now let's add the media lines
	if(options.audio) {
		offer.push({ type: "m", name: "audio 9 UDP/TLS/RTP/SAVPF " + options.audioPt });
		offer.push({ type: "c", name: "IN " + (options.ipv6 ? "IP6 " : "IP4 ") + options.address });
		offer.push({ type: "a", name: options.audioDir });
		offer.push({ type: "a", name: "rtpmap", value: options.audioPt + " " + options.audioRtpmap });
		if(options.audioFmtp) {
			offer.push({ type: "a", name: "fmtp", value: options.audioPt + " " + options.audioFmtp });
		}
	}
	if(options.video) {
		offer.push({ type: "m", name: "video 9 UDP/TLS/RTP/SAVPF " + options.videoPt });
		offer.push({ type: "c", name: "IN " + (options.ipv6 ? "IP6 " : "IP4 ") + options.address });
		offer.push({ type: "a", name: options.videoDir });
		offer.push({ type: "a", name: "rtpmap", value: options.videoPt + " " + options.videoRtpmap });
		if(options.videoRtcpfb) {
			offer.push({ type: "a", name: "rtcp-fb", value: options.videoPt + " ccm fir" });
			offer.push({ type: "a", name: "rtcp-fb", value: options.videoPt + " nack" });
			offer.push({ type: "a", name: "rtcp-fb", value: options.videoPt + " nack pli" });
			offer.push({ type: "a", name: "rtcp-fb", value: options.videoPt + " goog-remb" });
		}
		if(options.videoCodec === "vp9" && options.vp9Profile) {
			offer.push({ type: "a", name: "fmtp", value: options.videoPt + " profile-id=" + options.vp9Profile });
		} else if(options.videoCodec === "h264" && options.h264Profile) {
			offer.push({ type: "a", name: "fmtp", value: options.videoPt + " profile-level-id=" + options.h264Profile + ";packetization-mode=1" });
		} else if(options.videoFmtp) {
			offer.push({ type: "a", name: "fmtp", value: options.videoPt + " " + options.videoFmtp });
		} else if(options.videoCodec === "h264") {
			offer.push({ type: "a", name: "fmtp", value: options.videoPt + " profile-level-id=42e01f;packetization-mode=1" });
		}
	}
	if(options.data) {
		offer.push({ type: "m", name: "application 9 DTLS/SCTP 5000" });
		offer.push({ type: "c", name: "IN " + (options.ipv6 ? "IP6 " : "IP4 ") + options.address });
		offer.push({ type: "a", name: "sendrecv" });
		offer.push({ type: "a", name: "sctmap", value: "5000 webrtc-datachannel 16" });
	}
	// Done
	return offer;
}

JANUSSDP.generateAnswer = function(offer, options) {
	if(!offer)
		return null;
	// Let's set some defaults for the options, in case none were given
	options = options || {};
	if(options.audio === null || options.audio === undefined)
		options.audio = true;
	if(options.audio && !options.audioCodec) {
		if(JANUSSDP.findPayloadType(offer, "opus") !== -1) {
			options.audioCodec = "opus";
		} else if(JANUSSDP.findPayloadType(offer, "multiopus") !== -1) {
			options.audioCodec = "multiopus";
		} else if(JANUSSDP.findPayloadType(offer, "pcmu") !== -1) {
			options.audioCodec = "pcmu";
		} else if(JANUSSDP.findPayloadType(offer, "pcma") !== -1) {
			options.audioCodec = "pcma";
		} else if(JANUSSDP.findPayloadType(offer, "g722") !== -1) {
			options.audioCodec = "g722";
		} else if(JANUSSDP.findPayloadType(offer, "isac16") !== -1) {
			options.audioCodec = "isac16";
		} else if(JANUSSDP.findPayloadType(offer, "isac32") !== -1) {
			options.audioCodec = "isac32";
		}
	}
	if(options.video === null || options.video === undefined)
		options.video = true;
	if(options.video && !options.videoCodec) {
		if(JANUSSDP.findPayloadType(offer, "vp8") !== -1) {
			options.videoCodec = "vp8";
		} else if(JANUSSDP.findPayloadType(offer, "vp9", options.vp9Profile) !== -1) {
			options.videoCodec = "vp9";
		} else if(JANUSSDP.findPayloadType(offer, "h264", options.h264Profile) !== -1) {
			options.videoCodec = "h264";
		}
	}
	if(options.data === null || options.data === undefined)
		options.data = true;
	if(options.disableTwcc === null || options.disableTwcc === undefined)
		options.disableTwcc = false;
	// Let's prepare the answer
	var answer = [];
	// Iterate on all lines
	var audio = 0, video = 0, data = 0;
	var audioPt = -1, videoPt = -1;
	var medium = null;
	var reject = false;
	for(var index in offer) {
		var a = offer[index];
		if(!medium && a.type !== "m") {
			// We just copy all the session-level attributes
			if(!a.value)
				answer.push(a);
		}
		if(a.type === "m") {
			// New m-line
			reject = false;
			if(a.name.indexOf("audio") !== -1) {
				medium = "audio";
				audio++;
				if(audioPt < 0)
					audioPt = JANUSSDP.findPayloadType(offer, options.audioCodec);
				if(audioPt < 0)
					audio++;
				if(audio > 1) {
					reject = true;
					answer.push({ type: "m", name: "audio 0 UDP/TLS/RTP/SAVPF 0" });
				} else {
					answer.push({ type: "m", name: "audio 9 UDP/TLS/RTP/SAVPF " + audioPt });
				}
			} else if(a.name.indexOf("video") !== -1) {
				medium = "video";
				video++;
				if(videoPt < 0) {
					if(options.videoCodec === "vp9") {
						videoPt = JANUSSDP.findPayloadType(offer, options.videoCodec, options.vp9Profile);
					} else if(options.videoCodec == "h264") {
						videoPt = JANUSSDP.findPayloadType(offer, options.videoCodec, options.h264Profile);
					} else {
						videoPt = JANUSSDP.findPayloadType(offer, options.videoCodec);
					}
				}

				if(videoPt < 0)
					video++;
				if(video > 1) {
					reject = true;
					answer.push({ type: "m", name: "video 0 UDP/TLS/RTP/SAVPF 0" });
				} else {
					answer.push({ type: "m", name: "video 9 UDP/TLS/RTP/SAVPF " + videoPt });
				}
			} else if(a.name.indexOf("application") !== -1) {
				medium = "application";
				data = data+1
				if(data > 1) {
					reject = true
					answer.push({ type: "m", name: "application 0 DTLS/SCTP 5000" });
				} else {
					answer.push({ type: "m", name: a.name });
				}
			}
		} else if(a.type === "a") {
			if(a.name === "sendonly") {
				answer.push({ type: "a", name: "recvonly" });
			} else if(a.name === "recvonly") {
				answer.push({ type: "a", name: "sendonly" });
			} else if(a.value) {
				if(a.name === "rtpmap" || a.name === "fmtp" || a.name === "rtcp-fb") {
					// Drop attributes associated to payload types we're getting rid of
					var n = parseInt(a.value);
					if(medium === "audio" && n === audioPt) {
						answer.push(a);
					} else if(medium === "video" && n === videoPt) {
						answer.push(a);
					}
				} else if (a.name === "extmap") {
					// We do negotiate some RTP extensions
					if(a.value.indexOf("urn:ietf:params:rtp-hdrext:sdes:mid") !== -1) {
						answer.push(a);
					} else if(a.value.indexOf("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id") !== -1) {
						answer.push(a);
					} else if(a.value.indexOf("urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id") !== -1) {
						answer.push(a);
					} else if(options.disableTwcc !== true && a.value.indexOf("draft-holmer-rmcat-transport-wide-cc-extensions-01") !== -1) {
						answer.push(a);
					}
				}
			} else {
				answer.push(a);
			}
			// TODO Handle/filter other attributes
		}
	}
	// Done
	return answer;
}

module.exports = JANUSSDP;
