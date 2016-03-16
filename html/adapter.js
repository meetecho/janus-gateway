/*
 *  Copyright (c) 2014 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */

/* More information about these options at jshint.com/docs/options */
/* global mozRTCIceCandidate, mozRTCPeerConnection,
mozRTCSessionDescription, webkitRTCPeerConnection */
/* exported trace,requestUserMedia */

/*
 *  Edge support provided thanks to the adaptation devised by SimpleWebRTC
 *
 * 		https://simplewebrtc.com/bundle-edge.js
 * 
 */

//~ 'use strict';

var RTCPeerConnection = null;
var getUserMedia = null;
var attachMediaStream = null;
var reattachMediaStream = null;
var webrtcDetectedBrowser = null;
var webrtcDetectedVersion = null;

function trace(text) {
  // This function is used for logging.
  if (text[text.length - 1] === '\n') {
    text = text.substring(0, text.length - 1);
  }
  if (window.performance) {
    var now = (window.performance.now() / 1000).toFixed(3);
    console.log(now + ': ' + text);
  } else {
    console.log(text);
  }
}

function maybeFixConfiguration(pcConfig) {
  if (!pcConfig) {
    return;
  }
  for (var i = 0; i < pcConfig.iceServers.length; i++) {
    if (pcConfig.iceServers[i].hasOwnProperty('urls')) {
      pcConfig.iceServers[i].url = pcConfig.iceServers[i].urls;
      delete pcConfig.iceServers[i].urls;
    }
  }
}

if (navigator.mozGetUserMedia) {
  console.log('This appears to be Firefox');

  webrtcDetectedBrowser = 'firefox';

  webrtcDetectedVersion =
    parseInt(navigator.userAgent.match(/Firefox\/([0-9]+)\./)[1], 10);

  // The RTCPeerConnection object.
  RTCPeerConnection = function(pcConfig, pcConstraints) {
    // .urls is not supported in FF yet.
    maybeFixConfiguration(pcConfig);
    return new mozRTCPeerConnection(pcConfig, pcConstraints);
  };

  // The RTCSessionDescription object.
  window.RTCSessionDescription = mozRTCSessionDescription;

  // The RTCIceCandidate object.
  window.RTCIceCandidate = mozRTCIceCandidate;

  // getUserMedia shim (only difference is the prefix).
  // Code from Adam Barth.
  getUserMedia = navigator.mozGetUserMedia.bind(navigator);
  navigator.getUserMedia = getUserMedia;

  // Shim for MediaStreamTrack.getSources.
  MediaStreamTrack.getSources = function(successCb) {
    setTimeout(function() {
      var infos = [
        { kind: 'audio', id: 'default', label:'', facing:'' },
        { kind: 'video', id: 'default', label:'', facing:'' }
      ];
      successCb(infos);
    }, 0);
  };

  // Creates ICE server from the URL for FF.
  window.createIceServer = function(url, username, password) {
    var iceServer = null;
    var urlParts = url.split(':');
    if (urlParts[0].indexOf('stun') === 0) {
      // Create ICE server with STUN URL.
      iceServer = {
        'url': url
      };
    } else if (urlParts[0].indexOf('turn') === 0) {
      if (webrtcDetectedVersion < 27) {
        // Create iceServer with turn url.
        // Ignore the transport parameter from TURN url for FF version <=27.
        var turnUrlParts = url.split('?');
        // Return null for createIceServer if transport=tcp.
        if (turnUrlParts.length === 1 ||
          turnUrlParts[1].indexOf('transport=udp') === 0) {
          iceServer = {
            'url': turnUrlParts[0],
            'credential': password,
            'username': username
          };
        }
      } else {
        // FF 27 and above supports transport parameters in TURN url,
        // So passing in the full url to create iceServer.
        iceServer = {
          'url': url,
          'credential': password,
          'username': username
        };
      }
    }
    return iceServer;
  };

  window.createIceServers = function(urls, username, password) {
    var iceServers = [];
    // Use .url for FireFox.
    for (var i = 0; i < urls.length; i++) {
      var iceServer =
        window.createIceServer(urls[i], username, password);
      if (iceServer !== null) {
        iceServers.push(iceServer);
      }
    }
    return iceServers;
  };

  // Attach a media stream to an element.
  attachMediaStream = function(element, stream) {
    console.log('Attaching media stream');
    element.mozSrcObject = stream;
  };

  reattachMediaStream = function(to, from) {
    console.log('Reattaching media stream');
    to.mozSrcObject = from.mozSrcObject;
  };

} else if (navigator.webkitGetUserMedia) {
  console.log('This appears to be Chrome');

  webrtcDetectedBrowser = 'chrome';
  // Temporary fix until crbug/374263 is fixed.
  // Setting Chrome version to 999, if version is unavailable.
  var result = navigator.userAgent.match(/Chrom(e|ium)\/([0-9]+)\./);
  if (result !== null) {
    webrtcDetectedVersion = parseInt(result[2], 10);
  } else {
    webrtcDetectedVersion = 999;
  }

  // Creates iceServer from the url for Chrome M33 and earlier.
  window.createIceServer = function(url, username, password) {
    var iceServer = null;
    var urlParts = url.split(':');
    if (urlParts[0].indexOf('stun') === 0) {
      // Create iceServer with stun url.
      iceServer = {
        'url': url
      };
    } else if (urlParts[0].indexOf('turn') === 0) {
      // Chrome M28 & above uses below TURN format.
      iceServer = {
        'url': url,
        'credential': password,
        'username': username
      };
    }
    return iceServer;
  };

  // Creates an ICEServer object from multiple URLs.
  window.createIceServers = function(urls, username, password) {
    return {
      'urls': urls,
      'credential': password,
      'username': username
    };
  };

  // The RTCPeerConnection object.
  RTCPeerConnection = function(pcConfig, pcConstraints) {
    return new webkitRTCPeerConnection(pcConfig, pcConstraints);
  };

  // Get UserMedia (only difference is the prefix).
  // Code from Adam Barth.
  getUserMedia = navigator.webkitGetUserMedia.bind(navigator);
  navigator.getUserMedia = getUserMedia;

  // Attach a media stream to an element.
  attachMediaStream = function(element, stream) {
    if (typeof element.srcObject !== 'undefined') {
      element.srcObject = stream;
    } else if (typeof element.mozSrcObject !== 'undefined') {
      element.mozSrcObject = stream;
    } else if (typeof element.src !== 'undefined') {
      element.src = URL.createObjectURL(stream);
    } else {
      console.log('Error attaching stream to element.');
    }
  };

  reattachMediaStream = function(to, from) {
    to.src = from.src;
  };
} else if (navigator.mediaDevices && navigator.userAgent.match(
    /Edge\/(\d+).(\d+)$/)) {
  console.log('This appears to be Edge');
  webrtcDetectedBrowser = 'edge';

  webrtcDetectedVersion =
    parseInt(navigator.userAgent.match(/Edge\/(\d+).(\d+)$/)[2], 10);

  // the minimum version still supported by adapter.
  webrtcMinimumVersion = 10525;

  // getUserMedia has no prefix in Edge
  getUserMedia = navigator.getUserMedia.bind(navigator);
  navigator.getUserMedia = getUserMedia;

  // Shim for MediaStreamTrack.getSources.
  MediaStreamTrack.getSources = function(successCb) {
    setTimeout(function() {
      var infos = [
        { kind: 'audio', id: 'default', label:'', facing:'' },
        { kind: 'video', id: 'default', label:'', facing:'' }
      ];
      successCb(infos);
    }, 0);
  };

  // Attach a media stream to an element.
  attachMediaStream = function(element, stream) {
    console.log('Attaching media stream');
    element.srcObject = stream;
  };

  reattachMediaStream = function(to, from) {
    console.log('Reattaching media stream');
    to.srcObject = from.srcObject;
  };

  if (RTCIceGatherer) {
    window.RTCIceCandidate = function(args) {
      return args;
    };
    window.RTCSessionDescription = function(args) {
      return args;
    };

    window.RTCPeerConnection = function(config) {
      var self = this;

      this.onicecandidate = null;
      this.onaddstream = null;
      this.onremovestream = null;
      this.onsignalingstatechange = null;
      this.oniceconnectionstatechange = null;
      this.onnegotiationneeded = null;
      this.ondatachannel = null;

      this.localStreams = [];
      this.remoteStreams = [];
      this.getLocalStreams = function() { return self.localStreams; };
      this.getRemoteStreams = function() { return self.remoteStreams; };

      this.localDescription = new RTCSessionDescription({
        type: '',
        sdp: ''
      });
      this.remoteDescription = new RTCSessionDescription({
        type: '',
        sdp: ''
      });
      this.signalingState = 'stable';
      this.iceConnectionState = 'new';

      this.iceOptions = {
        gatherPolicy: 'all',
        iceServers: []
      };
      if (config && config.iceTransportPolicy) {
        switch (config.iceTransportPolicy) {
        case 'all':
        case 'relay':
          this.iceOptions.gatherPolicy = config.iceTransportPolicy;
          break;
        case 'none':
          console.warn('can not map iceTransportPolicy none,' +
              'falling back to "all"');
          break;
        }
      }
      //~ if (config && config.iceServers) {
        //~ // Make sure urls is used (http://ortc.org/wp-content/uploads/2015/06/ortc.html#idl-def-RTCIceServer)
        //~ for (var i = 0; i < config.iceServers.length; i++) {
          //~ if (config.iceServers[i].hasOwnProperty('url')) {
            //~ config.iceServers[i].urls = config.iceServers[i].url;
            //~ delete config.iceServers[i].url;
          //~ }
        //~ }
        //~ this.iceOptions.iceServers = config.iceServers;
        //~ this.iceOptions.iceServers.urls = this.iceOptions.iceServers.url;
      //~ }

      // per-track iceGathers etc
      this.tracks = [];

      this._iceCandidates = [];

      this._peerConnectionId = 'PC_' + Math.floor(Math.random() * 65536);

      // FIXME: Should be generated according to spec (guid?)
      // and be the same for all PCs from the same JS
      this._cname = Math.random().toString(36).substr(2, 10);
    };

    window.RTCPeerConnection.prototype.addStream = function(stream) {
      // clone just in case we're working in a local demo
      // FIXME: seems to be fixed
      this.localStreams.push(stream.clone());

      // FIXME: maybe trigger negotiationneeded?
    };

    window.RTCPeerConnection.prototype.removeStream = function(stream) {
      var idx = this.localStreams.indexOf(stream);
      if (idx > -1) {
        this.localStreams.splice(idx, 1);
      }
      // FIXME: maybe trigger negotiationneeded?
    };

    // SDP helper from sdp-jingle-json with modifications.
    window.RTCPeerConnection.prototype._toCandidateJSON = function(line) {
      var parts;
      if (line.indexOf('a=candidate:') === 0) {
        parts = line.substring(12).split(' ');
      } else { // no a=candidate
        parts = line.substring(10).split(' ');
      }

      var candidate = {
        foundation: parts[0],
        component: parts[1],
        protocol: parts[2].toLowerCase(),
        priority: parseInt(parts[3], 10),
        ip: parts[4],
        port: parseInt(parts[5], 10),
        // skip parts[6] == 'typ'
        type: parts[7]
        //generation: '0'
      };

      for (var i = 8; i < parts.length; i += 2) {
        if (parts[i] === 'raddr') {
          candidate.relatedAddress = parts[i + 1]; // was: relAddr
        } else if (parts[i] === 'rport') {
          candidate.relatedPort = parseInt(parts[i + 1], 10); // was: relPort
        } else if (parts[i] === 'generation') {
          candidate.generation = parts[i + 1];
        } else if (parts[i] === 'tcptype') {
          candidate.tcpType = parts[i + 1];
        }
      }
      return candidate;
    };

    // SDP helper from sdp-jingle-json with modifications.
    window.RTCPeerConnection.prototype._toCandidateSDP = function(candidate) {
      var sdp = [];
      sdp.push(candidate.foundation);
      sdp.push(candidate.component);
      sdp.push(candidate.protocol.toUpperCase());
      sdp.push(candidate.priority);
      sdp.push(candidate.ip);
      sdp.push(candidate.port);

      var type = candidate.type;
      sdp.push('typ');
      sdp.push(type);
      if (type === 'srflx' || type === 'prflx' || type === 'relay') {
        if (candidate.relatedAddress && candidate.relatedPort) {
          sdp.push('raddr');
          sdp.push(candidate.relatedAddress); // was: relAddr
          sdp.push('rport');
          sdp.push(candidate.relatedPort); // was: relPort
        }
      }
      if (candidate.tcpType && candidate.protocol.toUpperCase() === 'TCP') {
        sdp.push('tcptype');
        sdp.push(candidate.tcpType);
      }
      return 'a=candidate:' + sdp.join(' ');
    };

    // SDP helper from sdp-jingle-json with modifications.
    window.RTCPeerConnection.prototype._parseRtpMap = function(line) {
      var parts = line.substr(9).split(' ');
      var parsed = {
        payloadType: parseInt(parts.shift(), 10) // was: id
      };

      parts = parts[0].split('/');

      parsed.name = parts[0];
      parsed.clockRate = parseInt(parts[1], 10); // was: clockrate
      parsed.numChannels = parts.length === 3 ? parseInt(parts[2], 10) : 1; // was: channels
      return parsed;
    };

    // Parses SDP to determine capabilities.
    window.RTCPeerConnection.prototype._getRemoteCapabilities =
        function(section) {
      var remoteCapabilities = {
        codecs: [],
        headerExtensions: [],
        fecMechanisms: []
      };
      var i;
      var lines = section.split('\r\n');
      var mline = lines[0].substr(2).split(' ');
      var rtpmapFilter = function(line) {
        return line.indexOf('a=rtpmap:' + mline[i]) === 0;
      };
      var fmtpFilter = function(line) {
        return line.indexOf('a=fmtp:' + mline[i]) === 0;
      };
      var parseFmtp = function(line) {
        var parsed = {};
        var kv;
        var parts = line.substr(('a=fmtp:' + mline[i]).length + 1).split(';');
        for (var j = 0; j < parts.length; j++) {
          kv = parts[j].split('=');
          parsed[kv[0].trim()] = kv[1];
        }
        console.log('fmtp', mline[i], parsed);
        return parsed;
      };
      var rtcpFbFilter = function(line) {
        return line.indexOf('a=rtcp-fb:' + mline[i]) === 0;
      };
      var parseRtcpFb = function(line) {
        var parts = line.substr(('a=rtcp-fb:' + mline[i]).length + 1)
            .split(' ');
        return {
          type: parts.shift(),
          parameter: parts.join(' ')
        };
      };
      for (i = 3; i < mline.length; i++) { // find all codecs from mline[3..]
        var line = lines.filter(rtpmapFilter)[0];
        if (line) {
          var codec = this._parseRtpMap(line);
          // Don't add codecs we know WebRTC browsers don't support
          if(codec.name.toLowerCase() !== "opus" &&
              codec.name.toLowerCase() !== "pcma" &&
              codec.name.toLowerCase() !== "pcmu" &&
              codec.name.toLowerCase() !== "h264" &&
              codec.name.toLowerCase() !== "x-h264uc" &&
              codec.name.toLowerCase() !== "vp8")
            continue;
          var fmtp = lines.filter(fmtpFilter);
          codec.parameters = fmtp.length ? parseFmtp(fmtp[0]) : {};
          codec.rtcpFeedback = lines.filter(rtcpFbFilter).map(parseRtcpFb);

          remoteCapabilities.codecs.push(codec);
        }
      }
      return remoteCapabilities;
    };

    // Serializes capabilities to SDP.
    window.RTCPeerConnection.prototype._capabilitiesToSDP = function(caps) {
      var sdp = '';
      caps.codecs.forEach(function(codec) {
        var pt = codec.payloadType;
        if (codec.preferredPayloadType !== undefined) {
          pt = codec.preferredPayloadType;
        }
        sdp += 'a=rtpmap:' + pt +
            ' ' + codec.name +
            '/' + codec.clockRate +
            (codec.numChannels !== 1 ? '/' + codec.numChannels : '') +
            '\r\n';
        if (codec.parameters && codec.parameters.length) {
          sdp += 'a=ftmp:' + pt + ' ';
          Object.keys(codec.parameters).forEach(function(param) {
            sdp += param + '=' + codec.parameters[param];
          });
          sdp += '\r\n';
        }
        if (codec.rtcpFeedback) {
          // FIXME: special handling for trr-int?
          codec.rtcpFeedback.forEach(function(fb) {
            sdp += 'a=rtcp-fb:' + pt + ' ' + fb.type + ' ' +
                fb.parameter + '\r\n';
          });
        }
      });
      return sdp;
    };

    // Calculates the intersection of local and remote capabilities.
    window.RTCPeerConnection.prototype._getCommonCapabilities =
        function(localCapabilities, remoteCapabilities) {
      console.warn(localCapabilities);
      console.warn(remoteCapabilities);
      var commonCapabilities = {
        codecs: [],
        headerExtensions: [],
        fecMechanisms: []
      };
      localCapabilities.codecs.forEach(function(lCodec) {
        for (var i = 0; i < remoteCapabilities.codecs.length; i++) {
          var rCodec = remoteCapabilities.codecs[i];
          //~ if(rCodec.name.toLowerCase() === "h264")
            //~ rCodec.name = "X-H264UC";	// Ugly attempt to make H264 negotiation work
          if (lCodec.name.toLowerCase() === rCodec.name.toLowerCase() &&
              lCodec.clockRate === rCodec.clockRate &&
              lCodec.numChannels === rCodec.numChannels) {
            // push rCodec so we reply with offerer payload type
            commonCapabilities.codecs.push(rCodec);

            // FIXME: also need to calculate intersection between
            // .rtcpFeedback and .parameters
            break;
          }
        }
      });

      localCapabilities.headerExtensions.forEach(function(lHeaderExtension) {
        for (var i = 0; i < remoteCapabilities.headerExtensions.length; i++) {
          var rHeaderExtension = remoteCapabilities.headerExtensions[i];
          if (lHeaderExtension.uri === rHeaderExtension.uri) {
            commonCapabilities.headerExtensions.push(rHeaderExtension);
            break;
          }
        }
      });

      // FIXME: fecMechanisms
      return commonCapabilities;
    };

    // Parses DTLS parameters from SDP section or sessionpart.
    window.RTCPeerConnection.prototype._getDtlsParameters =
        function(section, session) {
      var lines = section.split('\r\n');
      lines = lines.concat(session.split('\r\n')); // Search in session part, too.
      var fpLine = lines.filter(function(line) {
        return line.indexOf('a=fingerprint:') === 0;
      });
      fpLine = fpLine[0].substr(14);
      var dtlsParameters = {
        role: 'auto',
        fingerprints: [{
          algorithm: fpLine.split(' ')[0],
          value: fpLine.split(' ')[1]
        }]
      };
      return dtlsParameters;
    };

    // Serializes DTLS parameters to SDP.
    window.RTCPeerConnection.prototype._dtlsParametersToSDP =
        function(params, setupType) {
      var sdp = 'a=setup:' + setupType + '\r\n';
      params.fingerprints.forEach(function(fp) {
        sdp += 'a=fingerprint:' + fp.algorithm + ' ' + fp.value + '\r\n';
      });
      return sdp;
    };

    // Parses ICE information from SDP section or sessionpart.
    window.RTCPeerConnection.prototype._getIceParameters =
        function(section, session) {
      var lines = section.split('\r\n');
      lines = lines.concat(session.split('\r\n')); // Search in session part, too.
      var iceParameters = {
        usernameFragment: lines.filter(function(line) {
          return line.indexOf('a=ice-ufrag:') === 0;
        })[0].substr(12),
        password: lines.filter(function(line) {
          return line.indexOf('a=ice-pwd:') === 0;
        })[0].substr(10),
      };
      return iceParameters;
    };

    // Serializes ICE parameters to SDP.
    window.RTCPeerConnection.prototype._iceParametersToSDP = function(params) {
      return 'a=ice-ufrag:' + params.usernameFragment + '\r\n' +
          'a=ice-pwd:' + params.password + '\r\n';
    };

    window.RTCPeerConnection.prototype._getEncodingParameters = function(ssrc) {
      return {
        ssrc: ssrc,
        codecPayloadType: 0,
        fec: 0,
        rtx: 0,
        priority: 1.0,
        maxBitrate: 2000000.0,
        minQuality: 0,
        framerateBias: 0.5,
        resolutionScale: 1.0,
        framerateScale: 1.0,
        active: true,
        dependencyEncodingId: undefined,
        encodingId: undefined
      };
    };

    // Create ICE gatherer, ICE transport and DTLS transport.
    window.RTCPeerConnection.prototype._createIceAndDtlsTransports =
        function(mid, sdpMLineIndex) {
      var self = this;
      var iceGatherer = new RTCIceGatherer(self.iceOptions);
      var iceTransport = new RTCIceTransport(iceGatherer);
      iceGatherer.onlocalcandidate = function(evt) {
        var event = {};
        event.candidate = {sdpMid: mid, sdpMLineIndex: sdpMLineIndex};

        var cand = evt.candidate;
        var isEndOfCandidates = !(cand && Object.keys(cand).length > 0);
        if (isEndOfCandidates) {
          event.candidate.candidate =
              'candidate:1 1 udp 1 0.0.0.0 9 typ endOfCandidates';
        } else {
          // RTCIceCandidate doesn't have a component, needs to be added
          cand.component = iceTransport.component === 'RTCP' ? 2 : 1;
          event.candidate.candidate = self._toCandidateSDP(cand);
        }
        if (self.onicecandidate !== null) {
          if (self.localDescription && self.localDescription.type === '') {
            self._iceCandidates.push(event);
          } else {
            self.onicecandidate(event);
          }
        }
      };
      iceTransport.onicestatechange = function() {
        console.log(self._peerConnectionId,
            'ICE state change', iceTransport.state);
        self._updateIceConnectionState(iceTransport.state);
      };

      var dtlsTransport = new RTCDtlsTransport(iceTransport);
      dtlsTransport.ondtlsstatechange = function() {
        /*
        console.log(self._peerConnectionId, sdpMLineIndex,
            'dtls state change', dtlsTransport.state);
        */
      };
      dtlsTransport.onerror = function(error) {
        console.error('dtls error', error);
      };
      return {
        iceGatherer: iceGatherer,
        iceTransport: iceTransport,
        dtlsTransport: dtlsTransport
      };
    };

    window.RTCPeerConnection.prototype.setLocalDescription =
        function(description) {
      var self = this;
      if (description.type === 'offer') {
        if (!description.ortc) {
          // FIXME: throw?
        } else {
          this.tracks = description.ortc;
        }
      } else if (description.type === 'answer') {
        var sections = self.remoteDescription.sdp.split('\r\nm=');
        var sessionpart = sections.shift();
        sections.forEach(function(section, sdpMLineIndex) {
          section = 'm=' + section;

          var iceGatherer = self.tracks[sdpMLineIndex].iceGatherer;
          var iceTransport = self.tracks[sdpMLineIndex].iceTransport;
          var dtlsTransport = self.tracks[sdpMLineIndex].dtlsTransport;
          var rtpSender = self.tracks[sdpMLineIndex].rtpSender;
          var localCapabilities =
              self.tracks[sdpMLineIndex].localCapabilities;
          var remoteCapabilities =
              self.tracks[sdpMLineIndex].remoteCapabilities;
          var sendSSRC = self.tracks[sdpMLineIndex].sendSSRC;
          var recvSSRC = self.tracks[sdpMLineIndex].recvSSRC;

          for(var c in self.tracks[sdpMLineIndex].remoteCandidates) {
            var candidate = self.tracks[sdpMLineIndex].remoteCandidates[c];
            self.addIceCandidate(candidate);
          }  

          var remoteIceParameters = self._getIceParameters(section,
              sessionpart);
          iceTransport.start(iceGatherer, remoteIceParameters, 'controlled');

          var remoteDtlsParameters = self._getDtlsParameters(section,
              sessionpart);
          dtlsTransport.start(remoteDtlsParameters);

          if (rtpSender) {
            // calculate intersection of capabilities
            var params = self._getCommonCapabilities(localCapabilities,
                remoteCapabilities);
            params.muxId = sendSSRC;
            params.encodings = [self._getEncodingParameters(sendSSRC)];
            params.rtcp = {
              cname: self._cname,
              reducedSize: false,
              ssrc: recvSSRC,
              mux: true
            };
            rtpSender.send(params);
          }
        });
      }

      this.localDescription = description;
      switch (description.type) {
      case 'offer':
        this._updateSignalingState('have-local-offer');
        break;
      case 'answer':
        this._updateSignalingState('stable');
        break;
      }

      // FIXME: need to _reliably_ execute after args[1] or promise
      window.setTimeout(function() {
        // FIXME: need to apply ice candidates in a way which is async but in-order
        self._iceCandidates.forEach(function(event) {
          if (self.onicecandidate !== null) {
            self.onicecandidate(event);
          }
        });
        self._iceCandidates = [];
      }, 50);
      if (arguments.length > 1 && typeof arguments[1] === 'function') {
        window.setTimeout(arguments[1], 0);
      }
      return new Promise(function(resolve) {
        resolve();
      });
    };

    window.RTCPeerConnection.prototype.setRemoteDescription =
        function(description) {
      // FIXME: for type=offer this creates state. which should not
      //  happen before SLD with type=answer but... we need the stream
      //  here for onaddstream.
      var self = this;
      var sections = description.sdp.split('\r\nm=');
      var sessionpart = sections.shift();
      var stream = new MediaStream();
      sections.forEach(function(section, sdpMLineIndex) {
        section = 'm=' + section;
        var lines = section.split('\r\n');
        var mline = lines[0].substr(2).split(' ');
        var kind = mline[0];
        var line;

        var iceGatherer;
        var iceTransport;
        var dtlsTransport;
        var rtpSender;
        var rtpReceiver;
        var sendSSRC;
        var recvSSRC;

        var mid = lines.filter(function(line) {
          return line.indexOf('a=mid:') === 0;
        })[0].substr(6);

        var cname;

        var remoteCapabilities;
        var params;

        if (description.type === 'offer') {
          var transports = self._createIceAndDtlsTransports(mid, sdpMLineIndex);

          var localCapabilities = RTCRtpReceiver.getCapabilities(kind);
          // determine remote caps from SDP
          remoteCapabilities = self._getRemoteCapabilities(section);

          line = lines.filter(function(line) {
            return line.indexOf('a=ssrc:') === 0 &&
                line.split(' ')[1].indexOf('cname:') === 0;
          });
          sendSSRC = (2 * sdpMLineIndex + 2) * 1001;
          if (line) { // FIXME: alot of assumptions here
            recvSSRC = line[0].split(' ')[0].split(':')[1];
            cname = line[0].split(' ')[1].split(':')[1];
          }
          rtpReceiver = new RTCRtpReceiver(transports.dtlsTransport, kind);

          // calculate intersection so no unknown caps get passed into the RTPReciver
          params = self._getCommonCapabilities(localCapabilities,
              remoteCapabilities);

          params.muxId = recvSSRC;
          params.encodings = [self._getEncodingParameters(recvSSRC)];
          params.rtcp = {
            cname: cname,
            reducedSize: false,
            ssrc: sendSSRC,
            mux: true
          };
          console.warn("rtpReceiver:",params);
          rtpReceiver.receive(params);
          // FIXME: not correct when there are multiple streams but that is
          // not currently supported.
          stream.addTrack(rtpReceiver.track);

          // FIXME: honor a=sendrecv
          if (self.localStreams.length > 0 &&
              self.localStreams[0].getTracks().length >= sdpMLineIndex) {
            // FIXME: actually more complicated, needs to match types etc
            var localtrack = self.localStreams[0].getTracks()[sdpMLineIndex];
            rtpSender = new RTCRtpSender(localtrack, transports.dtlsTransport);
          }

          self.tracks[sdpMLineIndex] = {
            iceGatherer: transports.iceGatherer,
            iceTransport: transports.iceTransport,
            dtlsTransport: transports.dtlsTransport,
            localCapabilities: localCapabilities,
            remoteCapabilities: remoteCapabilities,
            rtpSender: rtpSender,
            rtpReceiver: rtpReceiver,
            kind: kind,
            mid: mid,
            sendSSRC: sendSSRC,
            recvSSRC: recvSSRC,
            remoteCandidates: []
          };
        } else {
          iceGatherer = self.tracks[sdpMLineIndex].iceGatherer;
          iceTransport = self.tracks[sdpMLineIndex].iceTransport;
          dtlsTransport = self.tracks[sdpMLineIndex].dtlsTransport;
          rtpSender = self.tracks[sdpMLineIndex].rtpSender;
          rtpReceiver = self.tracks[sdpMLineIndex].rtpReceiver;
          sendSSRC = self.tracks[sdpMLineIndex].sendSSRC;
          recvSSRC = self.tracks[sdpMLineIndex].recvSSRC;
        }

        var remoteIceParameters = self._getIceParameters(section, sessionpart);
        var remoteDtlsParameters = self._getDtlsParameters(section,
            sessionpart);

        // There may be candidates listed in the SDP
        var candidatesFilter = function(line) {
          return line.indexOf('a=candidate:') === 0;
        };
        var candidates = lines.filter(candidatesFilter);
        if(candidates.length) {
          for(var i=0; i<candidates.length; i++) {
            var candidate = { candidate: candidates[i].substr(2), sdpMid: kind, sdpMLineIndex: sdpMLineIndex };
            self.tracks[sdpMLineIndex].remoteCandidates.push(candidate);
          }
          var lastCandidate = { candidate: 'candidate:1 1 udp 1 0.0.0.0 9 typ endOfCandidates', sdpMid: kind, sdpMLineIndex: sdpMLineIndex };
          self.tracks[sdpMLineIndex].remoteCandidates.push(lastCandidate);
        }

        // for answers we start ice and dtls here, otherwise this is done in SLD
        if (description.type === 'answer') {
          for(var c in self.tracks[sdpMLineIndex].remoteCandidates) {
            var candidate = self.tracks[sdpMLineIndex].remoteCandidates[c];
            self.addIceCandidate(candidate);
          }  

          iceTransport.start(iceGatherer, remoteIceParameters, 'controlling');
          dtlsTransport.start(remoteDtlsParameters);

          // determine remote caps from SDP
          remoteCapabilities = self._getRemoteCapabilities(section);
          // FIXME: store remote caps?

          // FIXME: only if a=sendrecv
          var bidi = lines.filter(function(line) {
            return line.indexOf('a=ssrc:') === 0;
          }).length > 0;
          if (rtpReceiver && bidi) {
            line = lines.filter(function(line) {
              return line.indexOf('a=ssrc:') === 0 &&
                  line.split(' ')[1].indexOf('cname:') === 0;
            });
            if (line) { // FIXME: alot of assumptions here
              recvSSRC = line[0].split(' ')[0].split(':')[1];
              cname = line[0].split(' ')[1].split(':')[1];
            }
            params = remoteCapabilities;
            params.muxId = recvSSRC;
            params.encodings = [self._getEncodingParameters(recvSSRC)];
            params.rtcp = {
              cname: cname,
              reducedSize: false,
              ssrc: sendSSRC,
              mux: true
            };
            console.warn("rtpReceiver:", params, kind);
            rtpReceiver.receive(params, kind);
            stream.addTrack(rtpReceiver.track);
            self.tracks[sdpMLineIndex].recvSSRC = recvSSRC;
          }
          if (rtpSender) {
            params = remoteCapabilities;
            params.muxId = sendSSRC;
            params.encodings = [self._getEncodingParameters(sendSSRC)];
            params.rtcp = {
              cname: self._cname,
              reducedSize: false,
              ssrc: recvSSRC,
              mux: true
            };
            console.warn("rtpSender:",params);
            rtpSender.send(params);
          }

        }
      });

      this.remoteDescription = description;
      switch (description.type) {
      case 'offer':
        this._updateSignalingState('have-remote-offer');
        break;
      case 'answer':
        this._updateSignalingState('stable');
        break;
      }
      window.setTimeout(function() {
        if (self.onaddstream !== null && stream.getTracks().length) {
          window.setTimeout(function() {
            self.onaddstream({stream: stream});
          }, 0);
        }
      }, 0);
      if (arguments.length > 1 && typeof arguments[1] === 'function') {
        window.setTimeout(arguments[1], 0);
      }
      return new Promise(function(resolve) {
        resolve();
      });
    };

    window.RTCPeerConnection.prototype.close = function() {
      this.tracks.forEach(function(track) {
        /* not yet
        if (track.iceGatherer) {
          track.iceGatherer.close();
        }
        */
        if (track.iceTransport) {
          track.iceTransport.stop();
        }
        if (track.dtlsTransport) {
          track.dtlsTransport.stop();
        }
        if (track.rtpSender) {
          track.rtpSender.stop();
        }
        if (track.rtpReceiver) {
          track.rtpReceiver.stop();
        }
      });
      // FIXME: clean up tracks, local streams, remote streams, etc
      this._updateSignalingState('closed');
      this._updateIceConnectionState('closed');
    };

    // Update the signaling state.
    window.RTCPeerConnection.prototype._updateSignalingState =
        function(newState) {
      this.signalingState = newState;
      if (this.onsignalingstatechange !== null) {
        this.onsignalingstatechange();
      }
    };

    // Update the ICE connection state.
    window.RTCPeerConnection.prototype._updateIceConnectionState =
        function(newState) {
      var self = this;
      if (this.iceConnectionState !== newState) {
        var agreement = self.tracks.every(function(track) {
          return track.iceTransport.state === newState;
        });
        if (agreement) {
          self.iceConnectionState = newState;
          if (this.oniceconnectionstatechange !== null) {
            this.oniceconnectionstatechange();
          }
        }
      }
    };

    window.RTCPeerConnection.prototype.createOffer = function() {
      var self = this;
      var offerOptions;
      if (arguments.length === 1 && typeof arguments[0] !== 'function') {
        offerOptions = arguments[0];
      } else if (arguments.length === 3) {
        offerOptions = arguments[2];
      }

      var mlines = [];
      var numAudioTracks = 0;
      var numVideoTracks = 0;
      // Default to sendrecv.
      if (this.localStreams.length) {
        numAudioTracks = this.localStreams[0].getAudioTracks().length;
        numVideoTracks = this.localStreams[0].getAudioTracks().length;
      }
      // Determine number of audio and video tracks we need to send/recv.
      if (offerOptions) {
        // Deal with Chrome legacy constraints...
        if (offerOptions.mandatory) {
          if (offerOptions.mandatory.OfferToReceiveAudio) {
            numAudioTracks = 1;
          } else if (offerOptions.mandatory.OfferToReceiveAudio === false) {
            numAudioTracks = 0;
          }
          if (offerOptions.mandatory.OfferToReceiveVideo) {
            numVideoTracks = 1;
          } else if (offerOptions.mandatory.OfferToReceiveVideo === false) {
            numVideoTracks = 0;
          }
        } else {
          if (offerOptions.offerToReceiveAudio !== undefined) {
            numAudioTracks = offerOptions.offerToReceiveAudio;
          }
          if (offerOptions.offerToReceiveVideo !== undefined) {
            numVideoTracks = offerOptions.offerToReceiveVideo;
          }
        }
      }
      if (this.localStreams.length) {
        // Push local streams.
        this.localStreams[0].getTracks().forEach(function(track) {
          mlines.push({
            kind: track.kind,
            track: track,
            wantReceive: track.kind === 'audio' ?
                numAudioTracks > 0 : numVideoTracks > 0
          });
          if (track.kind === 'audio') {
            numAudioTracks--;
          } else if (track.kind === 'video') {
            numVideoTracks--;
          }
        });
      }
      // Create M-lines for recvonly streams.
      while (numAudioTracks > 0 || numVideoTracks > 0) {
        if (numAudioTracks > 0) {
          mlines.push({
            kind: 'audio',
            wantReceive: true
          });
          numAudioTracks--;
        }
        if (numVideoTracks > 0) {
          mlines.push({
            kind: 'video',
            wantReceive: true
          });
          numVideoTracks--;
        }
      }

      var sdp = 'v=0\r\n' +
          'o=thisisadapterortc 8169639915646943137 2 IN IP4 127.0.0.1\r\n' +
          's=-\r\n' +
          't=0 0\r\n';
      var tracks = [];
      mlines.forEach(function(mline, sdpMLineIndex) {
        // For each track, create an ice gatherer, ice transport, dtls transport,
        // potentially rtpsender and rtpreceiver.
        var track = mline.track;
        var kind = mline.kind;
        var mid = Math.random().toString(36).substr(2, 10);

        var transports = self._createIceAndDtlsTransports(mid, sdpMLineIndex);

        var localCapabilities = RTCRtpSender.getCapabilities(kind);
        var rtpSender;
        // generate an ssrc now, to be used later in rtpSender.send
        var sendSSRC = (2 * sdpMLineIndex + 1) * 1001; //Math.floor(Math.random()*4294967295);
        var recvSSRC; // don't know yet
        if (track) {
          rtpSender = new RTCRtpSender(track, transports.dtlsTransport);
        }

        var rtpReceiver;
        if (mline.wantReceive) {
          rtpReceiver = new RTCRtpReceiver(transports.dtlsTransport, kind);
        }

        tracks[sdpMLineIndex] = {
          iceGatherer: transports.iceGatherer,
          iceTransport: transports.iceTransport,
          dtlsTransport: transports.dtlsTransport,
          localCapabilities: localCapabilities,
          remoteCapabilities: null,
          rtpSender: rtpSender,
          rtpReceiver: rtpReceiver,
          kind: kind,
          mid: mid,
          sendSSRC: sendSSRC,
          recvSSRC: recvSSRC,
          remoteCandidates: []
        };

        // Map things to SDP.
        // Build the mline.
        sdp += 'm=' + kind + ' 9 UDP/TLS/RTP/SAVPF ';
        sdp += localCapabilities.codecs.map(function(codec) {
          return codec.preferredPayloadType;
        }).join(' ') + '\r\n';

        sdp += 'c=IN IP4 0.0.0.0\r\n';
        sdp += 'a=rtcp:9 IN IP4 0.0.0.0\r\n';

        // Map ICE parameters (ufrag, pwd) to SDP.
        sdp += self._iceParametersToSDP(
            transports.iceGatherer.getLocalParameters());

        // Map DTLS parameters to SDP.
        sdp += self._dtlsParametersToSDP(
            transports.dtlsTransport.getLocalParameters(), 'actpass');

        sdp += 'a=mid:' + mid + '\r\n';

        if (rtpSender && rtpReceiver) {
          sdp += 'a=sendrecv\r\n';
        } else if (rtpSender) {
          sdp += 'a=sendonly\r\n';
        } else if (rtpReceiver) {
          sdp += 'a=recvonly\r\n';
        } else {
          sdp += 'a=inactive\r\n';
        }
        sdp += 'a=rtcp-mux\r\n';

        // Add a=rtpmap lines for each codec. Also fmtp and rtcp-fb.
        sdp += self._capabilitiesToSDP(localCapabilities);

        if (track) {
          sdp += 'a=msid:' + self.localStreams[0].id + ' ' + track.id + '\r\n';
          sdp += 'a=ssrc:' + sendSSRC + ' ' + 'msid:' +
              self.localStreams[0].id + ' ' + track.id + '\r\n';
        }
        sdp += 'a=ssrc:' + sendSSRC + ' cname:' + self._cname + '\r\n';
      });

      var desc = new RTCSessionDescription({
        type: 'offer',
        sdp: sdp,
        ortc: tracks
      });
      if (arguments.length && typeof arguments[0] === 'function') {
        window.setTimeout(arguments[0], 0, desc);
      }
      return new Promise(function(resolve) {
        resolve(desc);
      });
    };

    window.RTCPeerConnection.prototype.createAnswer = function() {
      var self = this;
      var answerOptions;
      if (arguments.length === 1 && typeof arguments[0] !== 'function') {
        answerOptions = arguments[0];
      } else if (arguments.length === 3) {
        answerOptions = arguments[2];
      }

      var sdp = 'v=0\r\n' +
          'o=thisisadapterortc 8169639915646943137 2 IN IP4 127.0.0.1\r\n' +
          's=-\r\n' +
          't=0 0\r\n';
      this.tracks.forEach(function(track/*, sdpMLineIndex*/) {
        var iceGatherer = track.iceGatherer;
        //var iceTransport = track.iceTransport;
        var dtlsTransport = track.dtlsTransport;
        var localCapabilities = track.localCapabilities;
        var remoteCapabilities = track.remoteCapabilities;
        var rtpSender = track.rtpSender;
        var rtpReceiver = track.rtpReceiver;
        var kind = track.kind;
        var sendSSRC = track.sendSSRC;
        //var recvSSRC = track.recvSSRC;

        // Calculate intersection of capabilities.
        var commonCapabilities = self._getCommonCapabilities(localCapabilities,
            remoteCapabilities);

        // Map things to SDP.
        // Build the mline.
        sdp += 'm=' + kind + ' 9 UDP/TLS/RTP/SAVPF ';
        sdp += commonCapabilities.codecs.map(function(codec) {
          return codec.payloadType;
        }).join(' ') + '\r\n';

        sdp += 'c=IN IP4 0.0.0.0\r\n';
        sdp += 'a=rtcp:9 IN IP4 0.0.0.0\r\n';

        // Map ICE parameters (ufrag, pwd) to SDP.
        sdp += self._iceParametersToSDP(iceGatherer.getLocalParameters());

        // Map DTLS parameters to SDP.
        sdp += self._dtlsParametersToSDP(dtlsTransport.getLocalParameters(),
            'active');

        sdp += 'a=mid:' + track.mid + '\r\n';

        if (rtpSender && rtpReceiver) {
          sdp += 'a=sendrecv\r\n';
        } else if (rtpReceiver) {
          sdp += 'a=sendonly\r\n';
        } else if (rtpSender) {
          sdp += 'a=recvonly\r\n';
        } else {
          sdp += 'a=inactive\r\n';
        }
        sdp += 'a=rtcp-mux\r\n';

        // Add a=rtpmap lines for each codec. Also fmtp and rtcp-fb.
        sdp += self._capabilitiesToSDP(commonCapabilities);

        if (rtpSender) {
          // add a=ssrc lines from RTPSender
          sdp += 'a=msid:' + self.localStreams[0].id + ' ' +
              rtpSender.track.id + '\r\n';
          sdp += 'a=ssrc:' + sendSSRC + ' ' + 'msid:' +
              self.localStreams[0].id + ' ' + rtpSender.track.id + '\r\n';
        }
        sdp += 'a=ssrc:' + sendSSRC + ' cname:' + self._cname + '\r\n';
      });

      var desc = new RTCSessionDescription({
        type: 'answer',
        sdp: sdp
        // ortc: tracks -- state is created in SRD already
      });
      if (arguments.length && typeof arguments[0] === 'function') {
        window.setTimeout(arguments[0], 0, desc);
      }
      return new Promise(function(resolve) {
        resolve(desc);
      });
    };

    window.RTCPeerConnection.prototype.addIceCandidate = function(candidate) {
      var track = this.tracks[candidate.sdpMLineIndex];
      console.log("addIceCandidate:", candidate);
      if (track) {
        console.log("track:", track);
        var cand = Object.keys(candidate.candidate).length > 0 ?
            this._toCandidateJSON(candidate.candidate) : {};
        // dirty hack to make simplewebrtc work.
        // FIXME: need another dirty hack to avoid adding candidates after this
        if (cand.type === 'endOfCandidates') {
          cand = {};
        }
        // dirty hack to make chrome work.
        if (cand.protocol === 'tcp' && cand.port === 0) {
          cand = {};
          window.setTimeout(function() {
            track.iceTransport.addRemoteCandidate(cand);
          }, 5000);
          return;
        }
        track.iceTransport.addRemoteCandidate(cand);
      }
      if (arguments.length > 1 && typeof arguments[1] === 'function') {
        window.setTimeout(arguments[1], 0);
      }
      return new Promise(function(resolve) {
        resolve();
      });
    };

    /*
    window.RTCPeerConnection.prototype.getStats = function(callback, errback) {
    };
    */
  }
} else {
  console.log('Browser does not appear to be WebRTC-capable');
}

// Returns the result of getUserMedia as a Promise.
function requestUserMedia(constraints) {
  return new Promise(function(resolve, reject) {
    var onSuccess = function(stream) {
      resolve(stream);
    };
    var onError = function(error) {
      reject(error);
    };

    try {
      getUserMedia(constraints, onSuccess, onError);
    } catch (e) {
      reject(e);
    }
  });
}

