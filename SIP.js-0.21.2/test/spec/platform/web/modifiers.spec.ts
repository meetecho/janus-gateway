/* eslint-disable max-len */
import * as Modifiers from "../../../../lib/platform/web/modifiers/index.js";

// TODO:
// These old tests were ported from JavaScript to TypesSript verbatim.
// The next time the Modifiers gets a work over, these should be reviewed.

const offer: RTCSdpType = "offer";

const SessionDescription = {
  withTcpCandidatesAndTelephoneEvents: {
    type: offer,
    sdp:
      "\r\n" +
      "v=0\r\n" +
      "o=- 5677966312555193038 2 IN IP4 127.0.0.1\r\n" +
      "s=-\r\n" +
      "t=0 0\r\n" +
      "a=group:BUNDLE audio\r\n" +
      "a=msid-semantic: WMS iAR3IFaSOkZ5FIEfztgAwWF9xUvbq02PCVKC\r\n" +
      "m=audio 53026 RTP/SAVPF 111 103 104 0 8 106 105 13 126\r\n" +
      "c=IN IP4 199.7.173.162\r\n" +
      "a=rtcp:53027 IN IP4 199.7.173.162\r\n" +
      "a=candidate:2608808550 1 udp 2113937151 192.168.1.33 53974 typ host generation 0\r\n" +
      "a=candidate:2608808550 2 tcp 2113937151 192.168.1.33 53974 typ host generation 0\r\n" +
      "a=candidate:478089246 1 udp 1685987071 127.0.0.1 58170 typ srflx raddr 127.0.0.1 rport 58170 generation 0 network-id 1\r\n" +
      "a=candidate:1099745028 1 udp 25042687 127.0.0.1 56353 typ relay raddr 127.0.0.1 rport 50998 generation 0 network-id 1\r\n" +
      "a=ice-ufrag:yTSZ59T6XRf4f7+q\r\n" +
      "a=ice-pwd:Qzco0YfB/GOFF9n3y1GAJyLK\r\n" +
      "a=ice-options:google-ice\r\n" +
      "a=fingerprint:sha-256 C8:36:3F:5B:EC:DD:D7:DB:BD:08:4A:18:68:B2:2A:57:19:29:C6:DF:00:52:3D:5D:33:A8:D6:50:48:22:B2:7F\r\n" +
      "a=setup:actpass\r\n" +
      "a=mid:audio\r\n" +
      "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n" +
      "a=sendrecv\r\n" +
      "a=rtcp-mux\r\n" +
      "a=crypto:0 AES_CM_128_HMAC_SHA1_32 inline:E0WyVK7CYWDzeiO6TFpPP6gJSC/XndKHRb8ciA9y\r\n" +
      "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:e71T3NtgK8PtmYvtNrbgi2fJL6e9xKhPPsXK7G3E\r\n" +
      "a=rtpmap:111 opus/48000/2\r\n" +
      "a=fmtp:111 minptime=10\r\n" +
      "a=rtpmap:103 ISAC/16000\r\n" +
      "a=rtpmap:104 ISAC/32000\r\n" +
      "a=rtpmap:0 PCMU/8000\r\n" +
      "a=rtpmap:8 PCMA/8000\r\n" +
      "a=rtpmap:106 CN/32000\r\n" +
      "a=rtpmap:105 CN/16000\r\n" +
      "a=rtpmap:13 CN/8000\r\n" +
      "a=rtpmap:126 telephone-event/8000\r\n" +
      "a=maxptime:60\r\n" +
      "a=ssrc:3254389050 cname:7x2CRZjJC+fBSDDl\r\n" +
      "a=ssrc:3254389050 msid:iAR3IFaSOkZ5FIEfztgAwWF9xUvbq02PCVKC aa5e18ed-eb5f-4475-8383-6d6b5abae41d\r\n" +
      "a=ssrc:3254389050 mslabel:iAR3IFaSOkZ5FIEfztgAwWF9xUvbq02PCVKC\r\n" +
      "a=ssrc:3254389050 label:aa5e18ed-eb5f-4475-8383-6d6b5abae41d\r\n" +
      "\r\n"
  }
};

describe("Web Modifiers", () => {
  let sdpWrapper: RTCSessionDescriptionInit;

  beforeEach(() => {
    sdpWrapper = SessionDescription.withTcpCandidatesAndTelephoneEvents;
  });

  it("should strip tcp candidates from sdp", (done) => {
    Modifiers.stripTcpCandidates(sdpWrapper).then((description) => {
      expect(description.type).toBe("offer");
      expect(description.sdp).toContain(
        "a=candidate:2608808550 1 udp 2113937151 192.168.1.33 53974 typ host generation 0"
      );
      expect(description.sdp).not.toContain(
        "a=candidate:2608808550 2 tcp 2113937151 192.168.1.33 53974 typ host generation 0"
      );
      expect(description.sdp).toContain(
        "a=candidate:478089246 1 udp 1685987071 127.0.0.1 58170 typ srflx raddr 127.0.0.1 rport 58170 generation 0 network-id 1"
      );
      expect(description.sdp).toContain(
        "a=candidate:1099745028 1 udp 25042687 127.0.0.1 56353 typ relay raddr 127.0.0.1 rport 50998 generation 0 network-id 1"
      );

      done();
    });
  });

  it("should strip telephone events from sdp", (done) => {
    Modifiers.stripTelephoneEvent(sdpWrapper).then((description) => {
      expect(description.type).toBe("offer");
      expect(description.sdp).not.toContain("a=rtpmap:126 telephone-event/8000");
      expect(description.sdp).toContain("m=audio 53026 RTP/SAVPF 111 103 104 0 8 106 105 13\r\n");

      done();
    });
  });
});
