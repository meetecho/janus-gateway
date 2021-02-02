#include "sdp-utils.h"

#include "debug.h"

/* Configure debug+logging */

int janus_log_level = LOG_VERB;
int refcount_debug = 0;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = TRUE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;


static const char *chrome88_offer=
"v=0\r\n"
"o=- 5542689891050562722 2 IN IP4 1.1.1.1\r\n"
"s=-\r\n"
"t=0 0\r\n"
"m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126\r\n"
"c=IN IP4 1.1.1.1\r\n"
"a=sendonly\r\n"
"a=rtpmap:111 opus/48000/2\r\n"
"a=rtpmap:103 ISAC/16000\r\n"
"a=rtpmap:104 ISAC/32000\r\n"
"a=rtpmap:9 G722/8000\r\n"
"a=rtpmap:0 PCMU/8000\r\n"
"a=rtpmap:8 PCMA/8000\r\n"
"a=rtpmap:106 CN/32000\r\n"
"a=rtpmap:105 CN/16000\r\n"
"a=rtpmap:13 CN/8000\r\n"
"a=rtpmap:110 telephone-event/48000\r\n"
"a=rtpmap:112 telephone-event/32000\r\n"
"a=rtpmap:113 telephone-event/16000\r\n"
"a=rtpmap:126 telephone-event/8000\r\n"
"a=fmtp:111 minptime=10;useinbandfec=1;maxaveragebitrate=65536; stereo=1; sprop-stereo=1\r\n"
"a=rtcp-fb:111 transport-cc\r\n"
"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
"a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
"a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n"
"m=video 9 UDP/TLS/RTP/SAVPF 96 98 100 102 127 125 108\r\n"
"c=IN IP4 1.1.1.1\r\n"
"b=AS:4000\r\n"
"a=sendonly\r\n"
"a=rtpmap:96 VP8/90000\r\n"
"a=rtpmap:98 VP9/90000\r\n"
"a=rtpmap:100 VP9/90000\r\n"
"a=rtpmap:102 H264/90000\r\n"
"a=rtpmap:127 H264/90000\r\n"
"a=rtpmap:125 H264/90000\r\n"
"a=rtpmap:108 H264/90000\r\n"
"a=fmtp:98 profile-id=0\r\n"
"a=fmtp:100 profile-id=2\r\n"
"a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n"
"a=fmtp:127 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\n"
"a=fmtp:125 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
"a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f\r\n"
"a=rtcp-fb:96 goog-remb\r\n"
"a=rtcp-fb:96 transport-cc\r\n"
"a=rtcp-fb:96 ccm fir\r\n"
"a=rtcp-fb:96 nack\r\n"
"a=rtcp-fb:96 nack pli\r\n"
"a=rtcp-fb:98 goog-remb\r\n"
"a=rtcp-fb:98 transport-cc\r\n"
"a=rtcp-fb:98 ccm fir\r\n"
"a=rtcp-fb:98 nack\r\n"
"a=rtcp-fb:98 nack pli\r\n"
"a=rtcp-fb:100 goog-remb\r\n"
"a=rtcp-fb:100 transport-cc\r\n"
"a=rtcp-fb:100 ccm fir\r\n"
"a=rtcp-fb:100 nack\r\n"
"a=rtcp-fb:100 nack pli\r\n"
"a=rtcp-fb:102 goog-remb\r\n"
"a=rtcp-fb:102 transport-cc\r\n"
"a=rtcp-fb:102 ccm fir\r\n"
"a=rtcp-fb:102 nack\r\n"
"a=rtcp-fb:102 nack pli\r\n"
"a=rtcp-fb:127 goog-remb\r\n"
"a=rtcp-fb:127 transport-cc\r\n"
"a=rtcp-fb:127 ccm fir\r\n"
"a=rtcp-fb:127 nack\r\n"
"a=rtcp-fb:127 nack pli\r\n"
"a=rtcp-fb:125 goog-remb\r\n"
"a=rtcp-fb:125 transport-cc\n"
"a=rtcp-fb:125 ccm fir\r\n"
"a=rtcp-fb:125 nack\r\n"
"a=rtcp-fb:125 nack pli\r\n"
"a=rtcp-fb:108 goog-remb\r\n"
"a=rtcp-fb:108 transport-cc\r\n"
"a=rtcp-fb:108 ccm fir\r\n"
"a=rtcp-fb:108 nack\r\n"
"a=rtcp-fb:108 nack pli\r\n"
"a=extmap:14 urn:ietf:params:rtp-hdrext:toffset\r\n"
"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
"a=extmap:13 urn:3gpp:video-orientation\r\n"
"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
"a=extmap:12 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n"
"a=extmap:11 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type\r\n"
"a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing\r\n"
"a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space\r\n"
"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
"a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
"a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n";



static const char *chrome90_offer=
"v=0\r\n"
"o=- 896940099054408028 2 IN IP4 1.1.1.1\r\n"
"s=-\r\n"
"t=0 0\r\n"
"m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126\r\n"
"c=IN IP4 1.1.1.1\r\n"
"a=sendonly\r\n"
"a=rtpmap:111 opus/48000/2\r\n"
"a=rtpmap:103 ISAC/16000\r\n"
"a=rtpmap:104 ISAC/32000\r\n"
"a=rtpmap:9 G722/8000\r\n"
"a=rtpmap:0 PCMU/8000\r\n"
"a=rtpmap:8 PCMA/8000\r\n"
"a=rtpmap:106 CN/32000\r\n"
"a=rtpmap:105 CN/16000\r\n"
"a=rtpmap:13 CN/8000\r\n"
"a=rtpmap:110 telephone-event/48000\r\n"
"a=rtpmap:112 telephone-event/32000\r\n"
"a=rtpmap:113 telephone-event/16000\r\n"
"a=rtpmap:126 telephone-event/8000\r\n"
"a=fmtp:111 minptime=10;useinbandfec=1;maxaveragebitrate=65536; stereo=1; sprop-stereo=1\r\n"
"a=rtcp-fb:111 transport-cc\r\n"
"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
"a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
"a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n"
"m=video 9 UDP/TLS/RTP/SAVPF 96 98 100 102 127 125 108 35\r\n"
"c=IN IP4 1.1.1.1\r\n"
"b=AS:4000\r\n"
"a=sendonly\r\n"
"a=rtpmap:96 VP8/90000\r\n"
"a=rtpmap:98 VP9/90000\r\n"
"a=rtpmap:100 VP9/90000\r\n"
"a=rtpmap:102 H264/90000\r\n"
"a=rtpmap:127 H264/90000\r\n"
"a=rtpmap:125 H264/90000\r\n"
"a=rtpmap:108 H264/90000\r\n"
"a=rtpmap:35 AV1X/90000\r\n"
"a=fmtp:98 profile-id=0\r\n"
"a=fmtp:100 profile-id=2\r\n"
"a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n"
"a=fmtp:127 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\n"
"a=fmtp:125 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
"a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f\r\n"
"a=rtcp-fb:96 goog-remb\r\n"
"a=rtcp-fb:96 transport-cc\r\n"
"a=rtcp-fb:96 ccm fir\r\n"
"a=rtcp-fb:96 nack\r\n"
"a=rtcp-fb:96 nack pli\r\n"
"a=rtcp-fb:98 goog-remb\r\n"
"a=rtcp-fb:98 transport-cc\r\n"
"a=rtcp-fb:98 ccm fir\r\n"
"a=rtcp-fb:98 nack\r\n"
"a=rtcp-fb:98 nack pli\r\n"
"a=rtcp-fb:100 goog-remb\r\n"
"a=rtcp-fb:100 transport-cc\r\n"
"a=rtcp-fb:100 ccm fir\r\n"
"a=rtcp-fb:100 nack\r\n"
"a=rtcp-fb:100 nack pli\r\n"
"a=rtcp-fb:102 goog-remb\r\n"
"a=rtcp-fb:102 transport-cc\r\n"
"a=rtcp-fb:102 ccm fir\r\n"
"a=rtcp-fb:102 nack\r\n"
"a=rtcp-fb:102 nack pli\r\n"
"a=rtcp-fb:127 goog-remb\r\n"
"a=rtcp-fb:127 transport-cc\r\n"
"a=rtcp-fb:127 ccm fir\r\n"
"a=rtcp-fb:127 nack\r\n"
"a=rtcp-fb:127 nack pli\r\n"
"a=rtcp-fb:125 goog-remb\r\n"
"a=rtcp-fb:125 transport-cc\r\n"
"a=rtcp-fb:125 ccm fir\r\n"
"a=rtcp-fb:125 nack\r\n"
"a=rtcp-fb:125 nack pli\r\n"
"a=rtcp-fb:108 goog-remb\r\n"
"a=rtcp-fb:108 transport-cc\r\n"
"a=rtcp-fb:108 ccm fir\r\n"
"a=rtcp-fb:108 nack\r\n"
"a=rtcp-fb:108 nack pli\r\n"
"a=rtcp-fb:35 goog-remb\r\n"
"a=rtcp-fb:35 transport-cc\r\n"
"a=rtcp-fb:35 ccm fir\r\n"
"a=rtcp-fb:35 nack\r\n"
"a=rtcp-fb:35 nack pli\r\n"
"a=extmap:14 urn:ietf:params:rtp-hdrext:toffset\r\n"
"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
"a=extmap:13 urn:3gpp:video-orientation\r\n"
"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
"a=extmap:12 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n"
"a=extmap:11 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type\r\n"
"a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing\r\n"
"a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space\r\n"
"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
"a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
"a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n";

static void sdp_test(const char *sdp_text, const char *codec, const char *profile) 
{
	char err_buf[512];
	janus_sdp *offer = janus_sdp_parse(sdp_text, err_buf, sizeof(err_buf));
	if (!offer) {
		JANUS_LOG(LOG_ERR, "Error parsing SDP? %s\n", err_buf);
		exit(1);
	}

	int pt = janus_sdp_get_codec_pt_full(offer, codec, profile);

	JANUS_LOG(LOG_WARN, "Got pt %d for %s %s\n\n", pt, codec, profile);

	janus_sdp_destroy(offer);
}

int main(int argc, char *argv[])
{
	if(janus_log_init(0, 1, NULL) < 0)
		exit(1);

	/* Expecting 125, getting 108 */
	sdp_test(chrome88_offer, "h264", "42e01f");

	/* Expecting 125, getting -1 */
	sdp_test(chrome90_offer, "h264", "42e01f");

	/* Expecting 98, getting -1 */
	sdp_test(chrome88_offer, "vp9", "0");

	/* Expecting 98, getting -1 */
	sdp_test(chrome90_offer, "vp9", "0");

	/* Expecting 100, getting -1 */
	sdp_test(chrome88_offer, "vp9", "2");

	/* Expecting 100, getting -1 */
	sdp_test(chrome90_offer, "vp9", "2");

	g_clear_pointer(&janus_log_global_prefix, g_free);

	janus_log_destroy();

	return 0;
}
