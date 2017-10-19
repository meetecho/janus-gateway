/*! \file    sdp.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SDP processing
 * \details  Implementation of an SDP
 * parser/merger/generator in the gateway. Each SDP coming from peers is
 * stripped/anonymized before it is passed to the plugins: all
 * DTLS/ICE/transport related information is removed, only leaving the
 * relevant information in place. SDP coming from plugins is stripped/anonymized
 * as well, and merged with the proper DTLS/ICE/transport information before
 * it is sent to the peers. The actual SDP processing (parsing SDP strings,
 * representation of SDP as an internal format, and so on) is done via
 * the tools provided in sdp-utils.h.
 *
 * \ingroup protocols
 * \ref protocols
 */

#include "janus.h"
#include "ice.h"
#include "dtls.h"
#include "sdp.h"
#include "utils.h"
#include "debug.h"
#include "events.h"


/* Pre-parse SDP: is this SDP valid? how many audio/video lines? any features to take into account? */
janus_sdp *janus_sdp_preparse(const char *jsep_sdp, char *error_str, size_t errlen,
		int *audio, int *video, int *data, int *bundle, int *rtcpmux, int *trickle) {
	if(!jsep_sdp || !audio || !video || !data || !bundle || !rtcpmux || !trickle) {
		JANUS_LOG(LOG_ERR, "  Can't preparse, invalid arguments\n");
		return NULL;
	}
	janus_sdp *parsed_sdp = janus_sdp_parse(jsep_sdp, error_str, errlen);
	if(!parsed_sdp) {
		JANUS_LOG(LOG_ERR, "  Error parsing SDP? %s\n", error_str ? error_str : "(unknown reason)");
		/* Invalid SDP */
		return NULL;
	}
	/* Look for m-lines */
	GList *temp = parsed_sdp->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		if(m->type == JANUS_SDP_AUDIO && m->port > 0) {
			*audio = *audio + 1;
		} else if(m->type == JANUS_SDP_VIDEO && m->port > 0) {
			*video = *video + 1;
		}
		temp = temp->next;
	}
#ifdef HAVE_SCTP
	*data = (strstr(jsep_sdp, "DTLS/SCTP") && !strstr(jsep_sdp, " 0 DTLS/SCTP")) ? 1 : 0;	/* FIXME This is a really hacky way of checking... */
#else
	*data = 0;
#endif
	*bundle = strstr(jsep_sdp, "a=group:BUNDLE") ? 1 : 0;	/* FIXME This is a really hacky way of checking... */
	*rtcpmux = strstr(jsep_sdp, "a=rtcp-mux") ? 1 : 0;	/* FIXME Should we make this check per-medium? */
	//~ *trickle = (strstr(jsep_sdp, "trickle") || strstr(jsep_sdp, "google-ice") || strstr(jsep_sdp, "Mozilla")) ? 1 : 0;	/* FIXME This is a really hacky way of checking... */
	/* FIXME We're assuming trickle is always supported, see https://github.com/meetecho/janus-gateway/issues/83 */
	*trickle = 1;

	return parsed_sdp;
}

/* Parse SDP */
int janus_sdp_process(void *ice_handle, janus_sdp *remote_sdp) {
	if(!ice_handle || !remote_sdp)
		return -1;
	janus_ice_handle *handle = (janus_ice_handle *)ice_handle;
	janus_ice_stream *stream = NULL;
	gchar *ruser = NULL, *rpass = NULL, *rhashing = NULL, *rfingerprint = NULL;
	int audio = 0, video = 0;
#ifdef HAVE_SCTP
	int data = 0;
#endif
	/* Ok, let's start with global attributes */
	GList *temp = remote_sdp->attributes;
	while(temp) {
		janus_sdp_attribute *a = (janus_sdp_attribute *)temp->data;
		if(a && a->name) {
			if(!strcasecmp(a->name, "fingerprint")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Fingerprint (global) : %s\n", handle->handle_id, a->value);
				if(strcasestr(a->value, "sha-256 ") == a->value) {
					rhashing = g_strdup("sha-256");
					rfingerprint = g_strdup(a->value + strlen("sha-256 "));
				} else if(strcasestr(a->value, "sha-1 ") == a->value) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-1 instead of sha-256), but that's ok\n", handle->handle_id);
					rhashing = g_strdup("sha-1");
					rfingerprint = g_strdup(a->value + strlen("sha-1 "));
				} else {
					/* FIXME We should handle this somehow anyway... OpenSSL supports them all */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-256/sha-1), *NOT* cool\n", handle->handle_id);
				}
			} else if(!strcasecmp(a->name, "ice-ufrag")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE ufrag (global):   %s\n", handle->handle_id, a->value);
				ruser = g_strdup(a->value);
			} else if(!strcasecmp(a->name, "ice-pwd")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE pwd (global):     %s\n", handle->handle_id, a->value);
				rpass = g_strdup(a->value);
			}
		}
		temp = temp->next;
	}
	/* Now go on with m-line and their attributes */
	temp = remote_sdp->m_lines;
	gboolean bundled = FALSE;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		bundled = FALSE;
		if(m->type == JANUS_SDP_AUDIO) {
			if(handle->rtp_profile == NULL && m->proto != NULL)
				handle->rtp_profile = g_strdup(m->proto);
			if(m->port > 0) {
				audio++;
				if(audio > 1) {
					temp = temp->next;
					continue;
				}
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsing audio candidates (stream=%d)...\n", handle->handle_id, handle->audio_id);
				stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->audio_id));
			} else {
				/* Audio rejected? */
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio rejected by peer...\n", handle->handle_id);
			}
		} else if(m->type == JANUS_SDP_VIDEO) {
			if(handle->rtp_profile == NULL && m->proto != NULL)
				handle->rtp_profile = g_strdup(m->proto);
			if(m->port > 0) {
				video++;
				if(video > 1) {
					temp = temp->next;
					continue;
				}
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsing video candidates (stream=%d)...\n", handle->handle_id, handle->video_id);
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
					stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->video_id));
				} else {
					guint id = handle->audio_id > 0 ? handle->audio_id : handle->video_id;
					stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
					bundled = id == handle->audio_id;
				}
			} else {
				/* Video rejected? */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video rejected by peer...\n", handle->handle_id);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
			}
#ifdef HAVE_SCTP
		} else if(m->type == JANUS_SDP_APPLICATION) {
			/* Is this SCTP for DataChannels? */
			if(!strcasecmp(m->proto, "DTLS/SCTP")) {
				if(m->port > 0) {
					/* Yep */
					data++;
					if(data > 1) {
						temp = temp->next;
						continue;
					}
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsing SCTP candidates (stream=%d)...\n", handle->handle_id, handle->video_id);
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
						stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->data_id));
					} else {
						guint id = handle->audio_id > 0 ? handle->audio_id : (handle->video_id > 0 ? handle->video_id : handle->data_id);
						stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
						bundled = (id == handle->audio_id || id == handle->video_id);
					}
					if(stream == NULL) {
						JANUS_LOG(LOG_WARN, "No valid stream for data??\n");
						temp = temp->next;
						continue;
					}
				}
			} else {
				/* Data channels rejected? */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Data channels rejected by peer...\n", handle->handle_id);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
			}
#endif
		} else {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping disabled/unsupported media line...\n", handle->handle_id);
		}
		if(stream == NULL) {
			temp = temp->next;
			continue;
		}
		/* Look for mid, ICE credentials and fingerprint first: check media attributes */
		GList *tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->name) {
				if(!strcasecmp(a->name, "mid")) {
					/* Found mid attribute */
					if(m->type == JANUS_SDP_AUDIO && m->port > 0) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio mid: %s\n", handle->handle_id, a->value);
						handle->audio_mid = g_strdup(a->value);
					} else if(m->type == JANUS_SDP_VIDEO && m->port > 0) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video mid: %s\n", handle->handle_id, a->value);
						handle->video_mid = g_strdup(a->value);
#ifdef HAVE_SCTP
					} else if(m->type == JANUS_SDP_APPLICATION) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Data Channel mid: %s\n", handle->handle_id, a->value);
						handle->data_mid = g_strdup(a->value);
#endif
					}
				} else if(!strcasecmp(a->name, "fingerprint")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Fingerprint (local) : %s\n", handle->handle_id, a->value);
					if(strcasestr(a->value, "sha-256 ") == a->value) {
						if(rhashing)
							g_free(rhashing);	/* FIXME We're overwriting the global one, if any */
						rhashing = g_strdup("sha-256");
						if(rfingerprint)
							g_free(rfingerprint);	/* FIXME We're overwriting the global one, if any */
						rfingerprint = g_strdup(a->value + strlen("sha-256 "));
					} else if(strcasestr(a->value, "sha-1 ") == a->value) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-1 instead of sha-256), but that's ok\n", handle->handle_id);
						if(rhashing)
							g_free(rhashing);	/* FIXME We're overwriting the global one, if any */
						rhashing = g_strdup("sha-1");
						if(rfingerprint)
							g_free(rfingerprint);	/* FIXME We're overwriting the global one, if any */
						rfingerprint = g_strdup(a->value + strlen("sha-1 "));
					} else {
						/* FIXME We should handle this somehow anyway... OpenSSL supports them all */
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-256), *NOT* cool\n", handle->handle_id);
					}
				} else if(!strcasecmp(a->name, "setup")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] DTLS setup (local):  %s\n", handle->handle_id, a->value);
					if(!strcasecmp(a->value, "actpass") || !strcasecmp(a->value, "passive"))
						stream->dtls_role = JANUS_DTLS_ROLE_CLIENT;
					else if(!strcasecmp(a->value, "active"))
						stream->dtls_role = JANUS_DTLS_ROLE_SERVER;
					/* TODO Handle holdconn... */
				} else if(!strcasecmp(a->name, "ice-ufrag")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE ufrag (local):   %s\n", handle->handle_id, a->value);
					if(ruser)
						g_free(ruser);	/* FIXME We're overwriting the global one, if any */
					ruser = g_strdup(a->value);
				} else if(!strcasecmp(a->name, "ice-pwd")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE pwd (local):     %s\n", handle->handle_id, a->value);
					if(rpass)
						g_free(rpass);	/* FIXME We're overwriting the global one, if any */
					rpass = g_strdup(a->value);
				}
			}
			tempA = tempA->next;
		}
		if(!ruser || !rpass || !rfingerprint || !rhashing) {
			/* Missing mandatory information, failure... */
			if(ruser)
				g_free(ruser);
			ruser = NULL;
			if(rpass)
				g_free(rpass);
			rpass = NULL;
			if(rhashing)
				g_free(rhashing);
			rhashing = NULL;
			if(rfingerprint)
				g_free(rfingerprint);
			rfingerprint = NULL;
			return -2;
		}
		/* Make sure we don't overwrite previously parsed fingerprints and ICE credentials if we're bundling */
		if(!bundled) {
			/* Store fingerprint and hashing */
			if(stream->remote_hashing != NULL)
				g_free(stream->remote_hashing);
			stream->remote_hashing = g_strdup(rhashing);
			if(stream->remote_fingerprint != NULL)
				g_free(stream->remote_fingerprint);
			stream->remote_fingerprint = g_strdup(rfingerprint);
			/* Store the ICE username and password for this stream */
			if(stream->ruser != NULL)
				g_free(stream->ruser);
			stream->ruser = g_strdup(ruser);
			if(stream->rpass != NULL)
				g_free(stream->rpass);
			stream->rpass = g_strdup(rpass);
		}
		/* Now look for candidates and other info */
		tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->name) {
				if(!strcasecmp(a->name, "candidate")) {
					if(m->type == JANUS_SDP_VIDEO && handle->audio_id > 0 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] This is a video candidate but we're bundling, ignoring...\n", handle->handle_id);
#ifdef HAVE_SCTP
					} else if(m->type == JANUS_SDP_APPLICATION && (handle->audio_id > 0 || handle->video_id > 0) && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] This is a SCTP candidate but we're bundling, ignoring...\n", handle->handle_id);
#endif
					} else {
						int res = janus_sdp_parse_candidate(stream, (const char *)a->value, 0);
						if(res != 0) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse candidate... (%d)\n", handle->handle_id, res);
						}
					}
				} else if(!strcasecmp(a->name, "rid")) {
					/* This attribute is used by Firefox for simulcasting */
					char rid[16];
					if(sscanf(a->value, "%15s send", rid) != 1) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse rid attribute...\n", handle->handle_id);
					} else {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsed rid: %s\n", handle->handle_id, rid);
						if(stream->rid[0] == NULL) {
							stream->rid[0] = g_strdup(rid);
						} else if(stream->rid[1] == NULL) {
							stream->rid[1] = g_strdup(rid);
						} else if(stream->rid[2] == NULL) {
							stream->rid[2] = g_strdup(rid);
						} else {
							JANUS_LOG(LOG_WARN, "[%"SCNu64"] Too many RTP Stream IDs, ignoring '%s'...\n", handle->handle_id, rid);
						}
					}
				} else if(!strcasecmp(a->name, "ssrc-group")) {
					/* FIXME This can be either FID or SIM */
					int res = janus_sdp_parse_ssrc_group(stream, (const char *)a->value, m->type == JANUS_SDP_VIDEO);
					if(res != 0) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse SSRC group attribute... (%d)\n", handle->handle_id, res);
					}
				} else if(!strcasecmp(a->name, "ssrc")) {
					int res = janus_sdp_parse_ssrc(stream, (const char *)a->value, m->type == JANUS_SDP_VIDEO);
					if(res != 0) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse SSRC attribute... (%d)\n", handle->handle_id, res);
					}
				} else if(!strcasecmp(a->name, "rtcp-fb")) {
					if(a->value && strstr(a->value, "nack") && stream->rtp_component) {
						if(m->type == JANUS_SDP_AUDIO) {
							/* Enable NACKs for audio */
							stream->rtp_component->do_audio_nacks = TRUE;
						} else if(m->type == JANUS_SDP_VIDEO) {
							/* Enable NACKs for video */
							stream->rtp_component->do_video_nacks = TRUE;
						}
					}
				}
#ifdef HAVE_SCTP
				else if(!strcasecmp(a->name, "sctpmap")) {
					/* TODO Parse sctpmap line to get the UDP-port value and the number of channels */
					JANUS_LOG(LOG_VERB, "Got a sctpmap attribute: %s\n", a->value);
				}
#endif
			}
			tempA = tempA->next;
		}
		temp = temp->next;
	}
	if(ruser)
		g_free(ruser);
	ruser = NULL;
	if(rpass)
		g_free(rpass);
	rpass = NULL;
	if(rhashing)
		g_free(rhashing);
	rhashing = NULL;
	if(rfingerprint)
		g_free(rfingerprint);
	rfingerprint = NULL;
	return 0;	/* FIXME Handle errors better */
}

int janus_sdp_parse_candidate(void *ice_stream, const char *candidate, int trickle) {
	if(ice_stream == NULL || candidate == NULL)
		return -1;
	janus_ice_stream *stream = (janus_ice_stream *)ice_stream;
	janus_ice_handle *handle = stream->handle;
	if(handle == NULL)
		return -2;
	janus_ice_component *component = NULL;
	if(strstr(candidate, "end-of-candidates")) {
		/* FIXME Should we do something with this? */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] end-of-candidates received\n", handle->handle_id);
		return 0;
	}
	if(strstr(candidate, "candidate:") == candidate) {
		/* Skipping the 'candidate:' prefix Firefox puts in trickle candidates */
		candidate += strlen("candidate:");
	}
	char rfoundation[32], rtransport[4], rip[40], rtype[6], rrelip[40];
	guint32 rcomponent, rpriority, rport, rrelport;
	int res = sscanf(candidate, "%31s %30u %3s %30u %39s %30u typ %5s %*s %39s %*s %30u",
		rfoundation, &rcomponent, rtransport, &rpriority,
			rip, &rport, rtype, rrelip, &rrelport);
	if(res < 7) {
		/* Failed to parse this address, can it be IPv6? */
		if(!janus_ice_is_ipv6_enabled()) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Received IPv6 candidate, but IPv6 support is disabled...\n", handle->handle_id);
			return res;
		}
	}
	if(res >= 7) {
		/* Add remote candidate */
		component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(rcomponent));
		if(component == NULL) {
			if(rcomponent == 2 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Skipping component %d in stream %d (rtcp-muxing)\n", handle->handle_id, rcomponent, stream->stream_id);
			} else {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"]   -- No such component %d in stream %d?\n", handle->handle_id, rcomponent, stream->stream_id);
			}
		} else {
			if(rcomponent == 2 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Skipping component %d in stream %d (rtcp-muxing)\n", handle->handle_id, rcomponent, stream->stream_id);
				return 0;
			}
			//~ if(trickle) {
				//~ if(component->dtls != NULL) {
					//~ /* This component is already ready, ignore this further candidate */
					//~ JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Ignoring this candidate, the component is already ready\n", handle->handle_id);
					//~ return 0;
				//~ }
			//~ }
			component->component_id = rcomponent;
			component->stream_id = stream->stream_id;
			NiceCandidate *c = NULL;
			if(!strcasecmp(rtype, "host")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Adding remote candidate component:%d stream:%d type:host %s:%d\n",
					handle->handle_id, rcomponent, stream->stream_id, rip, rport);
				/* Unless this is libnice >= 0.1.8, we only support UDP... */
				if(!strcasecmp(rtransport, "udp")) {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
#ifdef HAVE_LIBNICE_TCP
				} else if(!strcasecmp(rtransport, "tcp") && janus_ice_is_ice_tcp_enabled()) {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
#endif
				} else {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]    Skipping unsupported transport '%s' for media\n", handle->handle_id, rtransport);
				}
			} else if(!strcasecmp(rtype, "srflx")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Adding remote candidate component:%d stream:%d type:srflx %s:%d --> %s:%d \n",
					handle->handle_id, rcomponent, stream->stream_id,  rrelip, rrelport, rip, rport);
				/* Unless this is libnice >= 0.1.8, we only support UDP... */
				if(!strcasecmp(rtransport, "udp")) {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
#ifdef HAVE_LIBNICE_TCP
				} else if(!strcasecmp(rtransport, "tcp") && janus_ice_is_ice_tcp_enabled()) {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
#endif
				} else {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]    Skipping unsupported transport '%s' for media\n", handle->handle_id, rtransport);
				}
			} else if(!strcasecmp(rtype, "prflx")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Adding remote candidate component:%d stream:%d type:prflx %s:%d --> %s:%d\n",
					handle->handle_id, rcomponent, stream->stream_id, rrelip, rrelport, rip, rport);
				/* Unless this is libnice >= 0.1.8, we only support UDP... */
				if(!strcasecmp(rtransport, "udp")) {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
#ifdef HAVE_LIBNICE_TCP
				} else if(!strcasecmp(rtransport, "tcp") && janus_ice_is_ice_tcp_enabled()) {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
#endif
				} else {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]    Skipping unsupported transport '%s' for media\n", handle->handle_id, rtransport);
				}
			} else if(!strcasecmp(rtype, "relay")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Adding remote candidate component:%d stream:%d type:relay %s:%d --> %s:%d\n",
					handle->handle_id, rcomponent, stream->stream_id, rrelip, rrelport, rip, rport);
				/* We only support UDP/TCP/TLS... */
				if(strcasecmp(rtransport, "udp") && strcasecmp(rtransport, "tcp") && strcasecmp(rtransport, "tls")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]    Skipping unsupported transport '%s' for media\n", handle->handle_id, rtransport);
				} else {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_RELAYED);
				}
			} else {
				/* FIXME What now? */
				JANUS_LOG(LOG_ERR, "[%"SCNu64"]  Unknown remote candidate type:%s for component:%d stream:%d!\n",
					handle->handle_id, rtype, rcomponent, stream->stream_id);
			}
			if(c != NULL) {
				c->component_id = rcomponent;
				c->stream_id = stream->stream_id;
#ifndef HAVE_LIBNICE_TCP
				c->transport = NICE_CANDIDATE_TRANSPORT_UDP;
#else
				if(!strcasecmp(rtransport, "udp")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Transport: UDP\n", handle->handle_id);
					c->transport = NICE_CANDIDATE_TRANSPORT_UDP;
				} else {
					/* Check the type (https://tools.ietf.org/html/rfc6544#section-4.5) */
					const char *type = NULL;
					int ctype = 0;
					if(strstr(candidate, "tcptype active")) {
						type = "active";
						ctype = NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
					} else if(strstr(candidate, "tcptype passive")) {
						type = "passive";
						ctype = NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
					} else if(strstr(candidate, "tcptype so")) {
						type = "so";
						ctype = NICE_CANDIDATE_TRANSPORT_TCP_SO;
					} else {
						/* TODO: We should actually stop here... */
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Missing tcptype info for the TCP candidate!\n", handle->handle_id);
					}
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Transport: TCP (%s)\n", handle->handle_id, type);
					c->transport = ctype;
				}
#endif
				strncpy(c->foundation, rfoundation, NICE_CANDIDATE_MAX_FOUNDATION);
				c->priority = rpriority;
				nice_address_set_from_string(&c->addr, rip);
				nice_address_set_port(&c->addr, rport);
				c->username = g_strdup(stream->ruser);
				c->password = g_strdup(stream->rpass);
				if(c->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE || c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
					nice_address_set_from_string(&c->base_addr, rrelip);
					nice_address_set_port(&c->base_addr, rrelport);
				} else if(c->type == NICE_CANDIDATE_TYPE_RELAYED) {
					/* FIXME Do we really need the base address for TURN? */
					nice_address_set_from_string(&c->base_addr, rrelip);
					nice_address_set_port(&c->base_addr, rrelport);
				}
				component->candidates = g_slist_append(component->candidates, c);
				JANUS_LOG(LOG_HUGE, "[%"SCNu64"]    Candidate added to the list! (%u elements for %d/%d)\n", handle->handle_id,
					g_slist_length(component->candidates), stream->stream_id, component->component_id);
				/* Save for the summary, in case we need it */
				component->remote_candidates = g_slist_append(component->remote_candidates, g_strdup(candidate));
				/* Notify event handlers */
				if(janus_events_is_enabled()) {
					janus_session *session = (janus_session *)handle->session;
					json_t *info = json_object();
					json_object_set_new(info, "remote-candidate", json_string(candidate));
					json_object_set_new(info, "stream_id", json_integer(stream->stream_id));
					json_object_set_new(info, "component_id", json_integer(component->component_id));
					janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, info);
				}
				/* See if we need to process this */
				if(trickle) {
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START)) {
						/* This is a trickle candidate and ICE has started, we should process it right away */
						if(!component->process_started) {
							/* Actually, ICE has JUST started for this component, take care of the candidates we've added so far */
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE already started for this component, setting candidates we have up to now\n", handle->handle_id);
							janus_ice_setup_remote_candidates(handle, component->stream_id, component->component_id);
						} else {
							GSList *candidates = NULL;
							candidates = g_slist_append(candidates, c);
							if(nice_agent_set_remote_candidates(handle->agent, stream->stream_id, component->component_id, candidates) < 1) {
								JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to add trickle candidate :-(\n", handle->handle_id);
							} else {
								JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Trickle candidate added!\n", handle->handle_id);
							}
							g_slist_free(candidates);
						}
					} else {
						/* ICE hasn't started yet: to make sure we're not stuck, also check if we stopped processing the SDP */
						if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER)) {
							janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
							/* This is a trickle candidate and ICE has started, we should process it right away */
							if(!component->process_started) {
								/* Actually, ICE has JUST started for this component, take care of the candidates we've added so far */
								JANUS_LOG(LOG_VERB, "[%"SCNu64"] SDP processed but ICE not started yet for this component, setting candidates we have up to now\n", handle->handle_id);
								janus_ice_setup_remote_candidates(handle, component->stream_id, component->component_id);
							} else {
								GSList *candidates = NULL;
								candidates = g_slist_append(candidates, c);
								if(nice_agent_set_remote_candidates(handle->agent, stream->stream_id, component->component_id, candidates) < 1) {
									JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to add trickle candidate :-(\n", handle->handle_id);
								} else {
									JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Trickle candidate added!\n", handle->handle_id);
								}
								g_slist_free(candidates);
							}
						} else {
							/* Still processing the offer/answer: queue the trickle candidate for now, we'll process it later */
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Queueing trickle candidate, status is not START yet\n", handle->handle_id);
						}
					}
				}
			}
		}
	} else {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse candidate (res=%d)...\n", handle->handle_id, res);
		return res;
	}
	return 0;
}

int janus_sdp_parse_ssrc_group(void *ice_stream, const char *group_attr, int video) {
	if(ice_stream == NULL || group_attr == NULL)
		return -1;
	janus_ice_stream *stream = (janus_ice_stream *)ice_stream;
	janus_ice_handle *handle = stream->handle;
	if(handle == NULL)
		return -2;
	if(!video)
		return -3;
	gboolean fid = strstr(group_attr, "FID") != NULL;
	gboolean sim = strstr(group_attr, "SIM") != NULL;
	guint64 ssrc = 0;
	gchar **list = g_strsplit(group_attr, " ", -1);
	gchar *index = list[0];
	if(index != NULL) {
		int i=0;
		while(index != NULL) {
			if(i > 0 && strlen(index) > 0) {
				ssrc = g_ascii_strtoull(index, NULL, 0);
				switch(i) {
					case 1:
						stream->video_ssrc_peer = ssrc;
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC: %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer);
						break;
					case 2:
						if(fid) {
							stream->video_ssrc_peer_rtx = ssrc;
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (rtx): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_rtx);
						} else if(sim) {
							stream->video_ssrc_peer_sim_1 = ssrc;
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-1): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_sim_1);
						} else {
							JANUS_LOG(LOG_WARN, "[%"SCNu64"] Don't know what to do with SSRC: %"SCNu64"\n", handle->handle_id, ssrc);
						}
						break;
					case 3:
						if(fid) {
							JANUS_LOG(LOG_WARN, "[%"SCNu64"] Found one too many retransmission SSRC (rtx): %"SCNu64"\n", handle->handle_id, ssrc);
						} else if(sim) {
							stream->video_ssrc_peer_sim_2 = ssrc;
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-2): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_sim_2);
						} else {
							JANUS_LOG(LOG_WARN, "[%"SCNu64"] Don't know what to do with SSRC: %"SCNu64"\n", handle->handle_id, ssrc);
						}
						break;
					default:
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Don't know what to do with video SSRC: %"SCNu64"\n", handle->handle_id, ssrc);
						break;
				}
			}
			i++;
			index = list[i];
		}
	}
	g_clear_pointer(&list, g_strfreev);
	return 0;
}

int janus_sdp_parse_ssrc(void *ice_stream, const char *ssrc_attr, int video) {
	if(ice_stream == NULL || ssrc_attr == NULL)
		return -1;
	janus_ice_stream *stream = (janus_ice_stream *)ice_stream;
	janus_ice_handle *handle = stream->handle;
	if(handle == NULL)
		return -2;
	guint64 ssrc = g_ascii_strtoull(ssrc_attr, NULL, 0);
	if(ssrc == 0 || ssrc > G_MAXUINT32)
		return -3;
	if(video) {
		if(stream->video_ssrc_peer == 0) {
			stream->video_ssrc_peer = ssrc;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC: %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer);
		} else {
			/* We already have a video SSRC: check if RID is involved, and we'll keep track of this for simulcasting */
			if(stream->rid[0]) {
				if(stream->video_ssrc_peer_sim_1 == 0) {
					stream->video_ssrc_peer_sim_1 = ssrc;
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-1): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_sim_1);
				} else if(stream->video_ssrc_peer_sim_2 == 0) {
					stream->video_ssrc_peer_sim_2 = ssrc;
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-2): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_sim_2);
				} else {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Don't know what to do with video SSRC: %"SCNu64"\n", handle->handle_id, ssrc);
				}
			}
		}
	} else {
		if(stream->audio_ssrc_peer == 0) {
			stream->audio_ssrc_peer = ssrc;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer audio SSRC: %"SCNu32"\n", handle->handle_id, stream->audio_ssrc_peer);
		}
	}
	return 0;
}

int janus_sdp_anonymize(janus_sdp *anon) {
	if(anon == NULL)
		return -1;
	int audio = 0, video = 0, data = 0;
		/* o= */
	if(anon->o_addr != NULL) {
		g_free(anon->o_addr);
		anon->o_ipv4 = TRUE;
		anon->o_addr = g_strdup("1.1.1.1");
	}
		/* a= */
	GList *temp = anon->attributes;
	while(temp) {
		janus_sdp_attribute *a = (janus_sdp_attribute *)temp->data;
		/* These are attributes we handle ourselves, the plugins don't need them */
		if(!strcasecmp(a->name, "ice-ufrag")
				|| !strcasecmp(a->name, "ice-pwd")
				|| !strcasecmp(a->name, "ice-options")
				|| !strcasecmp(a->name, "fingerprint")
				|| !strcasecmp(a->name, "group")
				|| !strcasecmp(a->name, "msid-semantic")
				|| !strcasecmp(a->name, "rtcp-rsize")) {
			anon->attributes = g_list_remove(anon->attributes, a);
			temp = anon->attributes;
			janus_sdp_attribute_destroy(a);
			continue;
		}
		temp = temp->next;
		continue;
	}
		/* m= */
	temp = anon->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		if(m->type == JANUS_SDP_AUDIO && m->port > 0) {
			audio++;
			m->port = audio == 1 ? 9 : 0;
		} else if(m->type == JANUS_SDP_VIDEO && m->port > 0) {
			video++;
			m->port = video == 1 ? 9 : 0;
		} else if(m->type == JANUS_SDP_APPLICATION && m->port > 0) {
			if(m->proto != NULL && !strcasecmp(m->proto, "DTLS/SCTP")) {
				data++;
				m->port = data == 1 ? 9 : 0;
			} else {
				m->port = 0;
			}
		} else {
			m->port = 0;
		}
			/* c= */
		if(m->c_addr != NULL) {
			g_free(m->c_addr);
			m->c_ipv4 = TRUE;
			m->c_addr = g_strdup("1.1.1.1");
		}
			/* a= */
		GList *tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			/* These are attributes we handle ourselves, the plugins don't need them */
			if(!strcasecmp(a->name, "ice-ufrag")
					|| !strcasecmp(a->name, "ice-pwd")
					|| !strcasecmp(a->name, "ice-options")
					|| !strcasecmp(a->name, "crypto")
					|| !strcasecmp(a->name, "fingerprint")
					|| !strcasecmp(a->name, "setup")
					|| !strcasecmp(a->name, "connection")
					|| !strcasecmp(a->name, "group")
					|| !strcasecmp(a->name, "mid")
					|| !strcasecmp(a->name, "msid")
					|| !strcasecmp(a->name, "msid-semantic")
					|| !strcasecmp(a->name, "rid")
					|| !strcasecmp(a->name, "rtcp")
					|| !strcasecmp(a->name, "rtcp-mux")
					|| !strcasecmp(a->name, "rtcp-rsize")
					|| !strcasecmp(a->name, "candidate")
					|| !strcasecmp(a->name, "ssrc")
					|| !strcasecmp(a->name, "ssrc-group")
					|| !strcasecmp(a->name, "sctpmap")) {
				m->attributes = g_list_remove(m->attributes, a);
				tempA = m->attributes;
				janus_sdp_attribute_destroy(a);
				continue;
			}
			tempA = tempA->next;
		}
		/* Also remove attributes/formats we know we don't support (or don't want to support) now */
		tempA = m->attributes;
		GList *purged_ptypes = NULL;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->value && (strstr(a->value, "red/90000") || strstr(a->value, "ulpfec/90000") || strstr(a->value, "rtx/90000"))) {
				int ptype = atoi(a->value);
				JANUS_LOG(LOG_VERB, "Will remove payload type %d (%s)\n", ptype, a->value);
				purged_ptypes = g_list_append(purged_ptypes, GINT_TO_POINTER(ptype));
			}
			tempA = tempA->next;
		}
		if(purged_ptypes) {
			tempA = purged_ptypes;
			while(tempA) {
				int ptype = GPOINTER_TO_INT(tempA->data);
				janus_sdp_remove_payload_type(anon, ptype);
				tempA = tempA->next;
			}
			g_list_free(purged_ptypes);
			purged_ptypes = NULL;
		}
		temp = temp->next;
	}

	JANUS_LOG(LOG_VERB, " -------------------------------------------\n");
	JANUS_LOG(LOG_VERB, "  >> Anonymized\n");
	JANUS_LOG(LOG_VERB, " -------------------------------------------\n");

	return 0;
}

char *janus_sdp_merge(void *ice_handle, janus_sdp *anon) {
	if(ice_handle == NULL || anon == NULL)
		return NULL;
	janus_ice_handle *handle = (janus_ice_handle *)ice_handle;
	janus_ice_stream *stream = NULL;
	/* Check available media */
	int audio = 0;
	int video = 0;
	int data = 0;
	GList *temp = anon->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		if(m->type == JANUS_SDP_AUDIO && m->port > 0) {
			audio = 1;
		} else if(m->type == JANUS_SDP_VIDEO && m->port > 0) {
			video = 1;
#ifdef HAVE_SCTP
		} else if(m->type == JANUS_SDP_APPLICATION && m->port > 0) {
			if(m->proto && !strcasecmp(m->proto, "DTLS/SCTP"))
				data = 1;
#endif
		}
		temp = temp->next;
	}
	char *rtp_profile = handle->rtp_profile ? handle->rtp_profile : (char *)"RTP/SAVPF";
	gboolean ipv4 = !strstr(janus_get_public_ip(), ":");
	/* Origin o= */
	gint64 sessid = janus_get_real_time();
	if(anon->o_name == NULL)
		anon->o_name = g_strdup("-");
	if(anon->o_sessid == 0 || anon->o_version == 0) {
		anon->o_sessid = sessid;
		anon->o_version = 1;
	}
	anon->o_ipv4 = ipv4;
	g_free(anon->o_addr);
	anon->o_addr = g_strdup(janus_get_public_ip());
	/* Session name s= */
	if(anon->s_name == NULL)
		anon->s_name = g_strdup("Meetecho Janus");
	/* Chrome doesn't like global c= lines, remove it */
	g_free(anon->c_addr);
	anon->c_addr = NULL;
	/* bundle: add new global attribute */
	char buffer[2048], buffer_part[512];
	buffer[0] = '\0';
	buffer_part[0] = '\0';
	g_snprintf(buffer, sizeof(buffer), "BUNDLE");
	if(audio) {
		g_snprintf(buffer_part, sizeof(buffer_part),
			" %s", handle->audio_mid ? handle->audio_mid : "audio");
		g_strlcat(buffer, buffer_part, JANUS_BUFSIZE);
	}
	if(video) {
		g_snprintf(buffer_part, sizeof(buffer_part),
			" %s", handle->video_mid ? handle->video_mid : "video");
		g_strlcat(buffer, buffer_part, JANUS_BUFSIZE);
	}
	if(data) {
		g_snprintf(buffer_part, sizeof(buffer_part),
			" %s", handle->data_mid ? handle->data_mid : "data");
		g_strlcat(buffer, buffer_part, JANUS_BUFSIZE);
	}
	/* Global attributes: start with group */
	GList *first = anon->attributes;
	janus_sdp_attribute *a = janus_sdp_attribute_create("group", "%s", buffer);
	anon->attributes = g_list_insert_before(anon->attributes, first, a);
	/* msid-semantic: add new global attribute */
	a = janus_sdp_attribute_create("msid-semantic", " WMS janus");
	anon->attributes = g_list_insert_before(anon->attributes, first, a);
	/* ICE Full or Lite? */
	if(janus_ice_is_ice_lite_enabled()) {
		/* Janus is acting in ICE Lite mode, advertize this */
		a = janus_sdp_attribute_create("ice-lite", NULL);
		anon->attributes = g_list_insert_before(anon->attributes, first, a);
	}
	/* Media lines now */
	audio = 0;
	video = 0;
#ifdef HAVE_SCTP
	data = 0;
#endif
	temp = anon->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		first = m->attributes;
		/* Overwrite RTP profile for audio and video */
		if(m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) {
			g_free(m->proto);
			m->proto = g_strdup(rtp_profile);
		}
		/* Media connection c= */
		g_free(m->c_addr);
		m->c_ipv4 = ipv4;
		m->c_addr = g_strdup(janus_get_public_ip());
		/* Check if we need to refuse the media or not */
		if(m->type == JANUS_SDP_AUDIO && m->port > 0) {
			audio++;
			if(audio > 1 || !handle->audio_id) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping audio line (we have %d audio lines, and the id is %d)\n", handle->handle_id, audio, handle->audio_id);
				m->port = 0;
				m->direction = JANUS_SDP_INACTIVE;
				temp = temp->next;
				continue;
			}
			/* Audio */
			stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->audio_id));
			if(stream == NULL) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping audio line (invalid stream %d)\n", handle->handle_id, handle->audio_id);
				m->port = 0;
				m->direction = JANUS_SDP_INACTIVE;
				temp = temp->next;
				continue;
			}
		} else if(m->type == JANUS_SDP_VIDEO && m->port > 0) {
			video++;
			gint id = handle->video_id;
			if(id == 0 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE))
				id = handle->audio_id > 0 ? handle->audio_id : handle->video_id;
			if(video > 1 || !id) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping video line (we have %d video lines, and the id is %d)\n", handle->handle_id, video,
					janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? handle->audio_id : handle->video_id);
				m->port = 0;
				m->direction = JANUS_SDP_INACTIVE;
				temp = temp->next;
				continue;
			}
			/* Video */
			stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
			if(stream == NULL) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping video line (invalid stream %d)\n", handle->handle_id, id);
				m->port = 0;
				m->direction = JANUS_SDP_INACTIVE;
				temp = temp->next;
				continue;
			}
#ifdef HAVE_SCTP
		} else if(m->type == JANUS_SDP_APPLICATION) {
			/* Is this SCTP for DataChannels? */
			if(!strcasecmp(m->proto, "DTLS/SCTP") && m->port > 0) {
				/* Yep */
				data++;
				gint id = handle->data_id;
				if(id == 0 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE))
					id = handle->audio_id > 0 ? handle->audio_id : handle->video_id;
				if(data > 1 || !id) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping SCTP line (we have %d SCTP lines, and the id is %d)\n", handle->handle_id, data, id);
					m->port = 0;
					m->direction = JANUS_SDP_INACTIVE;
					temp = temp->next;
					continue;
				}
				/* SCTP */
				stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
				if(stream == NULL) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping SCTP line (invalid stream %d)\n", handle->handle_id, id);
					m->port = 0;
					m->direction = JANUS_SDP_INACTIVE;
					temp = temp->next;
					continue;
				}
			} else {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping unsupported application media line...\n", handle->handle_id);
				m->port = 0;
				m->direction = JANUS_SDP_INACTIVE;
				temp = temp->next;
				continue;
			}
#endif
		} else {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping disabled/unsupported media line...\n", handle->handle_id);
			m->port = 0;
			m->direction = JANUS_SDP_INACTIVE;
			temp = temp->next;
			continue;
		}
		/* a=mid:(audio|video|data) */
		if(m->type == JANUS_SDP_AUDIO) {
			a = janus_sdp_attribute_create("mid", "%s", handle->audio_mid ? handle->audio_mid : "audio");
			m->attributes = g_list_insert_before(m->attributes, first, a);
		} else if(m->type == JANUS_SDP_VIDEO) {
			a = janus_sdp_attribute_create("mid", "%s", handle->video_mid ? handle->video_mid : "video");
			m->attributes = g_list_insert_before(m->attributes, first, a);
#ifdef HAVE_SCTP
		} else if(m->type == JANUS_SDP_APPLICATION) {
			/* FIXME sctpmap and webrtc-datachannel should be dynamic */
			a = janus_sdp_attribute_create("sctpmap", "5000 webrtc-datachannel 16");
			m->attributes = g_list_insert_before(m->attributes, first, a);
			a = janus_sdp_attribute_create("mid", "%s", handle->data_mid ? handle->data_mid : "data");
			m->attributes = g_list_insert_before(m->attributes, first, a);
#endif
		}
		if(m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) {
			a = janus_sdp_attribute_create("rtcp-mux", NULL);
			m->attributes = g_list_insert_before(m->attributes, first, a);
		}
		/* ICE ufrag and pwd, DTLS fingerprint setup and connection a= */
		gchar *ufrag = NULL;
		gchar *password = NULL;
		nice_agent_get_local_credentials(handle->agent, stream->stream_id, &ufrag, &password);
		a = janus_sdp_attribute_create("ice-ufrag", "%s", ufrag);
		m->attributes = g_list_insert_before(m->attributes, first, a);
		a = janus_sdp_attribute_create("ice-pwd", "%s", password);
		m->attributes = g_list_insert_before(m->attributes, first, a);
		g_free(ufrag);
		g_free(password);
		a = janus_sdp_attribute_create("ice-options", "trickle");
		m->attributes = g_list_insert_before(m->attributes, first, a);
		a = janus_sdp_attribute_create("fingerprint", "sha-256 %s", janus_dtls_get_local_fingerprint());
		m->attributes = g_list_insert_before(m->attributes, first, a);
		a = janus_sdp_attribute_create("setup", "%s", janus_get_dtls_srtp_role(stream->dtls_role));
		m->attributes = g_list_insert_before(m->attributes, first, a);
		/* Add last attributes, rtcp and ssrc (msid) */
		if(m->type == JANUS_SDP_AUDIO &&
				(m->direction == JANUS_SDP_DEFAULT || m->direction == JANUS_SDP_SENDRECV || m->direction == JANUS_SDP_SENDONLY)) {
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" cname:janusaudio", stream->audio_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" msid:janus janusa0", stream->audio_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" mslabel:janus", stream->audio_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" label:janusa0", stream->audio_ssrc);
			m->attributes = g_list_append(m->attributes, a);
		} else if(m->type == JANUS_SDP_VIDEO &&
				(m->direction == JANUS_SDP_DEFAULT || m->direction == JANUS_SDP_SENDRECV || m->direction == JANUS_SDP_SENDONLY)) {
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" cname:janusvideo", stream->video_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" msid:janus janusv0", stream->video_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" mslabel:janus", stream->video_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" label:janusv0", stream->video_ssrc);
			m->attributes = g_list_append(m->attributes, a);
		}
		/* FIXME If the peer is Firefox and is negotiating simulcasting, add the rid attributes */
		if(m->type == JANUS_SDP_VIDEO && stream->rid[0] != NULL) {
			char rids[50];
			rids[0] = '\0';
			int i=0;
			for(i=0; i<3; i++) {
				if(stream->rid[i] == NULL)
					continue;
				a = janus_sdp_attribute_create("rid", "%s recv", stream->rid[i]);
				m->attributes = g_list_append(m->attributes, a);
				if(strlen(rids) == 0) {
					g_strlcat(rids, stream->rid[i], sizeof(rids));
				} else {
					g_strlcat(rids, ";", sizeof(rids));
					g_strlcat(rids, stream->rid[i], sizeof(rids));
				}
			}
			a = janus_sdp_attribute_create("simulcast", " recv rid=%s", rids);
			m->attributes = g_list_append(m->attributes, a);
		}
		/* And now the candidates */
		janus_ice_candidates_to_sdp(handle, m, stream->stream_id, 1);
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) &&
				(m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO))
			janus_ice_candidates_to_sdp(handle, m, stream->stream_id, 2);
		/* Since we're half-trickling, we need to notify the peer that these are all the
		 * candidates we have for this media stream, via an end-of-candidates attribute:
		 * https://tools.ietf.org/html/draft-ietf-mmusic-trickle-ice-02#section-4.1 */
		janus_sdp_attribute *end = janus_sdp_attribute_create("end-of-candidates", NULL);
		m->attributes = g_list_append(m->attributes, end);
		/* Next */
		temp = temp->next;
	}

	char *sdp = janus_sdp_write(anon);

	JANUS_LOG(LOG_VERB, " -------------------------------------------\n");
	JANUS_LOG(LOG_VERB, "  >> Merged (%zu bytes)\n", strlen(sdp));
	JANUS_LOG(LOG_VERB, " -------------------------------------------\n");
	JANUS_LOG(LOG_VERB, "%s\n", sdp);

	return sdp;
}
