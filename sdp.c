/*! \file    sdp.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SDP processing
 * \details  Implementation of an SDP
 * parser/merger/generator in the server. Each SDP coming from peers is
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

#include <netdb.h>

#include <gio/gio.h>

#include "janus.h"
#include "ice.h"
#include "sdp.h"
#include "utils.h"
#include "ip-utils.h"
#include "debug.h"
#include "events.h"


/* Pre-parse SDP: is this SDP valid? how many audio/video lines? any features to take into account? */
janus_sdp *janus_sdp_preparse(void *ice_handle, const char *jsep_sdp, char *error_str, size_t errlen,
		int *audio, int *video, int *data) {
	if(!ice_handle || !jsep_sdp || !audio || !video || !data) {
		JANUS_LOG(LOG_ERR, "  Can't preparse, invalid arguments\n");
		return NULL;
	}
	janus_ice_handle *handle = (janus_ice_handle *)ice_handle;
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
		/* Preparse the mid as well */
		GList *tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->name) {
				if(!strcasecmp(a->name, "mid")) {
					/* Found mid attribute */
					if(a->value == NULL) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid mid attribute (no value)\n", handle->handle_id);
						janus_sdp_destroy(parsed_sdp);
						return NULL;
					}
					if(m->type == JANUS_SDP_AUDIO && m->port > 0) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio mid: %s\n", handle->handle_id, a->value);
						if(strlen(a->value) > 16) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] Audio mid too large: (%zu > 16)\n", handle->handle_id, strlen(a->value));
							janus_sdp_destroy(parsed_sdp);
							return NULL;
						}
						if(handle->audio_mid == NULL)
							handle->audio_mid = g_strdup(a->value);
						if(handle->stream_mid == NULL)
							handle->stream_mid = handle->audio_mid;
					} else if(m->type == JANUS_SDP_VIDEO && m->port > 0) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video mid: %s\n", handle->handle_id, a->value);
						if(strlen(a->value) > 16) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] Video mid too large: (%zu > 16)\n", handle->handle_id, strlen(a->value));
							janus_sdp_destroy(parsed_sdp);
							return NULL;
						}
						if(handle->video_mid == NULL)
							handle->video_mid = g_strdup(a->value);
						if(handle->stream_mid == NULL)
							handle->stream_mid = handle->video_mid;
					}
				}
			}
			tempA = tempA->next;
		}
		temp = temp->next;
	}
#ifdef HAVE_SCTP
	*data = (strstr(jsep_sdp, "DTLS/SCTP") && !strstr(jsep_sdp, " 0 DTLS/SCTP") &&
		!strstr(jsep_sdp, " 0 UDP/DTLS/SCTP")) ? 1 : 0;	/* FIXME This is a really hacky way of checking... */
#else
	*data = 0;
#endif

	return parsed_sdp;
}

/* Parse SDP */
int janus_sdp_process(void *ice_handle, janus_sdp *remote_sdp, gboolean update) {
	if(!ice_handle || !remote_sdp)
		return -1;
	janus_ice_handle *handle = (janus_ice_handle *)ice_handle;
	janus_ice_stream *stream = handle->stream;
	if(!stream)
		return -1;
	gchar *ruser = NULL, *rpass = NULL, *rhashing = NULL, *rfingerprint = NULL;
	int audio = 0, video = 0;
#ifdef HAVE_SCTP
	int data = 0;
#endif
	gboolean rtx = FALSE;
	/* Ok, let's start with global attributes */
	GList *temp = remote_sdp->attributes;
	while(temp) {
		janus_sdp_attribute *a = (janus_sdp_attribute *)temp->data;
		if(a && a->name && a->value) {
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
	int mlines = 0;
	temp = remote_sdp->m_lines;
	while(temp) {
		mlines++;
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		if(m->type == JANUS_SDP_AUDIO) {
			if(handle->rtp_profile == NULL && m->proto != NULL)
				handle->rtp_profile = g_strdup(m->proto);
			audio++;
			if(audio > 1) {
				temp = temp->next;
				continue;
			}
			if(m->port > 0) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsing audio candidates (stream=%d)...\n", handle->handle_id, stream->stream_id);
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO)) {
					janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
					stream->audio_ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? */
					if(stream->audio_rtcp_ctx == NULL) {
						stream->audio_rtcp_ctx = g_malloc0(sizeof(rtcp_context));
						stream->audio_rtcp_ctx->tb = 48000;	/* May change later */
					}
				}
				switch(m->direction) {
					case JANUS_SDP_INACTIVE:
					case JANUS_SDP_INVALID:
						stream->audio_send = FALSE;
						stream->audio_recv = FALSE;
						break;
					case JANUS_SDP_SENDONLY:
						/* A sendonly peer means recvonly for Janus */
						stream->audio_send = FALSE;
						stream->audio_recv = TRUE;
						break;
					case JANUS_SDP_RECVONLY:
						/* A recvonly peer means sendonly for Janus */
						stream->audio_send = TRUE;
						stream->audio_recv = FALSE;
						break;
					case JANUS_SDP_SENDRECV:
					case JANUS_SDP_DEFAULT:
					default:
						stream->audio_send = TRUE;
						stream->audio_recv = TRUE;
						break;
				}
				if(m->ptypes != NULL) {
					g_list_free(stream->audio_payload_types);
					stream->audio_payload_types = g_list_copy(m->ptypes);
				}
			} else {
				/* Audio rejected? */
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio rejected by peer...\n", handle->handle_id);
			}
		} else if(m->type == JANUS_SDP_VIDEO) {
			if(handle->rtp_profile == NULL && m->proto != NULL)
				handle->rtp_profile = g_strdup(m->proto);
			video++;
			if(video > 1) {
				temp = temp->next;
				continue;
			}
			if(m->port > 0) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsing video candidates (stream=%d)...\n", handle->handle_id, stream->stream_id);
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)) {
					janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
					stream->video_ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? */
					if(stream->video_rtcp_ctx[0] == NULL) {
						stream->video_rtcp_ctx[0] = g_malloc0(sizeof(rtcp_context));
						stream->video_rtcp_ctx[0]->tb = 90000;	/* May change later */
					}
				}
				switch(m->direction) {
					case JANUS_SDP_INACTIVE:
					case JANUS_SDP_INVALID:
						stream->video_send = FALSE;
						stream->video_recv = FALSE;
						break;
					case JANUS_SDP_SENDONLY:
						/* A sendonly peer means recvonly for Janus */
						stream->video_send = FALSE;
						stream->video_recv = TRUE;
						break;
					case JANUS_SDP_RECVONLY:
						/* A recvonly peer means sendonly for Janus */
						stream->video_send = TRUE;
						stream->video_recv = FALSE;
						break;
					case JANUS_SDP_SENDRECV:
					case JANUS_SDP_DEFAULT:
					default:
						stream->video_send = TRUE;
						stream->video_recv = TRUE;
						break;
				}
				if(m->ptypes != NULL) {
					g_list_free(stream->video_payload_types);
					stream->video_payload_types = g_list_copy(m->ptypes);
				}
			} else {
				/* Video rejected? */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video rejected by peer...\n", handle->handle_id);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
			}
#ifdef HAVE_SCTP
		} else if(m->type == JANUS_SDP_APPLICATION) {
			/* Is this SCTP for DataChannels? */
			if(!strcasecmp(m->proto, "DTLS/SCTP") || !strcasecmp(m->proto, "UDP/DTLS/SCTP")) {
				data++;
				if(data > 1) {
					temp = temp->next;
					continue;
				}
				if(m->port > 0) {
					/* Yep */
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsing SCTP candidates (stream=%d)...\n", handle->handle_id, stream->stream_id);
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS)) {
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
					}
					if(!strcasecmp(m->proto, "UDP/DTLS/SCTP")) {
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP);
					} else {
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP);
					}
				} else {
					/* Data channels rejected? */
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Data channels rejected by peer...\n", handle->handle_id);
					janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
					janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP);
				}
			} else {
				/* Unsupported data channels format. */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Data channels format %s unsupported, skipping\n", handle->handle_id, m->proto);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP);
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
			if(a->name && a->value) {
				if(!strcasecmp(a->name, "mid")) {
					/* Found mid attribute */
					if(m->type == JANUS_SDP_AUDIO && m->port > 0) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio mid: %s\n", handle->handle_id, a->value);
						if(strlen(a->value) > 16) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] Audio mid too large: (%zu > 16)\n", handle->handle_id, strlen(a->value));
							return -2;
						}
						if(handle->audio_mid == NULL)
							handle->audio_mid = g_strdup(a->value);
						if(handle->stream_mid == NULL)
							handle->stream_mid = handle->audio_mid;
					} else if(m->type == JANUS_SDP_VIDEO && m->port > 0) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video mid: %s\n", handle->handle_id, a->value);
						if(strlen(a->value) > 16) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] Video mid too large: (%zu > 16)\n", handle->handle_id, strlen(a->value));
							return -2;
						}
						if(handle->video_mid == NULL)
							handle->video_mid = g_strdup(a->value);
						if(handle->stream_mid == NULL)
							handle->stream_mid = handle->video_mid;
#ifdef HAVE_SCTP
					} else if(m->type == JANUS_SDP_APPLICATION) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Data Channel mid: %s\n", handle->handle_id, a->value);
						if(handle->data_mid == NULL)
							handle->data_mid = g_strdup(a->value);
						if(handle->stream_mid == NULL)
							handle->stream_mid = handle->data_mid;
#endif
					}
				} else if(!strcasecmp(a->name, "fingerprint")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Fingerprint (local) : %s\n", handle->handle_id, a->value);
					if(strcasestr(a->value, "sha-256 ") == a->value) {
						g_free(rhashing);	/* FIXME We're overwriting the global one, if any */
						rhashing = g_strdup("sha-256");
						g_free(rfingerprint);	/* FIXME We're overwriting the global one, if any */
						rfingerprint = g_strdup(a->value + strlen("sha-256 "));
					} else if(strcasestr(a->value, "sha-1 ") == a->value) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-1 instead of sha-256), but that's ok\n", handle->handle_id);
						g_free(rhashing);	/* FIXME We're overwriting the global one, if any */
						rhashing = g_strdup("sha-1");
						g_free(rfingerprint);	/* FIXME We're overwriting the global one, if any */
						rfingerprint = g_strdup(a->value + strlen("sha-1 "));
					} else {
						/* FIXME We should handle this somehow anyway... OpenSSL supports them all */
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-256), *NOT* cool\n", handle->handle_id);
					}
				} else if(!strcasecmp(a->name, "setup")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] DTLS setup (local):  %s\n", handle->handle_id, a->value);
					if(!update) {
						if(!strcasecmp(a->value, "actpass") || !strcasecmp(a->value, "passive")) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Setting connect state (DTLS client)\n", handle->handle_id);
							stream->dtls_role = JANUS_DTLS_ROLE_CLIENT;
						} else if(!strcasecmp(a->value, "active")) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Setting accept state (DTLS server)\n", handle->handle_id);
							stream->dtls_role = JANUS_DTLS_ROLE_SERVER;
						}
						if(stream->component && stream->component->dtls)
							stream->component->dtls->dtls_role = stream->dtls_role;
					}
					/* TODO Handle holdconn... */
				} else if(!strcasecmp(a->name, "ice-ufrag")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE ufrag (local):   %s\n", handle->handle_id, a->value);
					g_free(ruser);	/* FIXME We're overwriting the global one, if any */
					ruser = g_strdup(a->value);
				} else if(!strcasecmp(a->name, "ice-pwd")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE pwd (local):     %s\n", handle->handle_id, a->value);
					g_free(rpass);	/* FIXME We're overwriting the global one, if any */
					rpass = g_strdup(a->value);
				}
			}
			tempA = tempA->next;
		}
		if(mlines == 1) {
			if(!ruser || !rpass || (janus_is_webrtc_encryption_enabled() && (!rfingerprint || !rhashing))) {
				/* Missing mandatory information, failure... */
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] SDP missing mandatory information\n", handle->handle_id);
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] %p, %p, %p, %p\n", handle->handle_id, ruser, rpass, rfingerprint, rhashing);
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
			/* If we received the ICE credentials for the first time, enforce them */
			if(ruser && !stream->ruser && rpass && !stream->rpass) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Setting remote credentials...\n", handle->handle_id);
				if(!nice_agent_set_remote_credentials(handle->agent, handle->stream_id, ruser, rpass)) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to set remote credentials!\n", handle->handle_id);
				}
			} else
			/* If this is a renegotiation, check if this is an ICE restart */
			if((ruser && stream->ruser && strcmp(ruser, stream->ruser)) ||
					(rpass && stream->rpass && strcmp(rpass, stream->rpass))) {
				JANUS_LOG(LOG_INFO, "[%"SCNu64"] ICE restart detected\n", handle->handle_id);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES);
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART);
			}
			/* Store fingerprint and hashing */
			if(janus_is_webrtc_encryption_enabled()) {
				g_free(stream->remote_hashing);
				stream->remote_hashing = g_strdup(rhashing);
				g_free(stream->remote_fingerprint);
				stream->remote_fingerprint = g_strdup(rfingerprint);
			}
			/* Store the ICE username and password for this stream */
			g_free(stream->ruser);
			stream->ruser = g_strdup(ruser);
			g_free(stream->rpass);
			stream->rpass = g_strdup(rpass);
		}
		/* Is simulcasting enabled, using rid? (we need to check this before parsing SSRCs) */
		tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->name && !strcasecmp(a->name, "rid") && a->value) {
				/* This attribute is used for simulcasting */
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
			} else if(a->name && !strcasecmp(a->name, "simulcast") && a->value) {
				/* Firefox and Chrome signal simulcast support differently */
				stream->legacy_rid = strstr(a->value, "rid=") ? TRUE : FALSE;
			}
			tempA = tempA->next;
		}
		/* Let's start figuring out the SSRCs, and any grouping that may be there */
		stream->audio_ssrc_peer_new = 0;
		stream->video_ssrc_peer_new[0] = 0;
		stream->video_ssrc_peer_new[1] = 0;
		stream->video_ssrc_peer_new[2] = 0;
		stream->video_ssrc_peer_rtx_new[0] = 0;
		stream->video_ssrc_peer_rtx_new[1] = 0;
		stream->video_ssrc_peer_rtx_new[2] = 0;
		/* Any SSRC SIM group? */
		tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->name && a->value) {
				if(!strcasecmp(a->name, "ssrc-group") && strstr(a->value, "SIM")) {
					int res = janus_sdp_parse_ssrc_group(stream, (const char *)a->value, m->type == JANUS_SDP_VIDEO);
					if(res != 0) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse SSRC SIM group attribute... (%d)\n", handle->handle_id, res);
					}
				}
			}
			tempA = tempA->next;
		}
		/* Any SSRC FID group? */
		tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->name && a->value) {
				if(!strcasecmp(a->name, "ssrc-group") && strstr(a->value, "FID")) {
					int res = janus_sdp_parse_ssrc_group(stream, (const char *)a->value, m->type == JANUS_SDP_VIDEO);
					if(res != 0) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse SSRC FID group attribute... (%d)\n", handle->handle_id, res);
					}
				}
			}
			tempA = tempA->next;
		}
		/* Any SSRC in general? */
		tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->name && a->value) {
				if(!strcasecmp(a->name, "ssrc")) {
					int res = janus_sdp_parse_ssrc(stream, (const char *)a->value, m->type == JANUS_SDP_VIDEO);
					if(res != 0) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse SSRC attribute... (%d)\n", handle->handle_id, res);
					}
				}
			}
			tempA = tempA->next;
		}
		/* Now look for candidates and other info */
		tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->name) {
				if(!strcasecmp(a->name, "candidate")) {
					if(m->type == JANUS_SDP_AUDIO && mlines > 1) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] This is an audio candidate but we're bundling on another stream, ignoring...\n", handle->handle_id);
					} else if(m->type == JANUS_SDP_VIDEO && mlines > 1) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] This is a video candidate but we're bundling on another stream, ignoring...\n", handle->handle_id);
#ifdef HAVE_SCTP
					} else if(m->type == JANUS_SDP_APPLICATION && mlines > 1) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] This is a SCTP candidate but we're bundling on another stream, ignoring...\n", handle->handle_id);
#endif
					} else {
						int res = janus_sdp_parse_candidate(stream, (const char *)a->value, 0);
						if(res != 0) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse candidate... (%d)\n", handle->handle_id, res);
						}
					}
				} else if(!strcasecmp(a->name, "rtcp-fb")) {
					if(a->value && strstr(a->value, "nack") && stream->component) {
						if(m->type == JANUS_SDP_AUDIO) {
							/* Enable NACKs for audio */
							stream->component->do_audio_nacks = TRUE;
						} else if(m->type == JANUS_SDP_VIDEO) {
							/* Enable NACKs for video */
							stream->component->do_video_nacks = TRUE;
						}
					}
				} else if(!strcasecmp(a->name, "fmtp")) {
					if(a->value && strstr(a->value, "apt=")) {
						/* RFC4588 rtx payload type mapping */
						int ptype = -1, rtx_ptype = -1;
						if(sscanf(a->value, "%d apt=%d", &rtx_ptype, &ptype) != 2) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse fmtp/apt attribute...\n", handle->handle_id);
						} else {
							rtx = TRUE;
							janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX);
							if(stream->rtx_payload_types == NULL)
								stream->rtx_payload_types = g_hash_table_new(NULL, NULL);
							g_hash_table_insert(stream->rtx_payload_types, GINT_TO_POINTER(ptype), GINT_TO_POINTER(rtx_ptype));
						}
					}
				} else if(!strcasecmp(a->name, "rtpmap")) {
					if(a->value) {
						int ptype = atoi(a->value);
						if(ptype > -1) {
							char *cr = strchr(a->value, '/');
							if(cr != NULL) {
								cr++;
								uint32_t clock_rate = 0;
								if(janus_string_to_uint32(cr, &clock_rate) == 0) {
									if(stream->clock_rates == NULL)
										stream->clock_rates = g_hash_table_new(NULL, NULL);
									g_hash_table_insert(stream->clock_rates, GINT_TO_POINTER(ptype), GUINT_TO_POINTER(clock_rate));
								}
							}
						}
					}
				}
#ifdef HAVE_SCTP
				else if(!strcasecmp(a->name, "sctpmap")) {
					/* We don't really care */
					JANUS_LOG(LOG_VERB, "Got a sctpmap attribute: %s\n", a->value);
				}
#endif
			}
			tempA = tempA->next;
		}
		/* Any change in SSRCs we should be aware of? */
		if(m->type == JANUS_SDP_AUDIO) {
			if(stream->audio_ssrc_peer_new > 0) {
				if(stream->audio_ssrc_peer > 0 && stream->audio_ssrc_peer != stream->audio_ssrc_peer_new) {
					JANUS_LOG(LOG_INFO, "[%"SCNu64"] Audio SSRC changed: %"SCNu32" --> %"SCNu32"\n",
						handle->handle_id, stream->audio_ssrc_peer, stream->audio_ssrc_peer_new);
					/* FIXME Reset the RTCP context */
					janus_ice_component *component = stream->component;
					janus_mutex_lock(&component->mutex);
					if(stream->audio_rtcp_ctx) {
						memset(stream->audio_rtcp_ctx, 0, sizeof(*stream->audio_rtcp_ctx));
						stream->audio_rtcp_ctx->tb = 48000;	/* May change later */
					}
					if(component->last_seqs_audio)
						janus_seq_list_free(&component->last_seqs_audio);
					janus_mutex_unlock(&component->mutex);
				}
				stream->audio_ssrc_peer = stream->audio_ssrc_peer_new;
				stream->audio_ssrc_peer_new = 0;
			}
		} else if(m->type == JANUS_SDP_VIDEO) {
			int vindex = 0;
			for(vindex=0; vindex<3; vindex++) {
				if(stream->video_ssrc_peer_new[vindex] > 0) {
					if(stream->video_ssrc_peer[vindex] > 0 && stream->video_ssrc_peer[vindex] != stream->video_ssrc_peer_new[vindex]) {
						JANUS_LOG(LOG_INFO, "[%"SCNu64"] Video SSRC (#%d) changed: %"SCNu32" --> %"SCNu32"\n",
							handle->handle_id, vindex, stream->video_ssrc_peer[vindex], stream->video_ssrc_peer_new[vindex]);
						/* FIXME Reset the RTCP context */
						janus_ice_component *component = stream->component;
						if(component != NULL) {
							janus_mutex_lock(&component->mutex);
							if(stream->video_rtcp_ctx[vindex]) {
								memset(stream->video_rtcp_ctx[vindex], 0, sizeof(*stream->video_rtcp_ctx[vindex]));
								stream->video_rtcp_ctx[vindex]->tb = 90000;
							}
							if(component->last_seqs_video[vindex])
								janus_seq_list_free(&component->last_seqs_video[vindex]);
							janus_mutex_unlock(&component->mutex);
						}
					}
					stream->video_ssrc_peer[vindex] = stream->video_ssrc_peer_new[vindex];
					stream->video_ssrc_peer_new[vindex] = 0;
				}
				/* Do the same with the related rtx SSRC, if any */
				if(stream->video_ssrc_peer_rtx_new[vindex] > 0) {
					if(stream->video_ssrc_peer_rtx[vindex] > 0 && stream->video_ssrc_peer_rtx[vindex] != stream->video_ssrc_peer_rtx_new[vindex]) {
						JANUS_LOG(LOG_INFO, "[%"SCNu64"] Video SSRC (#%d rtx) changed: %"SCNu32" --> %"SCNu32"\n",
							handle->handle_id, vindex, stream->video_ssrc_peer_rtx[vindex], stream->video_ssrc_peer_rtx_new[vindex]);
					}
					stream->video_ssrc_peer_rtx[vindex] = stream->video_ssrc_peer_rtx_new[vindex];
					stream->video_ssrc_peer_rtx_new[vindex] = 0;
					if(stream->video_ssrc_rtx == 0)
						stream->video_ssrc_rtx = janus_random_uint32();	/* FIXME Should we look for conflicts? */
				}
			}
			if(stream->video_ssrc_peer[1] && stream->video_rtcp_ctx[1] == NULL) {
				stream->video_rtcp_ctx[1] = g_malloc0(sizeof(rtcp_context));
				stream->video_rtcp_ctx[1]->tb = 90000;
			}
			if(stream->video_ssrc_peer[2] && stream->video_rtcp_ctx[2] == NULL) {
				stream->video_rtcp_ctx[2] = g_malloc0(sizeof(rtcp_context));
				stream->video_rtcp_ctx[2]->tb = 90000;
			}
		}
		temp = temp->next;
	}
	/* Disable RFC4588 if the peer didn't negotiate it */
	if(!rtx) {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX);
		stream->video_ssrc_rtx = 0;
	}
	/* Cleanup */
	g_free(ruser);
	g_free(rpass);
	g_free(rhashing);
	g_free(rfingerprint);

	return 0;	/* FIXME Handle errors better */
}

typedef struct janus_sdp_mdns_candidate {
	janus_ice_handle *handle;
	char *candidate, *local;
	GCancellable *cancellable;
} janus_sdp_mdns_candidate;
static void janus_sdp_mdns_resolved(GObject *source_object, GAsyncResult *res, gpointer user_data) {
	/* This callback is invoked when the address is resolved */
	janus_sdp_mdns_candidate *mc = (janus_sdp_mdns_candidate *)user_data;
	GResolver *resolver = g_resolver_get_default();
	GError *error = NULL;
	GList *list = g_resolver_lookup_by_name_finish(resolver, res, &error);
	if(mc == NULL) {
		g_resolver_free_addresses(list);
		g_object_unref(resolver);
		return;
	}
	char *resolved = NULL;
	if(error != NULL || list == NULL || list->data == NULL) {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Error resolving mDNS address (%s): %s\n",
			mc->handle->handle_id, mc->local, error ? error->message : "no results");
	} else {
		resolved = g_inet_address_to_string((GInetAddress *)list->data);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] mDNS address (%s) resolved: %s\n",
			mc->handle->handle_id, mc->local, resolved);
	}
	g_resolver_free_addresses(list);
	g_object_unref(resolver);
	if(resolved != NULL && mc->handle->stream && mc->handle->app_handle &&
			!g_atomic_int_get(&mc->handle->app_handle->stopped) &&
			!g_atomic_int_get(&mc->handle->destroyed)) {
		/* Replace the .local address with the resolved one in the candidate string */
		mc->candidate = janus_string_replace(mc->candidate, mc->local, resolved);
		/* Parse the candidate again */
		janus_mutex_lock(&mc->handle->mutex);
		(void)janus_sdp_parse_candidate(mc->handle->stream, mc->candidate, 1);
		janus_mutex_unlock(&mc->handle->mutex);
	}
	g_free(resolved);
	/* Get rid of the helper struct */
	janus_refcount_decrease(&mc->handle->ref);
	g_free(mc->candidate);
	g_free(mc->local);
	g_free(mc);
}

int janus_sdp_parse_candidate(void *ice_stream, const char *candidate, int trickle) {
	if(ice_stream == NULL || candidate == NULL)
		return -1;
	janus_ice_stream *stream = (janus_ice_stream *)ice_stream;
	janus_ice_handle *handle = stream->handle;
	if(handle == NULL)
		return -2;
	janus_ice_component *component = NULL;
	if(strlen(candidate) == 0 || strstr(candidate, "end-of-candidates")) {
		/* FIXME Should we do something with this? */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] end-of-candidates received\n", handle->handle_id);
		return 0;
	}
	if(strstr(candidate, "candidate:") == candidate) {
		/* Skipping the 'candidate:' prefix Firefox puts in trickle candidates */
		candidate += strlen("candidate:");
	}
	char rfoundation[33], rtransport[4], rip[50], rtype[6], rrelip[40];
	guint32 rcomponent, rpriority, rport, rrelport;
	int res = sscanf(candidate, "%32s %30u %3s %30u %49s %30u typ %5s %*s %39s %*s %30u",
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
		if(strstr(rip, ".local")) {
			/* The IP is actually an mDNS address, try to resolve it
			 * https://tools.ietf.org/html/draft-ietf-rtcweb-mdns-ice-candidates-04 */
			if(!janus_ice_is_mdns_enabled()) {
				/* ...unless mDNS resolution is disabled, in which case ignore this candidate */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] mDNS candidate ignored\n", handle->handle_id);
				return 0;
			}
			/* We'll resolve this address asynchronously, in order not to keep this thread busy */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Resolving mDNS address (%s) asynchronously\n",
				handle->handle_id, rip);
			janus_sdp_mdns_candidate *mc = g_malloc(sizeof(janus_sdp_mdns_candidate));
			janus_refcount_increase(&handle->ref);
			mc->handle = handle;
			mc->candidate = g_strdup(candidate);
			mc->local = g_strdup(rip);
			mc->cancellable = NULL;
			GResolver *resolver = g_resolver_get_default();
			g_resolver_lookup_by_name_async(resolver, rip, NULL,
				(GAsyncReadyCallback)janus_sdp_mdns_resolved, mc);
			return 0;
		}
		/* Add remote candidate */
		component = stream->component;
		if(component == NULL || rcomponent > 1) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Skipping component %d in stream %d (rtcp-muxing)\n", handle->handle_id, rcomponent, stream->stream_id);
		} else {
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
				g_strlcpy(c->foundation, rfoundation, NICE_CANDIDATE_MAX_FOUNDATION);
				c->priority = rpriority;
				gboolean added = nice_address_set_from_string(&c->addr, rip);
				if(!added) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]    Invalid address '%s', skipping %s candidate (%s)\n",
						handle->handle_id, rip, rtype, candidate);
					nice_candidate_free(c);
					return 0;
				}
				nice_address_set_port(&c->addr, rport);
				if(c->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE || c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
					added = nice_address_set_from_string(&c->base_addr, rrelip);
					if(added)
						nice_address_set_port(&c->base_addr, rrelport);
				} else if(c->type == NICE_CANDIDATE_TYPE_RELAYED) {
					/* FIXME Do we really need the base address for TURN? */
					added = nice_address_set_from_string(&c->base_addr, rrelip);
					if(added)
						nice_address_set_port(&c->base_addr, rrelport);
				}
				if(!added) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]    Invalid base address '%s', skipping %s candidate (%s)\n",
						handle->handle_id, rrelip, rtype, candidate);
					nice_candidate_free(c);
					return 0;
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
					janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_RCAND,
						session->session_id, handle->handle_id, handle->opaque_id, info);
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
							/* Queue the candidate, we'll process it in the loop */
							janus_ice_add_remote_candidate(handle, c);
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
								/* Queue the candidate, we'll process it in the loop */
								janus_ice_add_remote_candidate(handle, c);
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
	if(stream->rid[0] != NULL) {
		/* Simulcasting is rid-based, don't parse SSRCs for now */
		return 0;
	}
	gboolean fid = strstr(group_attr, "FID") != NULL;
	gboolean sim = strstr(group_attr, "SIM") != NULL;
	guint64 ssrc = 0;
	guint32 first_ssrc = 0;
	gchar **list = g_strsplit(group_attr, " ", -1);
	gchar *index = list[0];
	if(index != NULL) {
		int i=0;
		while(index != NULL) {
			if(i > 0 && strlen(index) > 0) {
				ssrc = g_ascii_strtoull(index, NULL, 0);
				switch(i) {
					case 1:
						first_ssrc = ssrc;
						if(stream->video_ssrc_peer_new[0] == ssrc || stream->video_ssrc_peer_new[1] == ssrc
								|| stream->video_ssrc_peer_new[2] == ssrc) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Already parsed this SSRC: %"SCNu64" (%s group)\n",
								handle->handle_id, ssrc, (fid ? "FID" : (sim ? "SIM" : "??")));
						} else {
							if(stream->video_ssrc_peer_new[0] == 0) {
								stream->video_ssrc_peer_new[0] = ssrc;
								JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC: %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_new[0]);
							} else {
								/* We already have a video SSRC: check if rid is involved, and we'll keep track of this for simulcasting */
								if(stream->rid[0]) {
									if(stream->video_ssrc_peer_new[1] == 0) {
										stream->video_ssrc_peer_new[1] = ssrc;
										JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-1): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_new[1]);
									} else if(stream->video_ssrc_peer_new[2] == 0) {
										stream->video_ssrc_peer_new[2] = ssrc;
										JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-2): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_new[2]);
									} else {
										JANUS_LOG(LOG_WARN, "[%"SCNu64"] Don't know what to do with video SSRC: %"SCNu64"\n", handle->handle_id, ssrc);
									}
								}
							}
						}
						break;
					case 2:
						if(fid) {
							if(stream->video_ssrc_peer_new[0] == first_ssrc && stream->video_ssrc_peer_rtx_new[0] == 0) {
								stream->video_ssrc_peer_rtx_new[0] = ssrc;
								JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (rtx): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_rtx_new[0]);
							} else if(stream->video_ssrc_peer_new[1] == first_ssrc && stream->video_ssrc_peer_rtx_new[1] == 0) {
								stream->video_ssrc_peer_rtx_new[1] = ssrc;
								JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-1 rtx): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_rtx_new[1]);
							} else if(stream->video_ssrc_peer_new[2] == first_ssrc && stream->video_ssrc_peer_rtx_new[2] == 0) {
								stream->video_ssrc_peer_rtx_new[2] = ssrc;
								JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-2 rtx): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_rtx_new[2]);
							} else {
								JANUS_LOG(LOG_WARN, "[%"SCNu64"] Don't know what to do with rtx SSRC: %"SCNu64"\n", handle->handle_id, ssrc);
							}
						} else if(sim) {
							stream->video_ssrc_peer_new[1] = ssrc;
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-1): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_new[1]);
						} else {
							JANUS_LOG(LOG_WARN, "[%"SCNu64"] Don't know what to do with SSRC: %"SCNu64"\n", handle->handle_id, ssrc);
						}
						break;
					case 3:
						if(fid) {
							JANUS_LOG(LOG_WARN, "[%"SCNu64"] Found one too many retransmission SSRC (rtx): %"SCNu64"\n", handle->handle_id, ssrc);
						} else if(sim) {
							stream->video_ssrc_peer_new[2] = ssrc;
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC (sim-2): %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_new[2]);
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
		if(stream->rid[0] != NULL) {
			/* Simulcasting is rid-based, only keep track of a single SSRC for fallback */
			if(stream->video_ssrc_peer_temp == 0) {
				stream->video_ssrc_peer_temp = ssrc;
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Peer video fallback SSRC: %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_temp);
			}
			return 0;
		}
		if(stream->video_ssrc_peer_new[0] == 0) {
			stream->video_ssrc_peer_new[0] = ssrc;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC: %"SCNu32"\n", handle->handle_id, stream->video_ssrc_peer_new[0]);
		}
	} else {
		if(stream->audio_ssrc_peer_new == 0) {
			stream->audio_ssrc_peer_new = ssrc;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer audio SSRC: %"SCNu32"\n", handle->handle_id, stream->audio_ssrc_peer_new);
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
			if(m->proto != NULL && (!strcasecmp(m->proto, "DTLS/SCTP") || !strcasecmp(m->proto, "UDP/DTLS/SCTP"))) {
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
			if(!a->name) {
				tempA = tempA->next;
				continue;
			}
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
					|| !strcasecmp(a->name, "simulcast")
					|| !strcasecmp(a->name, "rtcp")
					|| !strcasecmp(a->name, "rtcp-mux")
					|| !strcasecmp(a->name, "rtcp-rsize")
					|| !strcasecmp(a->name, "candidate")
					|| !strcasecmp(a->name, "end-of-candidates")
					|| !strcasecmp(a->name, "ssrc")
					|| !strcasecmp(a->name, "ssrc-group")
					|| !strcasecmp(a->name, "sctpmap")
					|| !strcasecmp(a->name, "sctp-port")
					|| !strcasecmp(a->name, "max-message-size")) {
				m->attributes = g_list_remove(m->attributes, a);
				tempA = m->attributes;
				janus_sdp_attribute_destroy(a);
				continue;
			}
			tempA = tempA->next;
		}
		/* We don't support encrypted RTP extensions yet, so get rid of them */
		tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->value && strstr(a->value, JANUS_RTP_EXTMAP_ENCRYPTED)) {
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
				if(ptype < 0) {
					JANUS_LOG(LOG_ERR, "Invalid payload type (%d)\n", ptype);
				} else {
					JANUS_LOG(LOG_VERB, "Will remove payload type %d (%s)\n", ptype, a->value);
					purged_ptypes = g_list_append(purged_ptypes, GINT_TO_POINTER(ptype));
				}
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

char *janus_sdp_merge(void *ice_handle, janus_sdp *anon, gboolean offer) {
	if(ice_handle == NULL || anon == NULL)
		return NULL;
	janus_ice_handle *handle = (janus_ice_handle *)ice_handle;
	janus_ice_stream *stream = handle->stream;
	if(stream == NULL)
		return NULL;
	char *rtp_profile = handle->rtp_profile ? handle->rtp_profile : (char *)"UDP/TLS/RTP/SAVPF";
	if(!janus_is_webrtc_encryption_enabled())
		rtp_profile = (char *)"RTP/AVPF";
	gboolean ipv4 = !strstr(janus_get_public_ip(0), ":");
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
	anon->o_addr = g_strdup(janus_get_public_ip(0));
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
	/* Iterate on available media */
	int audio = 0;
	int video = 0;
#ifdef HAVE_SCTP
	int data = 0;
#endif
	GList *temp = anon->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		if(m->type == JANUS_SDP_AUDIO) {
			audio++;
			if(audio == 1) {
				g_snprintf(buffer_part, sizeof(buffer_part),
					" %s", handle->audio_mid ? handle->audio_mid : "audio");
				g_strlcat(buffer, buffer_part, sizeof(buffer));
			}
		} else if(m->type == JANUS_SDP_VIDEO) {
			video++;
			if(video == 1) {
				g_snprintf(buffer_part, sizeof(buffer_part),
					" %s", handle->video_mid ? handle->video_mid : "video");
				g_strlcat(buffer, buffer_part, sizeof(buffer));
			}
#ifdef HAVE_SCTP
		} else if(m->type == JANUS_SDP_APPLICATION) {
			if(m->proto && (!strcasecmp(m->proto, "DTLS/SCTP") || !strcasecmp(m->proto, "UDP/DTLS/SCTP")))
				data++;
			if(data == 1) {
				g_snprintf(buffer_part, sizeof(buffer_part),
					" %s", handle->data_mid ? handle->data_mid : "data");
				g_strlcat(buffer, buffer_part, sizeof(buffer));
			}
#endif
		}
		temp = temp->next;
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
		m->c_addr = g_strdup(janus_get_public_ip(0));
		/* Check if we need to refuse the media or not */
		if(m->type == JANUS_SDP_AUDIO) {
			audio++;
			/* Audio */
			if(audio > 1) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping audio line (we have one already)\n", handle->handle_id);
				m->port = 0;
			}
			if(m->port == 0) {
				m->direction = JANUS_SDP_INACTIVE;
				stream->audio_ssrc = 0;
			}
			if(audio == 1) {
				switch(m->direction) {
					case JANUS_SDP_INACTIVE:
						stream->audio_send = FALSE;
						stream->audio_recv = FALSE;
						break;
					case JANUS_SDP_SENDONLY:
						stream->audio_send = TRUE;
						stream->audio_recv = FALSE;
						break;
					case JANUS_SDP_RECVONLY:
						stream->audio_send = FALSE;
						stream->audio_recv = TRUE;
						break;
					case JANUS_SDP_SENDRECV:
					case JANUS_SDP_DEFAULT:
					default:
						stream->audio_send = TRUE;
						stream->audio_recv = TRUE;
						break;
				}
			}
		} else if(m->type == JANUS_SDP_VIDEO) {
			video++;
			/* Video */
			if(video > 1) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping video line (we have one already)\n", handle->handle_id);
				m->port = 0;
			}
			if(m->port == 0) {
				m->direction = JANUS_SDP_INACTIVE;
				stream->video_ssrc = 0;
			}
			if(video == 1) {
				switch(m->direction) {
					case JANUS_SDP_INACTIVE:
						stream->video_send = FALSE;
						stream->video_recv = FALSE;
						break;
					case JANUS_SDP_SENDONLY:
						stream->video_send = TRUE;
						stream->video_recv = FALSE;
						break;
					case JANUS_SDP_RECVONLY:
						stream->video_send = FALSE;
						stream->video_recv = TRUE;
						break;
					case JANUS_SDP_SENDRECV:
					case JANUS_SDP_DEFAULT:
					default:
						stream->video_send = TRUE;
						stream->video_recv = TRUE;
						break;
				}
				if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
					/* Add RFC4588 stuff */
					if(stream->rtx_payload_types && g_hash_table_size(stream->rtx_payload_types) > 0) {
						janus_sdp_attribute *a = NULL;
						GList *ptypes = g_list_copy(m->ptypes), *tempP = ptypes;
						while(tempP) {
							int ptype = GPOINTER_TO_INT(tempP->data);
							int rtx_ptype = GPOINTER_TO_INT(g_hash_table_lookup(stream->rtx_payload_types, GINT_TO_POINTER(ptype)));
							if(rtx_ptype > 0) {
								m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(rtx_ptype));
								a = janus_sdp_attribute_create("rtpmap", "%d rtx/90000", rtx_ptype);
								m->attributes = g_list_append(m->attributes, a);
								a = janus_sdp_attribute_create("fmtp", "%d apt=%d", rtx_ptype, ptype);
								m->attributes = g_list_append(m->attributes, a);
							}
							tempP = tempP->next;
						}
						g_list_free(ptypes);
					}
				}
			}
#ifdef HAVE_SCTP
		} else if(m->type == JANUS_SDP_APPLICATION) {
			/* Is this SCTP for DataChannels? */
			if(m->port > 0 && (!strcasecmp(m->proto, "DTLS/SCTP") || !strcasecmp(m->proto, "UDP/DTLS/SCTP"))) {
				/* Yep */
				data++;
				if(data > 1) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping SCTP line (we have one already)\n", handle->handle_id);
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
		if(m->type == JANUS_SDP_AUDIO && audio == 1) {
			a = janus_sdp_attribute_create("mid", "%s", handle->audio_mid);
			m->attributes = g_list_insert_before(m->attributes, first, a);
		} else if(m->type == JANUS_SDP_VIDEO && video == 1) {
			a = janus_sdp_attribute_create("mid", "%s", handle->video_mid);
			m->attributes = g_list_insert_before(m->attributes, first, a);
#ifdef HAVE_SCTP
		} else if(m->type == JANUS_SDP_APPLICATION && data == 1) {
			if(!strcasecmp(m->proto, "UDP/DTLS/SCTP"))
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP);
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP)) {
				a = janus_sdp_attribute_create("sctpmap", "5000 webrtc-datachannel 16");
				m->attributes = g_list_insert_before(m->attributes, first, a);
			} else {
				a = janus_sdp_attribute_create("sctp-port", "5000");
				m->attributes = g_list_insert_before(m->attributes, first, a);
			}
			a = janus_sdp_attribute_create("mid", "%s", handle->data_mid);
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
		if(janus_is_webrtc_encryption_enabled()) {
			a = janus_sdp_attribute_create("fingerprint", "sha-256 %s", janus_dtls_get_local_fingerprint());
			m->attributes = g_list_insert_before(m->attributes, first, a);
			a = janus_sdp_attribute_create("setup", "%s", janus_get_dtls_srtp_role(offer ? JANUS_DTLS_ROLE_ACTPASS : stream->dtls_role));
			m->attributes = g_list_insert_before(m->attributes, first, a);
		}
		/* Add last attributes, rtcp and ssrc (msid) */
		if(m->type == JANUS_SDP_VIDEO && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
				(m->direction == JANUS_SDP_DEFAULT || m->direction == JANUS_SDP_SENDRECV || m->direction == JANUS_SDP_SENDONLY)) {
			/* Add FID group to negotiate the RFC4588 stuff */
			a = janus_sdp_attribute_create("ssrc-group", "FID %"SCNu32" %"SCNu32, stream->video_ssrc, stream->video_ssrc_rtx);
			m->attributes = g_list_append(m->attributes, a);
		}
		if(m->type == JANUS_SDP_AUDIO) {
			a = janus_sdp_attribute_create("msid", "janus janusa0");
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" cname:janus", stream->audio_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" msid:janus janusa0", stream->audio_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" mslabel:janus", stream->audio_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" label:janusa0", stream->audio_ssrc);
			m->attributes = g_list_append(m->attributes, a);
		} else if(m->type == JANUS_SDP_VIDEO) {
			a = janus_sdp_attribute_create("msid", "janus janusv0");
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" cname:janus", stream->video_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" msid:janus janusv0", stream->video_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" mslabel:janus", stream->video_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("ssrc", "%"SCNu32" label:janusv0", stream->video_ssrc);
			m->attributes = g_list_append(m->attributes, a);
			if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
				/* Add rtx SSRC group to negotiate the RFC4588 stuff */
				a = janus_sdp_attribute_create("ssrc", "%"SCNu32" cname:janus", stream->video_ssrc_rtx);
				m->attributes = g_list_append(m->attributes, a);
				a = janus_sdp_attribute_create("ssrc", "%"SCNu32" msid:janus janusv0", stream->video_ssrc_rtx);
				m->attributes = g_list_append(m->attributes, a);
				a = janus_sdp_attribute_create("ssrc", "%"SCNu32" mslabel:janus", stream->video_ssrc_rtx);
				m->attributes = g_list_append(m->attributes, a);
				a = janus_sdp_attribute_create("ssrc", "%"SCNu32" label:janusv0", stream->video_ssrc_rtx);
				m->attributes = g_list_append(m->attributes, a);
			}
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
			if(stream->legacy_rid) {
				a = janus_sdp_attribute_create("simulcast", " recv rid=%s", rids);
			} else {
				a = janus_sdp_attribute_create("simulcast", " recv %s", rids);
			}
			m->attributes = g_list_append(m->attributes, a);
		}
		if(!janus_ice_is_full_trickle_enabled()) {
			/* And now the candidates (but only if we're half-trickling) */
			janus_ice_candidates_to_sdp(handle, m, stream->stream_id, 1);
			/* Since we're half-trickling, we need to notify the peer that these are all the
			 * candidates we have for this media stream, via an end-of-candidates attribute:
			 * https://tools.ietf.org/html/draft-ietf-mmusic-trickle-ice-02#section-4.1 */
			janus_sdp_attribute *end = janus_sdp_attribute_create("end-of-candidates", NULL);
			m->attributes = g_list_append(m->attributes, end);
		}
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
