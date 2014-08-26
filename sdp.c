/*! \file    sdp.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SDP processing
 * \details  Implementation (based on the Sofia-SDP stack) of the SDP
 * parser/merger/generator in the gateway. Each SDP coming from peers is
 * stripped/anonymized before it is passed to the plugins: all
 * DTLS/ICE/transport related information is removed, only leaving the
 * relevant information in place. SDP coming from plugins is stripped/anonymized
 * as well, and merged with the proper DTLS/ICE/transport information before
 * it is sent to the peers.
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#include "janus.h"
#include "ice.h"
#include "dtls.h"
#include "sdp.h"
#include "utils.h"


static su_home_t *home = NULL;


/* SDP Initialization */
int janus_sdp_init() {
	home = su_home_new(sizeof(su_home_t));
	if(su_home_init(home) < 0) {
		JANUS_LOG(LOG_FATAL, "Ops, error setting up sofia-sdp?\n");
		return -1;
	}
	return 0;
}

void janus_sdp_deinit() {
	su_home_deinit(home);
	su_home_unref(home);
	home = NULL;
}


/* SDP parser */
void janus_sdp_free(janus_sdp *sdp) {
	if(!sdp)
		return;
	sdp_parser_t *parser = (sdp_parser_t *)sdp->parser;
	if(parser)
		sdp_parser_free(parser);
	sdp->parser = NULL;
	sdp->sdp = NULL;
	free(sdp);
	sdp = NULL;
}

/* Pre-parse SDP: is this SDP valid? how many audio/video lines? any features to take into account? */
janus_sdp *janus_sdp_preparse(const char *jsep_sdp, int *audio, int *video, int *data, int *bundle, int *rtcpmux, int *trickle) {
	if(!jsep_sdp || !audio || !video || !data || !bundle || !rtcpmux || !trickle) {
		JANUS_LOG(LOG_ERR, "  Can't preparse, invalid arduments\n");
		return NULL;
	}
	sdp_parser_t *parser = sdp_parse(home, jsep_sdp, strlen(jsep_sdp), 0);
	sdp_session_t *parsed_sdp = sdp_session(parser);
	if(!parsed_sdp) {
		JANUS_LOG(LOG_ERR, "  Error parsing SDP? %s\n", sdp_parsing_error(parser));
		sdp_parser_free(parser);
		/* Invalid SDP */
		return NULL;
	}
	sdp_media_t *m = parsed_sdp->sdp_media;
	while(m) {
		if(m->m_type == sdp_media_audio && m->m_port > 0) {
			*audio = *audio + 1;
		} else if(m->m_type == sdp_media_video && m->m_port > 0) {
			*video = *video + 1;
		}
		m = m->m_next;
	}
#ifdef HAVE_SCTP
	*data = (strstr(jsep_sdp, "DTLS/SCTP") && !strstr(jsep_sdp, "0 DTLS/SCTP")) ? 1 : 0;	/* FIXME This is a really hacky way of checking... */
#else
	*data = 0;
#endif
	*bundle = strstr(jsep_sdp, "a=group:BUNDLE") ? 1 : 0;	/* FIXME This is a really hacky way of checking... */
	*rtcpmux = strstr(jsep_sdp, "a=rtcp-mux") ? 1 : 0;	/* FIXME Should we make this check per-medium? */
	*trickle = strstr(jsep_sdp, "a=candidate") ? 0 : 1;	/* FIXME This is a really hacky way of checking... */
	janus_sdp *sdp = (janus_sdp *)calloc(1, sizeof(janus_sdp));
	if(sdp == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}

	sdp->parser = parser;
	sdp->sdp = parsed_sdp;
	return sdp;
}

/* Parse SDP */
int janus_sdp_parse(janus_ice_handle *handle, janus_sdp *sdp) {
	if(!handle || !sdp)
		return -1;
	sdp_session_t *remote_sdp = (sdp_session_t *)sdp->sdp;
	if(!remote_sdp)
		return -1;
	janus_ice_stream *stream = NULL;
	gchar *ruser = NULL, *rpass = NULL, *rhashing = NULL, *rfingerprint = NULL;
	int audio = 0, video = 0;
#ifdef HAVE_SCTP
	int data = 0;
#endif
	/* Ok, let's start */
	sdp_attribute_t *a = remote_sdp->sdp_attributes;
	while(a) {
		if(a->a_name) {
			if(!strcasecmp(a->a_name, "fingerprint")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Fingerprint (global) : %s\n", handle->handle_id, a->a_value);
				if(strcasestr(a->a_value, "sha-256 ") == a->a_value) {
					rhashing = g_strdup("sha-256");
					rfingerprint = g_strdup(a->a_value + strlen("sha-256 "));
				} else if(strcasestr(a->a_value, "sha-1 ") == a->a_value) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-1 instead of sha-256), but that's ok\n", handle->handle_id);
					rhashing = g_strdup("sha-1");
					rfingerprint = g_strdup(a->a_value + strlen("sha-1 "));
				} else {
					/* FIXME We should handle this somehow anyway... OpenSSL supports them all */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-256/sha-1), *NOT* cool\n", handle->handle_id);
				}
			} else if(!strcasecmp(a->a_name, "ice-ufrag")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE ufrag (global):   %s\n", handle->handle_id, a->a_value);
				ruser = g_strdup(a->a_value);
			} else if(!strcasecmp(a->a_name, "ice-pwd")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE pwd (global):     %s\n", handle->handle_id, a->a_value);
				rpass = g_strdup(a->a_value);
			}
		}
		a = a->a_next;
	}
	sdp_media_t *m = remote_sdp->sdp_media;
	while(m) {
		/* What media type is this? */
		if(m->m_type == sdp_media_audio && m->m_port > 0) {
			audio++;
			if(audio > 1) {
				m = m->m_next;
				continue;
			}
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsing audio candidates (stream=%d)...\n", handle->handle_id, handle->audio_id);
			stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->audio_id));
		} else if(m->m_type == sdp_media_video && m->m_port > 0) {
			video++;
			if(video > 1) {
				m = m->m_next;
				continue;
			}
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsing video candidates (stream=%d)...\n", handle->handle_id, handle->video_id);
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
				stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->video_id));
			} else {
				gint id = handle->audio_id > 0 ? handle->audio_id : handle->video_id;
				stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
			}
#ifdef HAVE_SCTP
		} else if(m->m_type == sdp_media_application) {
			/* Is this SCTP for DataChannels? */
			if(m->m_proto_name != NULL && !strcasecmp(m->m_proto_name, "DTLS/SCTP") && m->m_port > 0) {
				/* Yep */
				data++;
				if(data > 1) {
					m = m->m_next;
					continue;
				}
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Parsing SCTP candidates (stream=%d)...\n", handle->handle_id, handle->video_id);
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
					stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->data_id));
				} else {
					gint id = handle->audio_id > 0 ? handle->audio_id : (handle->video_id > 0 ? handle->video_id : handle->data_id);
					stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
				}
				if(stream == NULL) {
					JANUS_LOG(LOG_WARN, "No valid stream for data??\n");
					continue;
				}
			}
#endif
		} else {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping unsupported media line...\n", handle->handle_id);
			m = m->m_next;
			continue;
		}
		/* Look for ICE credentials and fingerprint first: check media attributes */
		a = m->m_attributes;
		while(a) {
			if(a->a_name) {
				if(!strcasecmp(a->a_name, "fingerprint")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Fingerprint (local) : %s\n", handle->handle_id, a->a_value);
					if(strcasestr(a->a_value, "sha-256 ") == a->a_value) {
						if(rhashing)
							g_free(rhashing);	/* FIXME We're overwriting the global one, if any */
						rhashing = g_strdup("sha-256");
						if(rfingerprint)
							g_free(rfingerprint);	/* FIXME We're overwriting the global one, if any */
						rfingerprint = g_strdup(a->a_value + strlen("sha-256 "));
					} else if(strcasestr(a->a_value, "sha-1 ") == a->a_value) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-1 instead of sha-256), but that's ok\n", handle->handle_id);
						if(rhashing)
							g_free(rhashing);	/* FIXME We're overwriting the global one, if any */
						rhashing = g_strdup("sha-1");
						if(rfingerprint)
							g_free(rfingerprint);	/* FIXME We're overwriting the global one, if any */
						rfingerprint = g_strdup(a->a_value + strlen("sha-1 "));
					} else {
						/* FIXME We should handle this somehow anyway... OpenSSL supports them all */
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]  Hashing algorithm not the one we expected (sha-256), *NOT* cool\n", handle->handle_id);
					}
				} else if(!strcasecmp(a->a_name, "setup")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] DTLS setup (local):  %s\n", handle->handle_id, a->a_value);
					if(!strcasecmp(a->a_value, "actpass") || !strcasecmp(a->a_value, "passive"))
						stream->dtls_role = JANUS_DTLS_ROLE_CLIENT;
					else if(!strcasecmp(a->a_value, "active"))
						stream->dtls_role = JANUS_DTLS_ROLE_SERVER;
					/* TODO Handle holdconn... */
				} else if(!strcasecmp(a->a_name, "ice-ufrag")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE ufrag (local):   %s\n", handle->handle_id, a->a_value);
					if(ruser)
						g_free(ruser);	/* FIXME We're overwriting the global one, if any */
					ruser = g_strdup(a->a_value);
				} else if(!strcasecmp(a->a_name, "ice-pwd")) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE pwd (local):     %s\n", handle->handle_id, a->a_value);
					if(rpass)
						g_free(rpass);	/* FIXME We're overwriting the global one, if any */
					rpass = g_strdup(a->a_value);
				}
			}
			a = a->a_next;
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
		/* FIXME We're replacing the fingerprint info, assuming it's going to be the same for all media */
		if(handle->remote_hashing != NULL)
			g_free(handle->remote_hashing);
		handle->remote_hashing = g_strdup(rhashing);
		if(handle->remote_fingerprint != NULL)
			g_free(handle->remote_fingerprint);
		handle->remote_fingerprint = g_strdup(rfingerprint);
		/* Store the ICE username and password for this stream */
		if(stream->ruser != NULL)
			g_free(stream->ruser);
		stream->ruser = g_strdup(ruser);
		if(stream->rpass != NULL)
			g_free(stream->rpass);
		stream->rpass = g_strdup(rpass);
		/* Now look for candidates and other info */
		a = m->m_attributes;
		while(a) {
			if(a->a_name) {
				if(!strcasecmp(a->a_name, "candidate")) {
					if(m->m_type == sdp_media_video && handle->audio_id > 0 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] This is a video candidate but we're bundling, ignoring...\n", handle->handle_id);
#ifdef HAVE_SCTP
					} else if(m->m_type == sdp_media_application && (handle->audio_id > 0 || handle->video_id > 0) && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] This is a SCTP candidate but we're bundling, ignoring...\n", handle->handle_id);
#endif
					} else {
						int res = janus_sdp_parse_candidate(stream, (const char *)a->a_value, 0);
						if(res != 0) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse candidate... (%d)\n", handle->handle_id, res);
						}
					}
				}
				if(!strcasecmp(a->a_name, "ssrc")) {
					int res = janus_sdp_parse_ssrc(stream, (const char *)a->a_value, m->m_type == sdp_media_video);
					if(res != 0) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse SSRC attribute... (%d)\n", handle->handle_id, res);
					}
				}
#ifdef HAVE_SCTP
				if(!strcasecmp(a->a_name, "sctpmap")) {
					/* TODO Parse sctpmap line to get the UDP-port value and the number of channels */
					JANUS_LOG(LOG_VERB, "Got a sctpmap attribute: %s\n", a->a_value);
				}
#endif
			}
			a = a->a_next;
		}
		m = m->m_next;
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

int janus_sdp_parse_candidate(janus_ice_stream *stream, const char *candidate, int trickle) {
	if(stream == NULL || candidate == NULL)
		return -1;
	janus_ice_handle *handle = stream->handle;
	if(handle == NULL)
		return -2;
	janus_mutex_lock(&handle->mutex);
	janus_ice_component *component = NULL;
	char rfoundation[32], rtransport[4], rip[24], rtype[6], rrelip[24];
	guint32 rcomponent, rpriority, rport, rrelport;
	int res = 0;
	if((res = sscanf(candidate, "%31s %30u %3s %30u %23s %30u typ %5s %*s %23s %*s %30u",
		rfoundation, &rcomponent, rtransport, &rpriority,
			rip, &rport, rtype, rrelip, &rrelport)) >= 7) {
		/* Add remote candidate */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Adding remote candidate for component %d to stream %d\n", handle->handle_id, rcomponent, stream->stream_id);
		component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(rcomponent));
		if(component == NULL) {
			if(rcomponent == 2 && !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] No such component %d in stream %d?\n", handle->handle_id, rcomponent, stream->stream_id);
		} else {
			if(rcomponent == 2 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping component %d in stream %d (rtcp-muxing)\n", handle->handle_id, rcomponent, stream->stream_id);
				janus_mutex_unlock(&handle->mutex);
				return 0;
			}
			if(trickle) {
				if(component->dtls != NULL) {
					/* This component is already ready, ignore this further candidate */
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Ignoring this candidate, the component is already ready\n", handle->handle_id);
					janus_mutex_unlock(&handle->mutex);
					return 0;
				}
			}
			component->component_id = rcomponent;
			component->stream_id = stream->stream_id;
			NiceCandidate *c = NULL;
			if(!strcasecmp(rtype, "host")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Adding host candidate... %s:%d\n", handle->handle_id, rip, rport);
				/* We only support UDP... */
				if(strcasecmp(rtransport, "udp")) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]    Unsupported transport %s!\n", handle->handle_id, rtransport);
				} else {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
				}
			} else if(!strcasecmp(rtype, "srflx")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Adding srflx candidate... %s:%d --> %s:%d \n", handle->handle_id, rrelip, rrelport, rip, rport);
				/* We only support UDP... */
				if(strcasecmp(rtransport, "udp")) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]    Unsupported transport %s!\n", handle->handle_id, rtransport);
				} else {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
				}
			} else if(!strcasecmp(rtype, "prflx")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Adding prflx candidate... %s:%d --> %s:%d\n", handle->handle_id, rrelip, rrelport, rip, rport);
				/* We only support UDP... */
				if(strcasecmp(rtransport, "udp")) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]    Unsupported transport %s!\n", handle->handle_id, rtransport);
				} else {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
				}
			} else if(!strcasecmp(rtype, "relay")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Adding relay candidate... %s:%d --> %s:%d\n", handle->handle_id, rrelip, rrelport, rip, rport);
				/* We only support UDP/TCP/TLS... */
				if(strcasecmp(rtransport, "udp") && strcasecmp(rtransport, "tcp") && strcasecmp(rtransport, "tls")) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]    Unsupported transport %s!\n", handle->handle_id, rtransport);
				} else {
					c = nice_candidate_new(NICE_CANDIDATE_TYPE_RELAYED);
				}
			} else {
				/* FIXME What now? */
				JANUS_LOG(LOG_ERR, "[%"SCNu64"]  Unknown candidate type %s!\n", handle->handle_id, rtype);
			}
			if(c != NULL) {
				c->component_id = rcomponent;
				c->stream_id = stream->stream_id;
				c->transport = NICE_CANDIDATE_TRANSPORT_UDP;
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
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]    Candidate added to the list! (%u elements for %d/%d)\n", handle->handle_id,
					g_slist_length(component->candidates), stream->stream_id, component->component_id);
				/* Save for the summary, in case we need it */
				component->remote_candidates = g_slist_append(component->remote_candidates, g_strdup(candidate));
				if(trickle && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START)) {
					/* This is a trickle candidate and ICE has started, we should process it right away */
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE_SYNCED)) {
						/* Actually, ICE has JUST started, take care of the candidates we've added so far */
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE_SYNCED);
						JANUS_LOG(LOG_INFO, "ICE started and trickling, sending connectivity checks for candidates retrieved so far...\n");
						if(handle->audio_id > 0) {
							janus_ice_setup_remote_candidates(handle, handle->audio_id, 1);
							if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))	/* http://tools.ietf.org/html/rfc5761#section-5.1.3 */
								janus_ice_setup_remote_candidates(handle, handle->audio_id, 2);
						}
						if(handle->video_id > 0) {
							janus_ice_setup_remote_candidates(handle, handle->video_id, 1);
							if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))	/* http://tools.ietf.org/html/rfc5761#section-5.1.3 */
								janus_ice_setup_remote_candidates(handle, handle->video_id, 2);
						}
					}
					GSList *candidates = NULL;
					candidates = g_slist_append(candidates, c);
					if (nice_agent_set_remote_candidates(handle->agent, stream->stream_id, component->component_id, candidates) < 1) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to add trickle candidate :-(\n", handle->handle_id);
					} else {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Trickle candidate added!\n", handle->handle_id);
					}
					g_slist_free(candidates);
				}
			}
		}
	} else {
		janus_mutex_unlock(&handle->mutex);
		return res;
	}
	janus_mutex_unlock(&handle->mutex);
	return 0;
}

int janus_sdp_parse_ssrc(janus_ice_stream *stream, const char *ssrc_attr, int video) {
	if(stream == NULL || ssrc_attr == NULL)
		return -1;
	janus_ice_handle *handle = stream->handle;
	if(handle == NULL)
		return -2;
	gint64 ssrc = atoll(ssrc_attr);
	if(ssrc == 0)
		return -3;
	if(video) {
		if(stream->video_ssrc_peer == 0) {
			stream->video_ssrc_peer = ssrc;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer video SSRC: %u\n", handle->handle_id, stream->video_ssrc_peer);
		}
	} else {
		if(stream->audio_ssrc_peer == 0) {
			stream->audio_ssrc_peer = ssrc;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Peer audio SSRC: %u\n", handle->handle_id, stream->audio_ssrc_peer);
		}
	}
	return 0;
}

char *janus_sdp_anonymize(const char *sdp) {
	if(sdp == NULL)
		return NULL;
	sdp_session_t *anon = NULL;
	sdp_parser_t *parser = sdp_parse(home, sdp, strlen(sdp), 0);
	if(!(anon = sdp_session(parser))) {
		JANUS_LOG(LOG_ERR, "Error parsing/merging SDP: %s\n", sdp_parsing_error(parser));
		return NULL;
	}
	/* c= */
	if(anon->sdp_connection && anon->sdp_connection->c_address) {
		anon->sdp_connection->c_address = "1.1.1.1";
	}
	/* a= */
	if(anon->sdp_attributes) {
		/* These are attributes we handle ourselves, the plugins don't need them */
		while(sdp_attribute_find(anon->sdp_attributes, "ice-ufrag"))
			sdp_attribute_remove(&anon->sdp_attributes, "ice-ufrag");
		while(sdp_attribute_find(anon->sdp_attributes, "ice-pwd"))
			sdp_attribute_remove(&anon->sdp_attributes, "ice-pwd");
		while(sdp_attribute_find(anon->sdp_attributes, "ice-options"))
			sdp_attribute_remove(&anon->sdp_attributes, "ice-options");
		while(sdp_attribute_find(anon->sdp_attributes, "fingerprint"))
			sdp_attribute_remove(&anon->sdp_attributes, "fingerprint");
		while(sdp_attribute_find(anon->sdp_attributes, "group"))
			sdp_attribute_remove(&anon->sdp_attributes, "group");
		while(sdp_attribute_find(anon->sdp_attributes, "msid-semantic"))
			sdp_attribute_remove(&anon->sdp_attributes, "msid-semantic");
	}
		/* m= */
	int a_sendrecv = 0, v_sendrecv = 0;
	if(anon->sdp_media) {
		int audio = 0, video = 0;
#ifdef HAVE_SCTP
		int data = 0;
#endif
		sdp_media_t *m = anon->sdp_media;
		while(m) {
			if(m->m_type == sdp_media_audio && m->m_port > 0) {
				audio++;
				m->m_port = audio == 1 ? 1 : 0;
			} else if(m->m_type == sdp_media_video && m->m_port > 0) {
				video++;
				m->m_port = video == 1 ? 1 : 0;
#ifdef HAVE_SCTP
			} else if(m->m_type == sdp_media_application) {
				if(m->m_proto_name != NULL && !strcasecmp(m->m_proto_name, "DTLS/SCTP") && m->m_port != 0) {
					data++;
					m->m_port = data == 1 ? 1 : 0;
				} else {
					m->m_port = 0;
				}
#endif
			} else {
				m->m_port = 0;
			}
				/* c= */
			if(m->m_connections) {
				sdp_connection_t *c = m->m_connections;
				while(c) {
					if(c->c_address) {
						c->c_address = "1.1.1.1";
					}
					c = c->c_next;
				}
			}
				/* a= */
			if(m->m_attributes) {
				/* These are attributes we handle ourselves, the plugins don't need them */
				while(sdp_attribute_find(m->m_attributes, "ice-ufrag"))
					sdp_attribute_remove(&m->m_attributes, "ice-ufrag");
				while(sdp_attribute_find(m->m_attributes, "ice-pwd"))
					sdp_attribute_remove(&m->m_attributes, "ice-pwd");
				while(sdp_attribute_find(m->m_attributes, "ice-options"))
					sdp_attribute_remove(&m->m_attributes, "ice-options");
				while(sdp_attribute_find(m->m_attributes, "crypto"))
					sdp_attribute_remove(&m->m_attributes, "crypto");
				while(sdp_attribute_find(m->m_attributes, "fingerprint"))
					sdp_attribute_remove(&m->m_attributes, "fingerprint");
				while(sdp_attribute_find(m->m_attributes, "setup"))
					sdp_attribute_remove(&m->m_attributes, "setup");
				while(sdp_attribute_find(m->m_attributes, "connection"))
					sdp_attribute_remove(&m->m_attributes, "connection");
				while(sdp_attribute_find(m->m_attributes, "group"))
					sdp_attribute_remove(&m->m_attributes, "group");
				while(sdp_attribute_find(m->m_attributes, "mid"))
					sdp_attribute_remove(&m->m_attributes, "mid");
				while(sdp_attribute_find(m->m_attributes, "msid-semantic"))
					sdp_attribute_remove(&m->m_attributes, "msid-semantic");
				while(sdp_attribute_find(m->m_attributes, "rtcp"))
					sdp_attribute_remove(&m->m_attributes, "rtcp");
				while(sdp_attribute_find(m->m_attributes, "rtcp-mux"))
					sdp_attribute_remove(&m->m_attributes, "rtcp-mux");
				while(sdp_attribute_find(m->m_attributes, "candidate"))
					sdp_attribute_remove(&m->m_attributes, "candidate");
				while(sdp_attribute_find(m->m_attributes, "ssrc"))
					sdp_attribute_remove(&m->m_attributes, "ssrc");
				while(sdp_attribute_find(m->m_attributes, "extmap"))	/* TODO Actually implement RTP extensions */
					sdp_attribute_remove(&m->m_attributes, "extmap");
				while(sdp_attribute_find(m->m_attributes, "sctpmap"))
					sdp_attribute_remove(&m->m_attributes, "sctpmap");
			}
			/* FIXME sendrecv hack: sofia-sdp doesn't print sendrecv, but we want it to */
			if(m->m_mode == sdp_sendrecv) {
				m->m_mode = sdp_inactive;
				if(m->m_type == sdp_media_audio)
					a_sendrecv = 1;
				else if(m->m_type == sdp_media_video)
					v_sendrecv = 1;
			}
			m = m->m_next;
		}
	}
	char buf[BUFSIZE];
	sdp_printer_t *printer = sdp_print(home, anon, buf, BUFSIZE, 0);
	if(sdp_message(printer)) {
		int retval = sdp_message_size(printer);
		sdp_printer_free(printer);
		/* FIXME Take care of the sendrecv hack */
		if(a_sendrecv || v_sendrecv) {
			char *replace = strstr(buf, "a=inactive");
			while(replace != NULL) {
				memcpy(replace, "a=sendrecv", strlen("a=sendrecv"));
				replace++;
				replace = strstr(replace, "a=inactive");
			}
		}
		JANUS_LOG(LOG_VERB, " -------------------------------------------\n");
		JANUS_LOG(LOG_VERB, "  >> Anonymized (%zu --> %d bytes)\n", strlen(sdp), retval);
		JANUS_LOG(LOG_VERB, " -------------------------------------------\n");
		JANUS_LOG(LOG_VERB, "%s\n", buf);
		return g_strdup(buf);
	} else {
		JANUS_LOG(LOG_ERR, "Error anonymizing SDP: %s\n", sdp_printing_error(printer));
		return NULL;
	}
}

char *janus_sdp_merge(janus_ice_handle *handle, const char *origsdp) {
	if(handle == NULL || origsdp == NULL)
		return NULL;
	sdp_session_t *anon = NULL;
	sdp_parser_t *parser = sdp_parse(home, origsdp, strlen(origsdp), 0);
	if(!(anon = sdp_session(parser))) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error parsing/merging SDP: %s\n", handle->handle_id, sdp_parsing_error(parser));
		return NULL;
	}
	/* Prepare SDP to merge */
	gchar buffer[512];
	memset(buffer, 0, 512);
	char *sdp = (char*)calloc(BUFSIZE, sizeof(char));
	if(sdp == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	sdp[0] = '\0';
	/* FIXME Any Plan B to take into account? */
	int planb = strstr(origsdp, "a=planb:") ? 1 : 0;
	if(planb) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B);
	}
	/* Version v= */
	g_strlcat(sdp,
		"v=0\r\n", BUFSIZE);
	/* Origin o= */
	if(anon->sdp_origin) {
		g_sprintf(buffer,
			"o=%s %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n",	/* FIXME Should we fix the address? */
				anon->sdp_origin->o_username ? anon->sdp_origin->o_username : "-",
				anon->sdp_origin->o_id, anon->sdp_origin->o_version);
		g_strlcat(sdp, buffer, BUFSIZE);
	} else {
		gint64 sessid = janus_get_monotonic_time();
		gint64 version = sessid;	/* FIXME This needs to be increased when it changes, so time should be ok */
		g_sprintf(buffer,
			"o=%s %"SCNi64" %"SCNi64" IN IP4 127.0.0.1\r\n",	/* FIXME Should we fix the address? */
				"-", sessid, version);
		g_strlcat(sdp, buffer, BUFSIZE);
	}
	/* Session name s= */
	g_sprintf(buffer,
		"s=%s\r\n", anon->sdp_subject ? anon->sdp_subject : "Meetecho Janus");
	g_strlcat(sdp, buffer, BUFSIZE);
	/* Timing t= */
	g_sprintf(buffer,
		"t=%lu %lu\r\n", anon->sdp_time ? anon->sdp_time->t_start : 0, anon->sdp_time ? anon->sdp_time->t_stop : 0);
	g_strlcat(sdp, buffer, BUFSIZE);
	/* bundle: add new global attribute */
	int audio = (strstr(origsdp, "m=audio") != NULL);
	int video = (strstr(origsdp, "m=video") != NULL);
#ifdef HAVE_SCTP
	int data = (strstr(origsdp, "DTLS/SCTP") && !strstr(origsdp, "0 DTLS/SCTP"));
#else
	int data = 0;
#endif
	g_strlcat(sdp, "a=group:BUNDLE", BUFSIZE);
	if(audio)
		g_strlcat(sdp, " audio", BUFSIZE);
	if(video)
		g_strlcat(sdp, " video", BUFSIZE);
	if(data)
		g_strlcat(sdp, " data", BUFSIZE);
	g_strlcat(sdp, "\r\n", BUFSIZE);
	/* msid-semantic: add new global attribute */
	g_strlcat(sdp,
		"a=msid-semantic: WMS janus\r\n",
		BUFSIZE);
	char wms[BUFSIZE];
	memset(wms, 0, BUFSIZE);
	g_strlcat(wms, "WMS", BUFSIZE);
	/* Copy other global attributes, if any */
	if(anon->sdp_attributes) {
		sdp_attribute_t *a = anon->sdp_attributes;
		while(a) {
			if(a->a_value == NULL) {
				g_sprintf(buffer,
					"a=%s\r\n", a->a_name);
				g_strlcat(sdp, buffer, BUFSIZE);
			} else {
				g_sprintf(buffer,
					"a=%s:%s\r\n", a->a_name, a->a_value);
				g_strlcat(sdp, buffer, BUFSIZE);
			}
			a = a->a_next;
		}
	}
	/* Media lines now */
	if(anon->sdp_media) {
		int audio = 0, video = 0;
#ifdef HAVE_SCTP
		int data = 0;
#endif
		sdp_media_t *m = anon->sdp_media;
		janus_ice_stream *stream = NULL;
		while(m) {
			if(m->m_type == sdp_media_audio && m->m_port > 0) {
				audio++;
				if(audio > 1 || !handle->audio_id) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping audio line (we have %d audio lines, and the id is %d)\n", handle->handle_id, audio, handle->audio_id);
					g_strlcat(sdp, "m=audio 0 RTP/SAVPF 0\r\n", BUFSIZE);
					/* FIXME Adding a c-line anyway because otherwise Firefox complains? ("c= connection line not specified for every media level, validation failed") */
					g_sprintf(buffer,
						"c=IN IP4 %s\r\n", janus_get_public_ip());
					g_strlcat(sdp, buffer, BUFSIZE);
					m = m->m_next;
					continue;
				}
				/* Audio */
				stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->audio_id));
				if(stream == NULL) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping audio line (invalid stream %d)\n", handle->handle_id, handle->audio_id);
					g_strlcat(sdp, "m=audio 0 RTP/SAVPF 0\r\n", BUFSIZE);
					/* FIXME Adding a c-line anyway because otherwise Firefox complains? ("c= connection line not specified for every media level, validation failed") */
					g_sprintf(buffer,
						"c=IN IP4 %s\r\n", janus_get_public_ip());
					g_strlcat(sdp, buffer, BUFSIZE);
					m = m->m_next;
					continue;
				}
				g_strlcat(sdp, "m=audio 1 RTP/SAVPF", BUFSIZE);
			} else if(m->m_type == sdp_media_video && m->m_port > 0) {
				video++;
				gint id = handle->video_id;
				if(id == 0 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE))
					id = handle->audio_id > 0 ? handle->audio_id : handle->video_id;
				if(video > 1 || !id) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping video line (we have %d video lines, and the id is %d)\n", handle->handle_id, video,
						janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? handle->audio_id : handle->video_id);
					g_strlcat(sdp, "m=video 0 RTP/SAVPF 0\r\n", BUFSIZE);
					/* FIXME Adding a c-line anyway because otherwise Firefox complains? ("c= connection line not specified for every media level, validation failed") */
					g_sprintf(buffer,
						"c=IN IP4 %s\r\n", janus_get_public_ip());
					g_strlcat(sdp, buffer, BUFSIZE);
					m = m->m_next;
					continue;
				}
				/* Video */
				stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
				if(stream == NULL) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping video line (invalid stream %d)\n", handle->handle_id, id);
					g_strlcat(sdp, "m=video 0 RTP/SAVPF 0\r\n", BUFSIZE);
					/* FIXME Adding a c-line anyway because otherwise Firefox complains? ("c= connection line not specified for every media level, validation failed") */
					g_sprintf(buffer,
						"c=IN IP4 %s\r\n", janus_get_public_ip());
					g_strlcat(sdp, buffer, BUFSIZE);
					m = m->m_next;
					continue;
				}
				g_strlcat(sdp, "m=video 1 RTP/SAVPF", BUFSIZE);
#ifdef HAVE_SCTP
			} else if(m->m_type == sdp_media_application) {
				/* Is this SCTP for DataChannels? */
				if(m->m_port > 0 && m->m_proto_name != NULL && !strcasecmp(m->m_proto_name, "DTLS/SCTP") && m->m_port > 0) {
					/* Yep */
					data++;
					gint id = handle->data_id;
					if(id == 0 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE))
						id = handle->audio_id > 0 ? handle->audio_id : handle->video_id;
					if(data > 1 || !id) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping SCTP line (we have %d SCTP lines, and the id is %d)\n", handle->handle_id, data, id);
						g_sprintf(buffer,
							"m=%s 0 %s 0\r\n",
							m->m_type_name, m->m_proto_name);
						g_strlcat(sdp, buffer, BUFSIZE);
						/* FIXME Adding a c-line anyway because otherwise Firefox complains? ("c= connection line not specified for every media level, validation failed") */
						g_sprintf(buffer,
							"c=IN IP4 %s\r\n", janus_get_public_ip());
						g_strlcat(sdp, buffer, BUFSIZE);
						m = m->m_next;
						continue;
					}
					/* SCTP */
					stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
					if(stream == NULL) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping SCTP line (invalid stream %d)\n", handle->handle_id, id);
						g_sprintf(buffer,
							"m=%s 0 %s 0\r\n",
							m->m_type_name, m->m_proto_name);
						g_strlcat(sdp, buffer, BUFSIZE);
						/* FIXME Adding a c-line anyway because otherwise Firefox complains? ("c= connection line not specified for every media level, validation failed") */
						g_sprintf(buffer,
							"c=IN IP4 %s\r\n", janus_get_public_ip());
						g_strlcat(sdp, buffer, BUFSIZE);
						m = m->m_next;
						continue;
					}
					g_strlcat(sdp, "m=application 1 DTLS/SCTP", BUFSIZE);
				} else {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping unsupported media line...\n", handle->handle_id);
					g_sprintf(buffer,
						"m=%s 0 %s 0\r\n",
						m->m_type_name, m->m_proto_name);
					g_strlcat(sdp, buffer, BUFSIZE);
					m = m->m_next;
					continue;
				}
#endif
			} else {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping unsupported media line...\n", handle->handle_id);
				g_sprintf(buffer,
					"m=%s 0 %s 0\r\n",
					m->m_type_name, m->m_proto_name);
				g_strlcat(sdp, buffer, BUFSIZE);
				/* FIXME Adding a c-line anyway because otherwise Firefox complains? ("c= connection line not specified for every media level, validation failed") */
				g_sprintf(buffer,
					"c=IN IP4 %s\r\n", janus_get_public_ip());
				g_strlcat(sdp, buffer, BUFSIZE);
				m = m->m_next;
				continue;
			}
			/* Add formats now */
			if(!m->m_rtpmaps) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] No RTP maps?? trying formats...\n", handle->handle_id);
				if(!m->m_format) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] No formats either?? this sucks!\n", handle->handle_id);
					g_strlcat(sdp, " 0", BUFSIZE);	/* FIXME Won't work apparently */
				} else {
					sdp_list_t *fmt = m->m_format;
					while(fmt) {
						g_sprintf(buffer, " %s", fmt->l_text);
						g_strlcat(sdp, buffer, BUFSIZE);
						fmt = fmt->l_next;
					}
				}
			} else {
				sdp_rtpmap_t *r = m->m_rtpmaps;
				while(r) {
					g_sprintf(buffer, " %d", r->rm_pt);
					g_strlcat(sdp, buffer, BUFSIZE);
					r = r->rm_next;
				}
			}
			g_strlcat(sdp, "\r\n", BUFSIZE);
			/* a=mid:(audio|video|data) */
			switch(m->m_type) {
				case sdp_media_audio:
					g_sprintf(buffer, "a=mid:audio\r\n");
					break;
				case sdp_media_video:
					g_sprintf(buffer, "a=mid:video\r\n");
					break;
#ifdef HAVE_SCTP
				case sdp_media_application:
					/* FIXME sctpmap and webrtc-datachannel should be dynamic */
					g_sprintf(buffer, "a=mid:data\r\na=sctpmap:5000 webrtc-datachannel 16\r\n");
					break;
#endif
				default:
					break;
			}
			g_strlcat(sdp, buffer, BUFSIZE);
			/* Any bandwidth? */
			if(m->m_bandwidths) {
				g_sprintf(buffer,
					"b=%s:%lu\r\n",	/* FIXME Are we doing this correctly? */
						m->m_bandwidths->b_modifier_name ? m->m_bandwidths->b_modifier_name : "AS",
						m->m_bandwidths->b_value);
				g_strlcat(sdp, buffer, BUFSIZE);
			}
			/* Media connection c= */
			g_sprintf(buffer,
				"c=IN IP4 %s\r\n", janus_get_public_ip());
			g_strlcat(sdp, buffer, BUFSIZE);
			/* What is the direction? */
			switch(m->m_mode) {
				case sdp_sendonly:
					g_strlcat(sdp, "a=sendonly\r\n", BUFSIZE);
					break;
				case sdp_recvonly:
					g_strlcat(sdp, "a=recvonly\r\n", BUFSIZE);
					break;
				case sdp_inactive:
				/*! \note Due to a sofia-sdp bug, when video is the only available
				 * medium and audio is not there, the mode for the video medium is
				 * set to sdp_inactive even when it actually is an 'a=sendrecv'. May
				 * this be caused by the fact that no audio is there, thus implicitly
				 * setting the whole session media to inactive? Anyway, until this
				 * is fixed we assume that an inactive is actually a sendrecv: yeah,
				 * an ugly and bad hack, but we never add an inactive stream in our
				 * JavaScript anyway... */
					JANUS_LOG(LOG_VERB, " *** Turning inactive to sendrecv... ***\n");
					//~ g_strlcat(sdp, "a=inactive\r\n", BUFSIZE);
					//~ break;
				case sdp_sendrecv:
				default:
					g_strlcat(sdp, "a=sendrecv\r\n", BUFSIZE);
					break;
			}
			if(m->m_type != sdp_media_application) {
				/* rtcp-mux */
				g_sprintf(buffer, "a=rtcp-mux\n");
				g_strlcat(sdp, buffer, BUFSIZE);
				/* RTP maps */
				if(m->m_rtpmaps) {
					sdp_rtpmap_t *rm = NULL;
					for(rm = m->m_rtpmaps; rm; rm = rm->rm_next) {
						g_sprintf(buffer, "a=rtpmap:%u %s/%lu%s%s\r\n",
							rm->rm_pt, rm->rm_encoding, rm->rm_rate,
							rm->rm_params ? "/" : "", 
							rm->rm_params ? rm->rm_params : "");
						g_strlcat(sdp, buffer, BUFSIZE);
					}
					for(rm = m->m_rtpmaps; rm; rm = rm->rm_next) {
						if(rm->rm_fmtp) {
							g_sprintf(buffer, "a=fmtp:%u %s\r\n", rm->rm_pt, rm->rm_fmtp);
							g_strlcat(sdp, buffer, BUFSIZE);
						}
					}
				}
			}
			/* ICE ufrag and pwd, DTLS fingerprint setup and connection a= */
			gchar *ufrag = NULL;
			gchar *password = NULL;
			nice_agent_get_local_credentials(handle->agent, stream->stream_id, &ufrag, &password);
			memset(buffer, 0, 100);
			g_sprintf(buffer,
				"a=ice-ufrag:%s\r\n"
				"a=ice-pwd:%s\r\n"
				"a=ice-options:trickle\r\n"
				"a=fingerprint:sha-256 %s\r\n"
				"a=setup:%s\r\n"
				"a=connection:new\r\n",
					ufrag, password,
					janus_dtls_get_local_fingerprint(),
					janus_get_dtls_srtp_role(stream->dtls_role));
			if(ufrag != NULL)
				g_free(ufrag);
			ufrag = NULL;
			if(password != NULL)
				g_free(password);
			password = NULL;
			g_strlcat(sdp, buffer, BUFSIZE);
			/* Copy existing media attributes, if any */
			if(m->m_attributes) {
				sdp_attribute_t *a = m->m_attributes;
				while(a) {
					if(!strcmp(a->a_name, "planb")) {
						/* Skip the fake planb attribute, it's for internal use only */
						a = a->a_next;
						continue;
					}
					if(a->a_value == NULL) {
						g_sprintf(buffer,
							"a=%s\r\n", a->a_name);
						g_strlcat(sdp, buffer, BUFSIZE);
					} else {
						g_sprintf(buffer,
							"a=%s:%s\r\n", a->a_name, a->a_value);
						g_strlcat(sdp, buffer, BUFSIZE);
					}
					a = a->a_next;
				}
			}
			/* Add last attributes, rtcp and ssrc (msid) */
			if(!planb) {
				/* Single SSRC */
				if(m->m_type == sdp_media_audio) {
					g_sprintf(buffer,
						"a=ssrc:%"SCNu32" cname:janusaudio\r\n"
						"a=ssrc:%"SCNu32" msid:janus janusa0\r\n"
						"a=ssrc:%"SCNu32" mslabel:janus\r\n"
						"a=ssrc:%"SCNu32" label:janusa0\r\n",
							stream->audio_ssrc, stream->audio_ssrc, stream->audio_ssrc, stream->audio_ssrc);
					g_strlcat(sdp, buffer, BUFSIZE);
				} else if(m->m_type == sdp_media_video) {
					g_sprintf(buffer,
						"a=ssrc:%"SCNu32" cname:janusvideo\r\n"
						"a=ssrc:%"SCNu32" msid:janus janusv0\r\n"
						"a=ssrc:%"SCNu32" mslabel:janus\r\n"
						"a=ssrc:%"SCNu32" label:janusv0\r\n",
							stream->video_ssrc, stream->video_ssrc, stream->video_ssrc, stream->video_ssrc);
					g_strlcat(sdp, buffer, BUFSIZE);
				}
			} else {
				/* Multiple SSRCs */
				char mslabel[255];
				memset(mslabel, 0, 255);
				if(m->m_attributes) {
					char id[256];
					uint32_t ssrc = 0;
					sdp_attribute_t *a = m->m_attributes;
					while(a) {
						if(a->a_name == NULL || a->a_value == NULL || strcmp(a->a_name, "planb")) {
							a = a->a_next;
							continue;
						}
						if(sscanf(a->a_value, "%255s %"SCNu32"", id, &ssrc) != 2) {
							JANUS_LOG(LOG_ERR, "Error parsing 'planb' attribute, skipping it...\n");
							a = a->a_next;
							continue;
						}
						JANUS_LOG(LOG_VERB, "Parsing 'planb' attribute: %s\n", a->a_value);
						/* Add proper SSRC attributes */
						if(m->m_type == sdp_media_audio) {
							g_sprintf(buffer,
								"a=ssrc:%"SCNu32" cname:%saudio\r\n"
								"a=ssrc:%"SCNu32" msid:%s %sa0\r\n"
								"a=ssrc:%"SCNu32" mslabel:%s\r\n"
								"a=ssrc:%"SCNu32" label:%sa0\r\n",
									ssrc, id, ssrc, id, id, ssrc, id, ssrc, id);
						} else if(m->m_type == sdp_media_video) {
							g_sprintf(buffer,
								"a=ssrc:%"SCNu32" cname:%svideo\r\n"
								"a=ssrc:%"SCNu32" msid:%s %sv0\r\n"
								"a=ssrc:%"SCNu32" mslabel:%s\r\n"
								"a=ssrc:%"SCNu32" label:%sv0\r\n",
									ssrc, id, ssrc, id, id, ssrc, id, ssrc, id);
						}
						g_strlcat(sdp, buffer, BUFSIZE);
						/* Add to msid-semantic, if needed */
						if(!strstr(wms, id)) {
							sprintf(mslabel, " %s", id);
							g_strlcat(wms, mslabel, BUFSIZE);
						}
						/* Go on */
						a = a->a_next;
					}
				}
			}
			/* And now the candidates */
			janus_ice_candidates_to_sdp(handle, sdp, stream->stream_id, 1);
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) &&
					m->m_type != sdp_media_application)
				janus_ice_candidates_to_sdp(handle, sdp, stream->stream_id, 2);
			/* Next */
			m = m->m_next;
		}
	}

	/* Do we need to update the msid-semantic attribute? */
	if(planb) {
		sdp = janus_string_replace(sdp, "WMS janus", wms);
	}
	
	JANUS_LOG(LOG_VERB, " -------------------------------------------\n");
	JANUS_LOG(LOG_VERB, "  >> Merged (%zu --> %zu bytes)\n", strlen(origsdp), strlen(sdp));
	JANUS_LOG(LOG_VERB, " -------------------------------------------\n");
	JANUS_LOG(LOG_VERB, "%s\n", sdp);
	return sdp;
}
