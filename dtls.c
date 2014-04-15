/*! \file    dtls.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU Affero General Public License v3
 * \brief    DTLS/SRTP processing
 * \details  Implementation (based on OpenSSL and libsrtp) of the DTLS/SRTP
 * transport. The code takes care of the DTLS handshake between peers and
 * the gateway, and sets the proper SRTP and SRTCP context up accordingly.
 * A DTLS alert from a peer is notified to the plugin handling him/her
 * by means of the hangup_media callback.
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#include "janus.h"
#include "debug.h"
#include "dtls.h"
#include "rtcp.h"


/* SRTP stuff (http://tools.ietf.org/html/rfc3711) */
static const char *janus_srtp_error[] =
{
	"err_status_ok",
	"err_status_fail",
	"err_status_bad_param",
	"err_status_alloc_fail",
	"err_status_dealloc_fail",
	"err_status_init_fail",
	"err_status_terminus",
	"err_status_auth_fail",
	"err_status_cipher_fail",
	"err_status_replay_fail",
	"err_status_replay_old",
	"err_status_algo_fail",
	"err_status_no_such_op",
	"err_status_no_ctx",
	"err_status_cant_check",
	"err_status_key_expired",
	"err_status_socket_err",
	"err_status_signal_err",
	"err_status_nonce_bad",
	"err_status_read_fail",
	"err_status_write_fail",
	"err_status_parse_err",
	"err_status_encode_err",
	"err_status_semaphore_err",
	"err_status_pfkey_err",
};
const gchar *janus_get_srtp_error(int error) {
	if(error < 0 || error > 24)
		return NULL;
	return janus_srtp_error[error];
}

const gchar *janus_get_dtls_srtp_state(janus_dtls_state state) {
	switch(state) {
		case JANUS_DTLS_STATE_CREATED:
			return "created";
		case JANUS_DTLS_STATE_TRYING:
			return "trying";
		case JANUS_DTLS_STATE_CONNECTED:
			return "connected";
		case JANUS_DTLS_STATE_FAILED:
			return "failed";
		default:
			return NULL;
	}
	return NULL;
}

const gchar *janus_get_dtls_srtp_role(janus_dtls_role role) {
	switch(role) {
		case JANUS_DTLS_ROLE_ACTPASS:
			return "actpass";
		case JANUS_DTLS_ROLE_SERVER:
			return "passive";
		case JANUS_DTLS_ROLE_CLIENT:
			return "active";
		default:
			return NULL;
	}
	return NULL;
}



/* DTLS stuff */
#define DTLS_CIPHERS	"ALL:NULL:eNULL:aNULL"

/* SRTP stuff (http://tools.ietf.org/html/rfc3711) */
#define SRTP_MASTER_KEY_LENGTH	16
#define SRTP_MASTER_SALT_LENGTH	14
#define SRTP_MASTER_LENGTH (SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH)


static SSL_CTX *ssl_ctx = NULL;
SSL_CTX *janus_dtls_get_ssl_ctx() {
	return ssl_ctx;
}
static gchar local_fingerprint[160];
gchar *janus_dtls_get_local_fingerprint() {
	return (gchar *)local_fingerprint;
}

/* DTLS-SRTP initialization */
gint janus_dtls_srtp_init(gchar *server_pem, gchar *server_key) {
	ssl_ctx = SSL_CTX_new(DTLSv1_method());
	if(!ssl_ctx) {
		JANUS_LOG(LOG_FATAL, "Ops, error creating DTLS context?\n");
		return -1;
	}
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, janus_dtls_verify_callback);
	SSL_CTX_set_tlsext_use_srtp(ssl_ctx, "SRTP_AES128_CM_SHA1_80");	/* FIXME Should we support something else as well? */
	if(!server_pem || !SSL_CTX_use_certificate_file(ssl_ctx, server_pem, SSL_FILETYPE_PEM)) {
		JANUS_LOG(LOG_FATAL, "Certificate error, does it exist?\n");
		JANUS_LOG(LOG_FATAL, "  %s\n", server_pem);
		return -2;
	}
	if(!server_key || !SSL_CTX_use_PrivateKey_file(ssl_ctx, server_key, SSL_FILETYPE_PEM)) {
		JANUS_LOG(LOG_FATAL, "Certificate key error, does it exist?\n");
		JANUS_LOG(LOG_FATAL, "  %s\n", server_key);
		return -3;
	}
	if(!SSL_CTX_check_private_key(ssl_ctx)) {
		JANUS_LOG(LOG_FATAL, "Certificate check error...\n");
		return -4;
	}
	BIO *certbio = BIO_new(BIO_s_file());
	if(certbio == NULL) {
		JANUS_LOG(LOG_FATAL, "Certificate BIO error...\n");
		return -5;
	}
	if(BIO_read_filename(certbio, server_pem) == 0) {
		JANUS_LOG(LOG_FATAL, "Error reading certificate...\n");
		BIO_free_all(certbio);
		return -6;
	}
	X509 *cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
	if(cert == NULL) {
		JANUS_LOG(LOG_FATAL, "Error reading certificate...\n");
		BIO_free_all(certbio);
		return -7;
	}
	unsigned int size;
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	if(X509_digest(cert, EVP_sha256(), (unsigned char *)fingerprint, &size) == 0) {
		JANUS_LOG(LOG_FATAL, "Error converting X509 structure...\n");
		X509_free(cert);
		BIO_free_all(certbio);
		return -7;
	}
	char *lfp = (char *)&local_fingerprint;
	int i = 0;
	for(i = 0; i < size; i++) {
		sprintf(lfp, "%.2X:", fingerprint[i]);
		lfp += 3;
	}
	*(lfp-1) = 0;
	JANUS_LOG(LOG_INFO, "Fingerprint of our certificate: %s\n", local_fingerprint);
	X509_free(cert);
	BIO_free_all(certbio);
	SSL_CTX_set_cipher_list(ssl_ctx, DTLS_CIPHERS);

	/* Initialize libsrtp */
	if(srtp_init() != err_status_ok) {
		JANUS_LOG(LOG_FATAL, "Ops, error setting up libsrtp?\n");
		return 5;
	}
	//~ srtp_install_event_handler(srtp_event_cb);
	return 0;
}


janus_dtls_srtp *janus_dtls_srtp_create(void *ice_component, janus_dtls_role role) {
	janus_ice_component *component = (janus_ice_component *)ice_component;
	if(component == NULL) {
		JANUS_LOG(LOG_ERR, "No component, no DTLS...\n");
		return NULL;
	}
	janus_ice_stream *stream = component->stream;
	if(!stream) {
		JANUS_LOG(LOG_ERR, "No stream, no DTLS...\n");
		return NULL;
	}
	janus_ice_handle *handle = stream->handle;
	if(!handle || !handle->agent) {
		JANUS_LOG(LOG_ERR, "No handle/agent, no DTLS...\n");
		return NULL;
	}
	janus_dtls_srtp *dtls = calloc(1, sizeof(janus_dtls_srtp));
	if(dtls == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	/* Create SSL context, at last */
	dtls->srtp_valid = 0;
	dtls->dtls_last_msg = NULL;
	dtls->dtls_last_len = 0;
	dtls->ssl = SSL_new(janus_dtls_get_ssl_ctx());
	if(!dtls->ssl) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component DTLS SSL session??\n", handle->handle_id);
		janus_dtls_srtp_destroy(dtls);
		return NULL;
	}
	SSL_set_ex_data(dtls->ssl, 0, dtls);
	SSL_set_info_callback(dtls->ssl, janus_dtls_callback);
	dtls->read_bio = BIO_new(BIO_s_mem());
	if(!dtls->read_bio) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]   Error creating read BIO!\n", handle->handle_id);
		janus_dtls_srtp_destroy(dtls);
		return NULL;
	}
	BIO_set_mem_eof_return(dtls->read_bio, -1);
	dtls->write_bio = BIO_new(BIO_s_mem());
	if(!dtls->write_bio) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]   Error creating write BIO!\n", handle->handle_id);
		janus_dtls_srtp_destroy(dtls);
		return NULL;
	}
	BIO_set_mem_eof_return(dtls->write_bio, -1);
	SSL_set_bio(dtls->ssl, dtls->read_bio, dtls->write_bio);
	dtls->dtls_role = role;
	if(dtls->dtls_role == JANUS_DTLS_ROLE_CLIENT) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Setting connect state (DTLS client)\n", handle->handle_id);
		SSL_set_connect_state(dtls->ssl);
	} else {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Setting accept state (DTLS server)\n", handle->handle_id);
		SSL_set_accept_state(dtls->ssl);
	}
	/* Done */
	dtls->component = component;
	return dtls;
}

void janus_dtls_srtp_handshake(janus_dtls_srtp *dtls) {
	if(dtls == NULL || dtls->ssl == NULL)
		return;
	if(dtls->dtls_state == JANUS_DTLS_STATE_CREATED)
		dtls->dtls_state = JANUS_DTLS_STATE_TRYING;
	SSL_do_handshake(dtls->ssl);
	janus_dtls_fd_bridge(dtls);
}

void janus_dtls_srtp_incoming_msg(janus_dtls_srtp *dtls, char *buf, uint16_t len) {
	if(dtls == NULL) {
		JANUS_LOG(LOG_ERR, "No DTLS-SRTP stack, no incoming message...\n");
		return;
	}
	janus_ice_component *component = (janus_ice_component *)dtls->component;
	if(component == NULL) {
		JANUS_LOG(LOG_ERR, "No component, no DTLS...\n");
		return;
	}
	janus_ice_stream *stream = component->stream;
	if(!stream) {
		JANUS_LOG(LOG_ERR, "No stream, no DTLS...\n");
		return;
	}
	janus_ice_handle *handle = stream->handle;
	if(!handle || !handle->agent) {
		JANUS_LOG(LOG_ERR, "No handle/agent, no DTLS...\n");
		return;
	}
	if(handle->alert) {
		JANUS_LOG(LOG_ERR, "Alert already received, clearing up...\n");
		return;
	}
	if(!dtls->ssl || !dtls->read_bio) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No DTLS stuff for component %d in stream %d??\n", handle->handle_id, component->component_id, stream->stream_id);
		return;
	}
	/* We just got a message, can we get rid of the last sent message? */
	if(dtls->dtls_last_msg != NULL) {
		g_free(dtls->dtls_last_msg);
		dtls->dtls_last_msg = NULL;
		dtls->dtls_last_len = 0;
	}
	janus_dtls_fd_bridge(dtls);
	int written = BIO_write(dtls->read_bio, buf, len);
	JANUS_LOG(LOG_HUGE, "    Written %d of those bytes on the read BIO...\n", written);
	janus_dtls_fd_bridge(dtls);
	int read = SSL_read(dtls->ssl, buf, len);
	JANUS_LOG(LOG_HUGE, "    ...and read %d of them from SSL...\n", read);
	janus_dtls_fd_bridge(dtls);
	if(handle->stop || janus_is_stopping()) {
		/* DTLS alert received, we should end it here */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Forced to stop it here...\n", handle->handle_id);
		//~ g_main_loop_quit(iceloop);
		return;
	}
	if(SSL_is_init_finished(dtls->ssl)) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] DTLS established, yay!\n", handle->handle_id);
		/* Check the remote fingerprint */
		X509 *rcert = SSL_get_peer_certificate(dtls->ssl);
		if(!rcert) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] No remote certificate??\n", handle->handle_id);
		} else {
			unsigned int rsize;
			unsigned char rfingerprint[EVP_MAX_MD_SIZE];
			char remote_fingerprint[160];
			char *rfp = (char *)&remote_fingerprint;
			if(handle->remote_hashing && !strcasecmp(handle->remote_hashing, "sha-1")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Computing sha-1 fingerprint of remote certificate...\n", handle->handle_id);
				X509_digest(rcert, EVP_sha1(), (unsigned char *)rfingerprint, &rsize);
			} else {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Computing sha-256 fingerprint of remote certificate...\n", handle->handle_id);
				X509_digest(rcert, EVP_sha256(), (unsigned char *)rfingerprint, &rsize);
			}
			X509_free(rcert);
			rcert = NULL;
			int i = 0;
			for(i = 0; i < rsize; i++) {
				sprintf(rfp, "%.2X:", rfingerprint[i]);
				rfp += 3;
			}
			*(rfp-1) = 0;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Remote fingerprint (%s) of the client is %s\n",
				handle->handle_id, handle->remote_hashing ? handle->remote_hashing : "sha-256", remote_fingerprint);
			if(!strcasecmp(remote_fingerprint, handle->remote_fingerprint ? handle->remote_fingerprint : "(none)")) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Fingerprint is a match!\n", handle->handle_id);
				dtls->dtls_state = JANUS_DTLS_STATE_CONNECTED;
			} else {
				/* FIXME NOT a match! MITM? */
				JANUS_LOG(LOG_ERR, "[%"SCNu64"]  Fingerprint is NOT a match! expected %s\n", handle->handle_id, handle->remote_fingerprint);
				dtls->dtls_state = JANUS_DTLS_STATE_FAILED;
				goto done;
			}
			if(dtls->dtls_state == JANUS_DTLS_STATE_CONNECTED) {
				/* Complete with SRTP setup */
				unsigned char material[SRTP_MASTER_LENGTH*2];
				unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
				/* Export keying material for SRTP */
				if (!SSL_export_keying_material(dtls->ssl, material, SRTP_MASTER_LENGTH*2, "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
					/* Oops... */
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] Oops, couldn't extract SRTP keying material for component %d in stream %d??\n", handle->handle_id, component->component_id, stream->stream_id);
					goto done;
				}
				/* Key derivation (http://tools.ietf.org/html/rfc5764#section-4.2) */
				if(dtls->dtls_role == JANUS_DTLS_ROLE_CLIENT) {
					local_key = material;
					remote_key = local_key + SRTP_MASTER_KEY_LENGTH;
					local_salt = remote_key + SRTP_MASTER_KEY_LENGTH;
					remote_salt = local_salt + SRTP_MASTER_SALT_LENGTH;
				} else {
					remote_key = material;
					local_key = remote_key + SRTP_MASTER_KEY_LENGTH;
					remote_salt = local_key + SRTP_MASTER_KEY_LENGTH;
					local_salt = remote_salt + SRTP_MASTER_SALT_LENGTH;
				}
				/* Build master keys and set SRTP policies */
					/* Remote (inbound) */
				crypto_policy_set_rtp_default(&(dtls->remote_policy.rtp));
				crypto_policy_set_rtcp_default(&(dtls->remote_policy.rtcp));
				dtls->remote_policy.ssrc.type = ssrc_any_inbound;
				dtls->remote_policy.key = calloc(SRTP_MASTER_LENGTH+8, sizeof(char));
				if(dtls->remote_policy.key == NULL) {
					JANUS_LOG(LOG_FATAL, "Memory error!\n");
					goto done;
				}
				memcpy(dtls->remote_policy.key, remote_key, SRTP_MASTER_KEY_LENGTH);
				memcpy(dtls->remote_policy.key + SRTP_MASTER_KEY_LENGTH, remote_salt, SRTP_MASTER_SALT_LENGTH);
				dtls->remote_policy.window_size = 128;
				dtls->remote_policy.allow_repeat_tx = 0;
				dtls->remote_policy.next = NULL;
					/* Local (outbound) */
				crypto_policy_set_rtp_default(&(dtls->local_policy.rtp));
				crypto_policy_set_rtcp_default(&(dtls->local_policy.rtcp));
				dtls->local_policy.ssrc.type = ssrc_any_outbound;
				dtls->local_policy.key = calloc(SRTP_MASTER_LENGTH+8, sizeof(char));
				if(dtls->local_policy.key == NULL) {
					JANUS_LOG(LOG_FATAL, "Memory error!\n");
					goto done;
				}
				memcpy(dtls->local_policy.key, local_key, SRTP_MASTER_KEY_LENGTH);
				memcpy(dtls->local_policy.key + SRTP_MASTER_KEY_LENGTH, local_salt, SRTP_MASTER_SALT_LENGTH);
				dtls->local_policy.window_size = 128;
				dtls->local_policy.allow_repeat_tx = 0;
				dtls->local_policy.next = NULL;
				/* Create SRTP sessions */
				err_status_t res = srtp_create(&(dtls->srtp_in), &(dtls->remote_policy));
				if(res != err_status_ok) {
					/* Something went wrong... */
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] Oops, error creating inbound SRTP session for component %d in stream %d??\n", handle->handle_id, component->component_id, stream->stream_id);
					JANUS_LOG(LOG_ERR, "[%"SCNu64"]  -- %d (%s)\n", handle->handle_id, res, janus_get_srtp_error(res));
					goto done;
				}
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Created inbound SRTP session for component %d in stream %d\n", handle->handle_id, component->component_id, stream->stream_id);
				res = srtp_create(&(dtls->srtp_out), &(dtls->local_policy));
				if(res != err_status_ok) {
					/* Something went wrong... */
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] Oops, error creating outbound SRTP session for component %d in stream %d??\n", handle->handle_id, component->component_id, stream->stream_id);
					JANUS_LOG(LOG_ERR, "[%"SCNu64"]  -- %d (%s)\n", handle->handle_id, res, janus_get_srtp_error(res));
					goto done;
				}
				dtls->srtp_valid = 1;
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Created outbound SRTP session for component %d in stream %d\n", handle->handle_id, component->component_id, stream->stream_id);
				//~ if(component->component_id == 2) {
					//~ /* FIXME Ugly hack to send a RTCP SDES right away, and make browsers happy */
					//~ JANUS_LOG(LOG_VERB, " Going to send a RTCP REPORT (SDES)...\n");
					//~ char rtcp[1024];
					//~ memset(&rtcp, 0, 1024);
					//~ char *rtcp_packet = (char *)&rtcp;
					//~ rtcp_sdes *sdes = (rtcp_sdes *)rtcp_packet;
					//~ sdes->header.version = 2;
					//~ sdes->header.padding = 0;
					//~ sdes->header.rc = 1;
					//~ sdes->header.type = RTCP_SDES;	/* SDES */
					//~ sdes->header.length = htons(2);	/* 2 words */
					//~ sdes->chunk.csrc = htonl(stream->ssrc);
					//~ sdes->item.type = 1;
					//~ sdes->item.len = 0;
					//~ /* SRTCP Protect */
					//~ int protected = 12;	/* RTCP header + chunk + item */
					//~ res = srtp_protect_rtcp(dtls->srtp_out, &rtcp, &protected);
					//~ // JANUS_LOG(LOG_VERB, " ... SRTCP protect %s (len=%d-->%d)...\n", janus_get_srtp_error(res), 12, protected);
					//~ /* Shoot! */
					//~ // JANUS_LOG(LOG_VERB, " ... Sending SRTCP packet (type=%d, len=%d, ssrc=%d)...\n",
						//~ // header->packet_type, ntohs(header->length), ntohl(chunk->csrc));
					//~ // int sent = 
						//~ nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, (const char *)&rtcp);
					//~ // JANUS_LOG(LOG_VERB, " ... Sent %d bytes!\n", sent);
				//~ }
			}
done:
			if(!handle->alert && dtls->srtp_valid) {
				/* Handshake successfully completed */
				janus_ice_dtls_handshake_done(handle, component);
			} else {
				/* Something went wrong in either DTLS or SRTP... tell the plugin about it */
				janus_dtls_callback(dtls->ssl, SSL_CB_ALERT, 0);
			}
		}
	}
}

void janus_dtls_srtp_destroy(janus_dtls_srtp *dtls) {
	if(dtls == NULL)
		return;
	/* Destroy DTLS stack and free resources */
	dtls->component = NULL;
	if(dtls->ssl != NULL) {
		SSL_free(dtls->ssl);
		dtls->ssl = NULL;
	}
	/* BIOs are destroyed by SSL_free */
	dtls->read_bio = NULL;
	dtls->write_bio = NULL;
	if(dtls->srtp_valid) {
		if(dtls->remote_policy.key != NULL) {
			g_free(dtls->remote_policy.key);
			dtls->remote_policy.key = NULL;
		}
		if(dtls->local_policy.key != NULL) {
			g_free(dtls->local_policy.key);
			dtls->local_policy.key = NULL;
		}
		srtp_dealloc(dtls->srtp_in);
		srtp_dealloc(dtls->srtp_out);
		/* FIXME What about dtls->remote_policy and dtls->local_policy? */
	}
	if(dtls->dtls_last_msg != NULL) {
		g_free(dtls->dtls_last_msg);
		dtls->dtls_last_msg = NULL;
	}
	g_free(dtls);
	dtls = NULL;
}

/* DTLS alert callback */
void janus_dtls_callback(const SSL *ssl, int where, int ret) {
	/* We only care about alerts */
	if (!(where & SSL_CB_ALERT)) {
		return;
	}
	janus_dtls_srtp *dtls = SSL_get_ex_data(ssl, 0);
	if(!dtls) {
		JANUS_LOG(LOG_ERR, "No DTLS session related to this alert...\n");
		return;
	}
	dtls->srtp_valid = 0;
	janus_ice_component *component = dtls->component;
	if(component == NULL) {
		JANUS_LOG(LOG_ERR, "No ICE component related to this alert...\n");
		return;
	}
	janus_ice_stream *stream = component->stream;
	if(!stream) {
		JANUS_LOG(LOG_ERR, "No ICE stream related to this alert...\n");
		return;
	}
	janus_ice_handle *handle = stream->handle;
	if(!stream) {
		JANUS_LOG(LOG_ERR, "No ICE handle related to this alert...\n");
		return;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] DTLS alert received, closing...\n", handle->handle_id);
	if(!handle->alert) {
		handle->alert = 1;
		if(handle->iceloop)
			g_main_loop_quit(handle->iceloop);
		janus_plugin *plugin = (janus_plugin *)handle->app;
		if(plugin != NULL) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about it (%s)\n", handle->handle_id, plugin->get_name());
			if(plugin && plugin->hangup_media)
				plugin->hangup_media(handle->app_handle);
		}
	}
}

/* DTLS certificate verification callback */
int janus_dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
	/* We just use the verify_callback to request a certificate from the client */
	return 1;
}

/* DTLS BIOs to/from socket bridge */
void janus_dtls_fd_bridge(janus_dtls_srtp *dtls) {
	if(dtls == NULL) {
		JANUS_LOG(LOG_ERR, "No DTLS-SRTP stack, no DTLS bridge...\n");
		return;
	}
	janus_ice_component *component = (janus_ice_component *)dtls->component;
	if(component == NULL) {
		JANUS_LOG(LOG_ERR, "No component, no DTLS bridge...\n");
		return;
	}
	janus_ice_stream *stream = component->stream;
	if(!stream) {
		JANUS_LOG(LOG_ERR, "No stream, no DTLS bridge...\n");
		return;
	}
	janus_ice_handle *handle = stream->handle;
	if(!handle || !handle->agent || !dtls->write_bio) {
		JANUS_LOG(LOG_ERR, "No handle/agent/bio, no DTLS bridge...\n");
		return;
	}
	int pending = BIO_ctrl_pending(dtls->write_bio);
	JANUS_LOG(LOG_HUGE, "[%"SCNu64"] DTLS check pending: %d\n", handle->handle_id, pending);
	if (pending > 0) {
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] >> Going to send DTLS data: %d bytes\n", handle->handle_id, pending);
		char outgoing[pending];
		size_t out = BIO_read(dtls->write_bio, outgoing, sizeof(outgoing));
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] >> >> Read %d bytes from the write_BIO...\n", handle->handle_id, pending);
		int bytes = nice_agent_send(handle->agent, component->stream_id, component->component_id, out, outgoing);
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] >> >> ... and sent %d of those bytes on the socket\n", handle->handle_id, bytes);

		/* Take note of the last sent message */
		if(dtls->dtls_last_msg != NULL) {
			g_free(dtls->dtls_last_msg);
			dtls->dtls_last_msg = NULL;
			dtls->dtls_last_len = 0;
		}
		dtls->dtls_last_msg = calloc(pending, sizeof(char));
		if(dtls->dtls_last_msg == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return;
		}
		memcpy(dtls->dtls_last_msg, &outgoing, out);
		dtls->dtls_last_len = out;
	}
}

gboolean janus_dtls_retry(gpointer stack) {
	janus_dtls_srtp *dtls = (janus_dtls_srtp *)stack;
	if(dtls == NULL)
		return FALSE;
	janus_ice_component *component = (janus_ice_component *)dtls->component;
	if(component == NULL)
		return FALSE;
	janus_ice_stream *stream = component->stream;
	if(!stream)
		return FALSE;
	janus_ice_handle *handle = stream->handle;
	if(!handle)
		return FALSE;
	if(handle->stop)
		return FALSE;
	//~ struct timeval timeout;
	//~ DTLSv1_get_timeout(dtls->ssl, &timeout);
	//~ JANUS_LOG(LOG_VERB, "[%"SCNu64"] DTLSv1_get_timeout: %"SCNu64"\n", handle->handle_id, timeout.tv_sec*1000000+timeout.tv_usec);
	//~ DTLSv1_handle_timeout(dtls->ssl);
	//~ janus_dtls_fd_bridge(dtls);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] A second has passed on component %d of stream %d\n", handle->handle_id, component->component_id, stream->stream_id);
	if(dtls->dtls_state == JANUS_DTLS_STATE_CONNECTED) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]  DTLS already set up, disabling retransmission timer!\n", handle->handle_id);
		return FALSE;
	}
	if(dtls->dtls_last_msg != NULL) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Retransmitting last message (len=%d)\n", handle->handle_id, dtls->dtls_last_len);
		nice_agent_send(handle->agent, component->stream_id, component->component_id, dtls->dtls_last_len, dtls->dtls_last_msg);
	}
	return TRUE;
}
