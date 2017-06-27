/*! \file    janus-pp-unperc.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Helper tool to remove the PERC layer from Janus .mjr recordings
 * \details  Our Janus WebRTC gateway provides a simple helper (janus_recorder)
 * to allow plugins to record audio, video and text frames sent by users. In
 * case the recorded media was captured in a PERC-enabled session, though,
 * the content of the RTP packets will still be encrypted, and thus
 * unavailable to \c janus-pp-rec for processing. This tool allows you
 * to decrypt that content, in case you have access to the key, so that
 * a plain .mjr file can be generated and processed to a media file.
 * 
 * Using the utility is quite simple. Just pass, as arguments to the tool,
 * the key as a base-64 encoded string, the path to the .mjr source file
 * you want to decrypt, and the path to the destination file, e.g.:
 * 
\verbatim
./janus-pp-unperc base64-key /path/to/source.mjr /path/to/destination.mjr
\endverbatim 
 * 
 * An attempt to specify an invalid key or to process a non-PERC recording
 * will result in an error since.
 * 
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <glib.h>
#include <jansson.h>

#include "../debug.h"
#include "pp-rtp.h"

#ifdef HAVE_SRTP_2
#include <srtp2/srtp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#else
#include <srtp/srtp.h>
#include <srtp/crypto_kernel.h>
#define srtp_err_status_t err_status_t
#define srtp_err_status_ok err_status_ok
#define srtp_err_status_replay_fail err_status_replay_fail
#define srtp_err_status_replay_old err_status_replay_old
static srtp_err_status_t srtp_crypto_policy_set_aes_gcm_256_16_auth(srtp_policy_t *policy) {
	JANUS_LOG(LOG_FATAL, "You need libsrtp2 to use janus-pp-unperc\n");
	exit(1);
}
#endif
/* SRTP error codes as a string array */
static const char *janus_srtp_error[] =
{
#ifdef HAVE_SRTP_2
	"srtp_err_status_ok",
	"srtp_err_status_fail",
	"srtp_err_status_bad_param",
	"srtp_err_status_alloc_fail",
	"srtp_err_status_dealloc_fail",
	"srtp_err_status_init_fail",
	"srtp_err_status_terminus",
	"srtp_err_status_auth_fail",
	"srtp_err_status_cipher_fail",
	"srtp_err_status_replay_fail",
	"srtp_err_status_replay_old",
	"srtp_err_status_algo_fail",
	"srtp_err_status_no_such_op",
	"srtp_err_status_no_ctx",
	"srtp_err_status_cant_check",
	"srtp_err_status_key_expired",
	"srtp_err_status_socket_err",
	"srtp_err_status_signal_err",
	"srtp_err_status_nonce_bad",
	"srtp_err_status_read_fail",
	"srtp_err_status_write_fail",
	"srtp_err_status_parse_err",
	"srtp_err_status_encode_err",
	"srtp_err_status_semaphore_err",
	"srtp_err_status_pfkey_err",
#else
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
#endif
};
static const char *janus_srtp_error_str(int error) {
	if(error < 0 || error > 24)
		return NULL;
	return janus_srtp_error[error];
}


/* Info header in the structured recording */
static const char *header = "MJR00001";
/* Frame header in the structured recording */
static const char *frame_header = "MEETECHO";

#define htonll(x) ((1==htonl(1)) ? (x) : ((gint64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((gint64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

int janus_log_level = 4;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = TRUE;

int working = 0;


/* Signal handler */
static void janus_pp_handle_signal(int signum) {
	working = 0;
}


/* Main Code */
int main(int argc, char *argv[])
{
	janus_log_init(FALSE, TRUE, NULL);
	atexit(janus_log_destroy);

	/* Check the JANUS_PPUNPERC_DEBUG environment variable for the debugging level */
	if(g_getenv("JANUS_PPUNPERC_DEBUG") != NULL) {
		int val = atoi(g_getenv("JANUS_PPUNPERC_DEBUG"));
		if(val >= LOG_NONE && val <= LOG_MAX)
			janus_log_level = val;
		JANUS_LOG(LOG_INFO, "Logging level: %d\n", janus_log_level);
	}
	
	/* Evaluate arguments */
	if(argc != 4) {
		JANUS_LOG(LOG_INFO, "Usage: %s key source.mjr destination.mjr\n", argv[0]);
		exit(1);
	}
	char *source = NULL, *destination = NULL, *base64key = NULL;
	base64key = argv[1];
	source = argv[2];
	destination = argv[3];
	JANUS_LOG(LOG_INFO, "%s --> %s (%s)\n", source, destination, base64key);
	/* Decode the base64 string to get the key */
	gsize keylen = 0;
	uint8_t *key = g_base64_decode(base64key, &keylen);
	if(key == NULL || keylen != 44) {
		JANUS_LOG(LOG_ERR, "Invalid key %s\n", base64key);
		g_free(key);
		exit(1);
	}
	/* Initialize libsrtp */
	if(srtp_init() != srtp_err_status_ok) {
		JANUS_LOG(LOG_FATAL, "Ops, error setting up libsrtp?\n");
		g_free(key);
		exit(1);
	}
	/* Create an SRTP context */
	srtp_t srtp_in;
	srtp_policy_t remote_policy;
	srtp_crypto_policy_set_aes_gcm_256_16_auth(&remote_policy.rtp);
	srtp_crypto_policy_set_aes_gcm_256_16_auth(&remote_policy.rtcp);
	remote_policy.ssrc.type = ssrc_any_inbound;
	remote_policy.ssrc.value = 0;
	remote_policy.key = key;
	remote_policy.window_size = 1024;
	remote_policy.allow_repeat_tx = 1;
	remote_policy.next = NULL;
	srtp_err_status_t res = srtp_create(&srtp_in, &remote_policy);
	if(res != srtp_err_status_ok) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Error creating SRTP context: %d (%s)\n", res, janus_srtp_error_str(res));
		g_free(key);
		exit(1);
	}

	/* Open the source file */
	FILE *file = fopen(source, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s\n", source);
		g_free(key);
		exit(1);
	}
	fseek(file, 0L, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);
	JANUS_LOG(LOG_INFO, "File is %zu bytes\n", fsize);

	/* Handle SIGINT */
	working = 1;
	signal(SIGINT, janus_pp_handle_signal);

	/* Pre-parse */
	JANUS_LOG(LOG_INFO, "Pre-parsing file...\n");
	gboolean parsed_header = FALSE;
	json_t *mjr_header = NULL;
	int bytes = 0, rtplen = 0, skip = 0;
	long offset = 0;
	uint16_t len = 0;
	char prebuffer[1500], payload[1500];
	memset(prebuffer, 0, 1500);
	/* Let's look for timestamp resets first */
	while(working && offset < fsize) {
		/* Read frame header */
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		if(bytes != 8 || prebuffer[0] != 'M') {
			JANUS_LOG(LOG_WARN, "Invalid header at offset %ld (%s), the processing will stop here...\n",
				offset, bytes != 8 ? "not enough bytes" : "wrong prefix");
			break;
		}
		if(prebuffer[1] == 'E') {
			/* Either the old .mjr format header ('MEETECHO' header followed by 'audio' or 'video'), or a frame */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len == 5 && !parsed_header) {
				/* This is the main header */
				JANUS_LOG(LOG_ERR, "Old .mjr header format, so this can't be a PERC recording\n");
				g_free(key);
				fclose(file);
				exit(1);
			} else if(len < 12) {
				/* Not RTP, skip */
				JANUS_LOG(LOG_VERB, "Skipping packet (not RTP?)\n");
				offset += len;
				continue;
			}
		} else if(prebuffer[1] == 'J') {
			/* New .mjr format, check if this is a PERC recording */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len > 0 && !parsed_header) {
				/* This is the info header */
				JANUS_LOG(LOG_VERB, "New .mjr header format\n");
				bytes = fread(prebuffer, sizeof(char), len, file);
				parsed_header = TRUE;
				prebuffer[len] = '\0';
				json_error_t error;
				mjr_header = json_loads(prebuffer, 0, &error);
				if(!mjr_header) {
					g_free(key);
					fclose(file);
					JANUS_LOG(LOG_ERR, "Error parsing header, JSON error: on line %d: %s\n", error.line, error.text);
					exit(1);
				}
				/* Let's check if this is a PERC recording */
				if(json_object_del(mjr_header, "p") < 0) {
					/* It isn't... */
					g_free(key);
					json_decref(mjr_header);
					fclose(file);
					JANUS_LOG(LOG_ERR, "This is not a PERC recording, giving up...\n");
					exit(1);
				}
				/* Make sure the content is RTP */
				json_t *type = json_object_get(mjr_header, "t");
				if(!type || !json_is_string(type)) {
					g_free(key);
					json_decref(mjr_header);
					fclose(file);
					JANUS_LOG(LOG_ERR, "Missing/invalid recording type in info header...\n");
					exit(1);
				}
				const char *t = json_string_value(type);
				if(!strcasecmp(t, "d")) {
					/* Data recordings don't go through the PERC process */
					g_free(key);
					json_decref(mjr_header);
					fclose(file);
					JANUS_LOG(LOG_ERR, "This is a data recording, no need to do any PERC decryption...\n");
					exit(1);
				}
				parsed_header = TRUE;
			}
		} else {
			JANUS_LOG(LOG_ERR, "Invalid header...\n");
			g_free(key);
			json_decref(mjr_header);
			fclose(file);
			exit(1);
		}
		/* Skip data for now */
		offset += len;
	}

	/* Create the target file */
	FILE *outfile = fopen(destination, "wb");
	if(outfile == NULL) {
		g_free(key);
		json_decref(mjr_header);
		JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
		exit(1);
	}
	gboolean header_written = FALSE;
	/* Now iterate on all packets, decrypt them using the provided key and save the result */
	offset = 0;
	JANUS_LOG(LOG_INFO, "Unencrypting RTP packets...\n");
	while(working && offset < fsize) {
		/* Read frame header */
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		if(bytes != 8 || prebuffer[0] != 'M') {
			/* Broken packet? Stop here */
			break;
		}
		prebuffer[8] = '\0';
		JANUS_LOG(LOG_VERB, "Header: %s\n", prebuffer);
		offset += 8;
		bytes = fread(&len, sizeof(uint16_t), 1, file);
		len = ntohs(len);
		JANUS_LOG(LOG_VERB, "  -- Length: %"SCNu16"\n", len);
		offset += 2;
		if(prebuffer[1] == 'J' || len < 12) {
			/* Not RTP, skip */
			JANUS_LOG(LOG_VERB, "  -- Not RTP, skipping\n");
			offset += len;
			continue;
		}
		if(len > 2000) {
			/* Way too large, very likely not RTP, skip */
			JANUS_LOG(LOG_VERB, "  -- Too large packet (%d bytes), skipping\n", len);
			offset += len;
			continue;
		}
		/* Get the whole packet */
		skip = 0;
		bytes = fread(prebuffer, sizeof(char), len, file);
		janus_pp_rtp_header *rtp = (janus_pp_rtp_header *)prebuffer;
		JANUS_LOG(LOG_VERB, "  -- RTP packet (ssrc=%"SCNu32", pt=%"SCNu16", ext=%"SCNu16", seq=%"SCNu16", ts=%"SCNu32")\n",
				ntohl(rtp->ssrc), rtp->type, rtp->extension, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
		if(rtp->csrccount) {
			JANUS_LOG(LOG_VERB, "  -- -- Skipping CSRC list\n");
			skip += rtp->csrccount*4;
		}
		if(rtp->extension) {
			janus_pp_rtp_header_extension *ext = (janus_pp_rtp_header_extension *)(prebuffer+12+skip);
			JANUS_LOG(LOG_VERB, "  -- -- RTP extension (type=%"SCNu16", length=%"SCNu16")\n",
				ntohs(ext->type), ntohs(ext->length));
			skip += 4 + ntohs(ext->length)*4;
		}
		rtplen = bytes-12-skip;
		if(rtp->padding) {
			/* There's padding data, let's check the last byte to see how much data we should skip */
			fseek(file, offset + len - 1, SEEK_SET);
			bytes = fread(prebuffer, sizeof(char), 1, file);
			uint8_t padlen = (uint8_t)prebuffer[0];
			JANUS_LOG(LOG_VERB, "Padding at sequence number %hu: %d/%d\n",
				ntohs(rtp->seq_number), padlen, len);
			rtplen -= padlen;
			if((rtplen - skip - 12) <= 0) {
				/* Only padding, drop this */
				JANUS_LOG(LOG_VERB, "  -- All padding, dropping the packet\n");
				offset += len;
				continue;
			}
		}
		/* Retrieve the payload now */
		payload[0] = 0x80;
		memcpy(&payload[1], &prebuffer[12+skip], rtplen);
		rtplen++;
		/* Decrypt the payload using the SRTP context */
		int buflen = rtplen;
		JANUS_LOG(LOG_VERB, "Extracted payload (%d/%d bytes), trying to decrypt...\n", buflen, len);
		rtp = (janus_pp_rtp_header *)&payload[0];
		JANUS_LOG(LOG_VERB, "  -- SRTP packet (ssrc=%"SCNu32", pt=%"SCNu16", ext=%"SCNu16", seq=%"SCNu16", ts=%"SCNu32")\n",
				ntohl(rtp->ssrc), rtp->type, rtp->extension, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
		res = srtp_unprotect(srtp_in, &payload[0], &buflen);
		if(res != srtp_err_status_ok) {
			JANUS_LOG(LOG_ERR, "Error decrypting SRTP packet: %d (%s)\n", res, janus_srtp_error_str(res));
			if(res == srtp_err_status_auth_fail) {
				JANUS_LOG(LOG_FATAL, "Wrong key? target file will be invalid...\n");
				g_free(key);
				json_decref(mjr_header);
				fclose(file);
				fclose(outfile);
				exit(1);
			}
		} else {
			/* Save the frame on the target .mjr file */
			JANUS_LOG(LOG_VERB, "  -- Decrypted to plain RTP packet (%d/%d bytes)\n", buflen, rtplen);
			rtplen = buflen;
			if(!header_written) {
				/* Let's write the .mjr header first, though */
				fwrite(header, sizeof(char), strlen(header), outfile);
				gchar *info_text = json_dumps(mjr_header, JSON_PRESERVE_ORDER);
				json_decref(mjr_header);
				uint16_t info_bytes = htons(strlen(info_text));
				fwrite(&info_bytes, sizeof(uint16_t), 1, outfile);
				fwrite(info_text, sizeof(char), strlen(info_text), outfile);
				free(info_text);
				header_written = TRUE;
			}
			fwrite(frame_header, sizeof(char), strlen(frame_header), outfile);
			uint16_t header_bytes = htons(rtplen);
			fwrite(&header_bytes, sizeof(uint16_t), 1, outfile);
			int temp = 0, tot = rtplen;
			while(tot > 0) {
				temp = fwrite(&payload[rtplen-tot], sizeof(char), tot, outfile);
				if(temp <= 0) {
					JANUS_LOG(LOG_ERR, "Error saving frame, invalid target file...\n");
					g_free(key);
					json_decref(mjr_header);
					fclose(file);
					fclose(outfile);
					exit(1);
				}
				tot -= temp;
			}
		}
		offset += len;
	}
	/* We're done */
	g_free(key);
	json_decref(mjr_header);
	fclose(file);
	fclose(outfile);
	outfile = fopen(destination, "rb");
	if(outfile == NULL) {
		JANUS_LOG(LOG_INFO, "No destination file %s??\n", destination);
	} else {
		fseek(outfile, 0L, SEEK_END);
		fsize = ftell(outfile);
		fseek(outfile, 0L, SEEK_SET);
		JANUS_LOG(LOG_INFO, "%s is %zu bytes\n", destination, fsize);
		fclose(outfile);
	}

	JANUS_LOG(LOG_INFO, "Bye!\n");
	return 0;
}
