/*! \file    janus-pp-rec.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Simple utility to post-process .mjr files saved by Janus
 * \details  Our Janus WebRTC gateway provides a simple helper (janus_recorder)
 * to allow plugins to record audio and video frames sent by users. At the time
 * of writing, this helper has been already integrated in the Video MCU
 * plugin in Janus, thus allowing video conferences and webinars to be
 * recorded. To keep things simple on the Janus side, though, no processing
 * at all is done in the recording step: this means that the recorder
 * actually only dumps the RTP frames it receives to a file in a structured way,
 * so that they can be post-processed later on to extract playable media
 * files. This utility allows you to process those files, in order to
 * get a working .webm (if the recording includes VP8 frames) or .opus
 * (if the recording includes Opus frames) file.
 * 
 * Using the utility is quite simple. Just pass, as arguments to the tool,
 * the path to the .mjr source file you want to post-process, and the
 * path to the destination file (a .webm if it's a video recording,
 * .opus otherwise), e.g.:
 * 
\verbatim
./janus-pp-rec /path/to/source.mjr /path/to/destination.[opus|webm] 
\endverbatim 
 * 
 * \note This utility does not do any form of transcoding. It just
 * depacketizes the RTP frames in order to get the payload, and saves
 * the frames in a valid container. Any further post-processing (e.g.,
 * muxing audio and video belonging to the same media session in a single
 * .webm file) is up to third-party applications.
 * 
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include "../debug.h"
#include "pp-rtp.h"
#include "pp-webm.h"
#include "pp-opus.h"

int log_level = 4;

static janus_pp_frame_packet *list = NULL, *last = NULL;
int working = 0;


/* Signal handler */
void janus_pp_handle_signal(int signum);
void janus_pp_handle_signal(int signum) {
	working = 0;
}


/* Main Code */
int main(int argc, char *argv[])
{
	if(argc != 3) {
		JANUS_LOG(LOG_INFO, "Usage: %s source.mjr destination.[opus|webm]\n", argv[0]);
		return -1;
	}
	char *source = argv[1];
	char *destination = argv[2];
	JANUS_LOG(LOG_INFO, "%s --> %s\n", source, destination);
	FILE *file = fopen(source, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s\n", source);
		return -1;
	}
	fseek(file, 0L, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);
	JANUS_LOG(LOG_INFO, "File is %zu bytes\n", fsize);

	/* Pre-parse */
	JANUS_LOG(LOG_INFO, "Pre-parsing file to generate ordered index...\n");
	int video;
	int bytes = 0, skip = 0;
	long offset = 0;
	uint16_t len = 0, count = 0;
	uint32_t first_ts = 0, last_ts = 0, reset = 0;	/* To handle whether there's a timestamp reset in the recording */
	char prebuffer[1500];
	memset(prebuffer, 0, 1500);
	/* Let's look for timestamp resets first */
	while(offset < fsize) {
		/* Read frame header */
		skip = 0;
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		if(bytes != 8 || prebuffer[0] != 'M') {
			JANUS_LOG(LOG_ERR, "Invalid header...\n");
			exit(1);
		}
		offset += 8;
		bytes = fread(&len, sizeof(uint16_t), 1, file);
		len = ntohs(len);
		offset += 2;
		if(len == 5) {
			/* This is the main header */
			bytes = fread(prebuffer, sizeof(char), 5, file);
			if(prebuffer[0] == 'v') {
				JANUS_LOG(LOG_INFO, "This is a video recording, assuming VP8\n");
				video = 1;
			} else if(prebuffer[0] == 'a') {
				JANUS_LOG(LOG_INFO, "This is an audio recording, assuming Opus\n");
				video = 0;
			} else {
				JANUS_LOG(LOG_WARN, "Unsupported recording media type...\n");
				exit(1);
			}
			offset += len;
			continue;
		} else if(len < 12) {
			/* Not RTP, skip */
			offset += len;
			continue;
		}
		/* Only read RTP header */
		bytes = fread(prebuffer, sizeof(char), 16, file);
		janus_pp_rtp_header *rtp = (janus_pp_rtp_header *)prebuffer;
		if(last_ts == 0) {
			first_ts = ntohl(rtp->timestamp);
			if(first_ts > 1000*1000)	/* Just used to check whether a packet is pre- or post-reset */
				first_ts -= 1000*1000;
		} else {
			if(ntohl(rtp->timestamp) < last_ts) {
				/* The new timestamp is smaller than the next one, is it a timestamp reset or simply out of order? */
				if(last_ts-ntohl(rtp->timestamp) > 2*1000*1000*1000) {
					reset = ntohl(rtp->timestamp);
					JANUS_LOG(LOG_INFO, "Timestamp reset: %"SCNu32"\n", reset);
				}
			} else if(ntohl(rtp->timestamp) < reset) {
				JANUS_LOG(LOG_INFO, "Updating timestamp reset: %"SCNu32" (was %"SCNu32")\n", ntohl(rtp->timestamp), reset);
				reset = ntohl(rtp->timestamp);
			}
		}
		last_ts = ntohl(rtp->timestamp);
		/* Skip data for now */
		offset += len;
	}
	/* Now let's parse the frames and order them */
	offset = 0;
	while(offset < fsize) {
		/* Read frame header */
		skip = 0;
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		prebuffer[8] = '\0';
		JANUS_LOG(LOG_VERB, "Header: %s\n", prebuffer);
		offset += 8;
		bytes = fread(&len, sizeof(uint16_t), 1, file);
		len = ntohs(len);
		JANUS_LOG(LOG_VERB, "  -- Length: %"SCNu16"\n", len);
		offset += 2;
		if(len < 12) {
			/* Not RTP, skip */
			JANUS_LOG(LOG_VERB, "  -- Not RTP, skipping\n");
			offset += len;
			continue;
		}
		/* Only read RTP header */
		bytes = fread(prebuffer, sizeof(char), 16, file);
		janus_pp_rtp_header *rtp = (janus_pp_rtp_header *)prebuffer;
		JANUS_LOG(LOG_VERB, "  -- RTP packet (ssrc=%"SCNu32", pt=%"SCNu16", ext=%"SCNu16", seq=%"SCNu16", ts=%"SCNu32")\n",
				ntohl(rtp->ssrc), rtp->type, rtp->extension, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
		if(rtp->extension) {
			janus_pp_rtp_header_extension *ext = (janus_pp_rtp_header_extension *)(prebuffer+12);
		JANUS_LOG(LOG_VERB, "  -- -- RTP extension (type=%"SCNu16", length=%"SCNu16")\n",
				ntohs(ext->type), ntohs(ext->length)); 
			skip = 4 + ntohs(ext->length)*4;
		}
		/* Generate frame packet and insert in the ordered list */
		janus_pp_frame_packet *p = calloc(1, sizeof(janus_pp_frame_packet));
		if(p == NULL) {
			JANUS_LOG(LOG_ERR, "Memory error!\n");
			return -1;
		}
		p->seq = ntohs(rtp->seq_number);
		if(reset == 0) {
			/* Simple enough... */
			p->ts = ntohl(rtp->timestamp);
		} else {
			/* Is this packet pre- or post-reset? */
			if(ntohl(rtp->timestamp) > first_ts) {
				/* Pre-reset... */
				p->ts = ntohl(rtp->timestamp);
			} else {
				/* Post-reset... */
				uint64_t max32 = UINT32_MAX;
				max32++;
				p->ts = max32+ntohl(rtp->timestamp);
			}
		}
		p->len = len;
		p->offset = offset;
		p->skip = skip;
		p->next = NULL;
		p->prev = NULL;
		if(list == NULL) {
			/* First element becomes the list itself (and the last item), at least for now */
			list = p;
			last = p;
		} else {
			/* Check where we should insert this, starting from the end */
			int added = 0;
			janus_pp_frame_packet *tmp = last;
			while(tmp) {
				if(tmp->ts < p->ts) {
					/* The new timestamp is greater than the last one we have, append */
					added = 1;
					if(tmp->next != NULL) {
						/* We're inserting */
						tmp->next->prev = p;
						p->next = tmp->next;
					} else {
						/* Update the last packet */
						last = p;
					}
					tmp->next = p;
					p->prev = tmp;
					break;
				} else if(tmp->ts == p->ts) {
					/* Same timestamp, check the sequence number */
					if(tmp->seq < p->seq && (abs(tmp->seq - p->seq) < 10000)) {
						/* The new sequence number is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					} else if(tmp->seq > p->seq && (abs(tmp->seq - p->seq) > 10000)) {
						/* The new sequence number (resetted) is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					}
				}
				/* If either the timestamp ot the sequence number we just got is smaller, keep going back */
				tmp = tmp->prev;
			}
			if(!added) {
				/* We reached the start */
				p->next = list;
				list->prev = p;
				list = p;
			}
		}
		/* Skip data for now */
		offset += len;
		count++;
	}
	
	JANUS_LOG(LOG_INFO, "Counted %"SCNu16" RTP packets\n", count);
	janus_pp_frame_packet *tmp = list;
	count = 0;
	while(tmp) {
		count++;
		JANUS_LOG(LOG_VERB, "[%10lu][%4d] seq=%"SCNu16", ts=%"SCNu64"\n", tmp->offset, tmp->len, tmp->seq, tmp->ts);
		tmp = tmp->next;
	}
	JANUS_LOG(LOG_INFO, "Counted %"SCNu16" frame packets\n", count);

	if(!video) {
		/* We don't need any pre-parsing for audio */
		if(janus_pp_opus_create(destination) < 0) {
			JANUS_LOG(LOG_ERR, "Error creating .opus file...\n");
			exit(1);
		}
	} else {
		/* Look for maximum width and height, and for the mean framerate */
		if(janus_pp_webm_preprocess(file, list) < 0) {
			JANUS_LOG(LOG_ERR, "Error pre-processing VP8 RTP frames...\n");
			exit(1);
		}
		/* Now we can write the WebM file */
		if(janus_pp_webm_create(destination) < 0) {
			JANUS_LOG(LOG_ERR, "Error creating .webm file...\n");
			exit(1);
		}
	}
	
	/* Handle SIGINT */
	signal(SIGINT, janus_pp_handle_signal);

	/* Loop */
	working = 1;
	if(!video) {
		if(janus_pp_opus_process(file, list, &working) < 0) {
			JANUS_LOG(LOG_ERR, "Error processing Opus RTP frames...\n");
		}
	} else {
		if(janus_pp_webm_process(file, list, &working) < 0) {
			JANUS_LOG(LOG_ERR, "Error processing Opus RTP frames...\n");
		}
	}

	/* Clean up */
	if(video) {
		janus_pp_webm_close();
	} else {
		janus_pp_opus_close();
	}
	fclose(file);
	
	file = fopen(destination, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_INFO, "No destination file %s??\n", destination);
	} else {
		fseek(file, 0L, SEEK_END);
		fsize = ftell(file);
		fseek(file, 0L, SEEK_SET);
		JANUS_LOG(LOG_INFO, "%s is %zu bytes\n", destination, fsize);
		fclose(file);
	}
	
	JANUS_LOG(LOG_INFO, "Bye!\n");
	
	return 0;
}
