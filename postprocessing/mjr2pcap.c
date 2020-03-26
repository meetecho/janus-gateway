/*! \file    mjr2pcap.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Helper tool to convert Janus .mjr recordings to .pcap files
 * \details  Our Janus WebRTC gateway provides a simple helper (janus_recorder)
 * to allow plugins to record audio, video and text frames sent by users.
 * The \c mjr2pcap tool is a simple utility that allows you remove extract
 * RTP packets from Janus recordings and save them to a .pcap file instead.
 * Notice that network levels are simulated, and so are timestamps for when
 * the packets have really been received, since that info is not stored in
 * .mjr files. As such, its main purpose is helping analyze RTP packets,
 * rather than investigate network issues.
 *
 * Using the utility is quite simple. Just pass, as arguments to the tool,
 * the path to the .mjr source file, and the path to the destination file, e.g.:
 *
\verbatim
./mjr2pcap /path/to/source.mjr /path/to/destination.pcap
\endverbatim
 *
 * An attempt to process a non-RTP recording will result in an error.
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
#include <sys/time.h>

#include <glib.h>
#include <jansson.h>

#include "../debug.h"
#include "pp-rtp.h"


#define htonll(x) ((1==htonl(1)) ? (x) : ((gint64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((gint64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

int janus_log_level = 4;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = TRUE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;

int working = 0;


/* Helper struct to define a libpcap global header
 * https://wiki.wireshark.org/Development/LibpcapFileFormat */
typedef struct mjr2pcap_global_header {
	guint32 magic_number;	/* Magic number */
	guint16 version_major;	/* Major version number */
	guint16 version_minor;	/* Minor version number */
	gint32  thiszone;		/* GMT to local correction */
	guint32 sigfigs;		/* Accuracy of timestamps */
	guint32 snaplen;		/* Max length of captured packets, in octets */
	guint32 network;		/* Data link type */
} mjr2pcap_global_header;

/* Helper struct to define a libpcap packet header
 * https://wiki.wireshark.org/Development/LibpcapFileFormat */
typedef struct mjr2pcap_packet_header {
	guint32 ts_sec;			/* Timestamp seconds */
	guint32 ts_usec;		/* Timestamp microseconds */
	guint32 incl_len;		/* Number of octets of packet saved in file */
	guint32 orig_len;		/* Actual length of packet */
} mjr2pcap_packet_header;

/* Ethernet header */
typedef struct mjr2pcap_ethernet_header {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
} mjr2pcap_ethernet_header;
static void mjr2pcap_ethernet_header_init(mjr2pcap_ethernet_header *eth) {
	memset(eth, 0, sizeof(*eth));
	eth->type = htons(0x0800);
}

/* IP header */
typedef struct mjr2pcap_ip_header {
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version:4;
	uint8_t hlen:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t hlen:4;
	uint8_t version:4;
#endif
	uint8_t tos;
	uint16_t tlen;
	uint16_t id;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t csum;
	uint8_t src[4];
	uint8_t dst[4];
} mjr2pcap_ip_header;
static void mjr2pcap_ip_header_init(mjr2pcap_ip_header *ip, int psize) {
	ip->version = 4;
	ip->hlen = 5;
	ip->tos = 0;
	ip->tlen = htons(28+psize);
	ip->id = htons(0);
	ip->flags = htons(0x4000);
	ip->ttl = 64;
	ip->protocol = 17;
	ip->csum = 0;
	ip->src[0] = 10;
	ip->src[1] = 1;
	ip->src[2] = 1;
	ip->src[3] = 1;
	ip->dst[0] = 10;
	ip->dst[1] = 2;
	ip->dst[2] = 2;
	ip->dst[3] = 2;
}

/* UDP header */
typedef struct mjr2pcap_udp_header {
	uint16_t srcport;
	uint16_t dstport;
	uint16_t len;
	uint16_t csum;
} mjr2pcap_udp_header;
static void mjr2pcap_udp_header_init(mjr2pcap_udp_header *udp, int psize) {
	udp->srcport = htons(1000);
	udp->dstport = htons(2000);
	udp->len = htons(8+psize);
	udp->csum = 0;
}


/* Signal handler */
static void janus_pp_handle_signal(int signum) {
	working = 0;
}


/* Main Code */
int main(int argc, char *argv[])
{
	janus_log_init(FALSE, TRUE, NULL);
	atexit(janus_log_destroy);

	/* Evaluate arguments */
	if(argc != 3) {
		JANUS_LOG(LOG_INFO, "Usage: %s source.mjr destination.pcap\n", argv[0]);
		exit(1);
	}
	char *source = NULL, *destination = NULL;
	source = argv[1];
	destination = argv[2];
	JANUS_LOG(LOG_INFO, "%s --> %s\n", source, destination);

	/* Open the source file */
	FILE *file = fopen(source, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s\n", source);
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
	gboolean has_timestamps = FALSE;
	gboolean parsed_header = FALSE;
	json_t *mjr_header = NULL;
	int bytes = 0;
	long offset = 0;
	uint16_t len = 0;
	gint64 started = 0;
	char prebuffer[1500];
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
				/* Old .mjr format, check if this is an RTP recording */
				bytes = fread(prebuffer, sizeof(char), 5, file);
				if(prebuffer[0] != 'a' && prebuffer[0] != 'v') {
					fclose(file);
					JANUS_LOG(LOG_ERR, "Not an RTP recording (data currently unsupported)...\n");
					exit(1);
				}
			} else if(len < 12) {
				/* Not RTP, skip */
				JANUS_LOG(LOG_VERB, "Skipping packet (not RTP?)\n");
				offset += len;
				continue;
			}
		} else if(prebuffer[1] == 'J') {
			/* New .mjr format, check if this is an RTP recording */
			if(prebuffer[2] == 'R' && prebuffer[3] == '0' && prebuffer[4] == '0' &&
					prebuffer[5] == '0' && prebuffer[6] == '0' && prebuffer[7] == '2') {
				/* Main header is MJR00002: this means we have timestamps too */
				has_timestamps = TRUE;
				JANUS_LOG(LOG_VERB, "New .mjr format, will parse timestamps too\n");
			}
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len > 0 && !parsed_header) {
				/* This is the info header */
				bytes = fread(prebuffer, sizeof(char), len, file);
				prebuffer[len] = '\0';
				json_error_t error;
				mjr_header = json_loads(prebuffer, 0, &error);
				if(!mjr_header) {
					fclose(file);
					JANUS_LOG(LOG_ERR, "Error parsing header, JSON error: on line %d: %s\n", error.line, error.text);
					exit(1);
				}
				/* Make sure the content is RTP */
				json_t *type = json_object_get(mjr_header, "t");
				if(!type || !json_is_string(type)) {
					json_decref(mjr_header);
					fclose(file);
					JANUS_LOG(LOG_ERR, "Missing/invalid recording type in info header...\n");
					exit(1);
				}
				const char *t = json_string_value(type);
				if(!strcasecmp(t, "d")) {
					/* Data recordings are not supported yet */
					json_decref(mjr_header);
					fclose(file);
					JANUS_LOG(LOG_ERR, "Not an RTP recording (data currently unsupported)...\n");
					exit(1);
				}
				json_t *updated = json_object_get(mjr_header, "u");
				if(!updated || !json_is_integer(updated)) {
					json_decref(mjr_header);
					fclose(file);
					JANUS_LOG(LOG_ERR, "Missing/invalid updated time in info header...\n");
					exit(1);
				}
				started = json_integer_value(updated);
			}
		} else {
			JANUS_LOG(LOG_ERR, "Invalid header...\n");
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
		json_decref(mjr_header);
		JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
		exit(1);
	}
	/* Start with the PCAP header */
	mjr2pcap_global_header pcap_header = {
		0xa1b2c3d4, 2, 4, 0, 0, 65535, 1
	};
	fwrite(&pcap_header, sizeof(char), sizeof(pcap_header), outfile);
	/* Now iterate on all packets, and save them to the .pcap file */
	offset = 0;
	JANUS_LOG(LOG_INFO, "Traversing RTP packets...\n");
	uint32_t pkt_ts = 0;
	while(working && offset < fsize) {
		/* Read frame header */
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		if(bytes != 8 || prebuffer[0] != 'M') {
			/* Broken packet? Stop here */
			break;
		}
		if(has_timestamps) {
			/* Read the packet timestamp */
			memcpy(&pkt_ts, prebuffer+4, sizeof(uint32_t));
			pkt_ts = ntohl(pkt_ts);
		}
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
		if(len > 1500) {
			/* Way too large, very likely not RTP, skip */
			JANUS_LOG(LOG_VERB, "  -- Too large packet (%d bytes), skipping\n", len);
			offset += len;
			continue;
		}
		/* Get the whole packet */
		bytes = fread(prebuffer, sizeof(char), len, file);
		if(bytes != len) {
			JANUS_LOG(LOG_WARN, "  -- Failed to read packet (%d != %d bytes), skipping\n", bytes, len);
			offset += len;
			continue;
		}
		/* Save the packet to PCAP */
		int hsize = sizeof(mjr2pcap_ethernet_header) + sizeof(mjr2pcap_ip_header) +
			sizeof(mjr2pcap_udp_header) + len;
		/* We need a fake Ethernet/IP/UDP encapsulation for this packet */
		mjr2pcap_ethernet_header eth;
		mjr2pcap_ethernet_header_init(&eth);
		mjr2pcap_ip_header ip;
		mjr2pcap_ip_header_init(&ip, len);
		mjr2pcap_udp_header udp;
		mjr2pcap_udp_header_init(&udp, len);
		/* Now prepare the packet header */
		struct timeval tv;
		if(has_timestamps) {
			/* Prepare a valid timestamp */
			gint64 timestamp = started + (pkt_ts*1000);
			tv.tv_sec = timestamp / G_USEC_PER_SEC;
			tv.tv_usec = timestamp -  (tv.tv_sec*G_USEC_PER_SEC);
		} else {
			/* Craft a dummy timestamp */
			gettimeofday(&tv, NULL);
		}
		mjr2pcap_packet_header header = {
			tv.tv_sec, tv.tv_usec, hsize, hsize
		};
		fwrite(&header, sizeof(char), sizeof(header), outfile);
		fwrite(&eth, sizeof(char), sizeof(eth), outfile);
		fwrite(&ip, sizeof(char), sizeof(ip), outfile);
		fwrite(&udp, sizeof(char), sizeof(udp), outfile);
		/* The write the packet itself (or part of it) */
		int temp = 0, tot = len;
		while(tot > 0) {
			temp = fwrite(prebuffer+len-tot, sizeof(char), len, outfile);
			if(temp <= 0) {
				JANUS_LOG(LOG_ERR, "Error dumping packet...\n");
				break;
			}
			tot -= temp;
		}
		offset += len;
	}
	/* We're done */
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
