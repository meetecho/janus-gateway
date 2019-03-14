/*! \file    text2pcap.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Dumping of RTP/RTCP packets to text2pcap or pcap format
 * \details  Implementation of a simple helper utility that can be used
 * to dump incoming and outgoing RTP/RTCP packets to pcap or text2pcap format.
 * Saving to pcap natively can be more efficient but will lack some features,
 * as the target will be a legacy (v2.4) \c .pcap file and not a \c .pcapng one.
 * When saving to a text file, instead, the resulting file can be passed to
 * the \c text2pcap application in order to get a \c .pcap or \c .pcapng file
 * that can be analyzed via Wireshark or similar applications, e.g.:
 *
\verbatim
/usr/sbin/text2pcap -D -n -l 1 -i 17 -u 1000,2000 -t '%H:%M:%S.' dump.txt dump.pcapng
/usr/sbin/wireshark dump.pcapng
\endverbatim
 *
 * While plugins are free to take advantage of this functionality, it's been
 * specifically added to make debugging from the core easier. Enabling and
 * disabling the dump of RTP/RTCP packets for the media traffic of a
 * specific handle is done via the \ref admin so check the documentation
 * of that section for more details. Notice that starting a new dump on
 * an existing filename will result in the new packets to be appended.
 *
 * \note Motivation and inspiration for this work came from a
 * <a href="https://blog.mozilla.org/webrtc/debugging-encrypted-rtp-is-more-fun-than-it-used-to-be/">similar effort</a>
 * recently done in Firefox, and from a discussion related to a
 * <a href="https://webrtchacks.com/video_replay/">blog post</a> on
 * WebRTC hacks, where guidelines are provided with respect to debugging
 * based on pcap files.
 *
 * \ingroup core
 * \ref core
 */

#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#else
#include <endian.h>
#endif

#include "text2pcap.h"
#include "debug.h"
#include "utils.h"

#define CASE_STR(name) case name: return #name
const char *janus_text2pcap_packet_string(janus_text2pcap_packet type) {
	switch(type) {
		CASE_STR(JANUS_TEXT2PCAP_RTP);
		CASE_STR(JANUS_TEXT2PCAP_RTCP);
		CASE_STR(JANUS_TEXT2PCAP_DATA);
		default:
			break;
	}
	return NULL;
}

/* Helper struct to define a libpcap global header
 * https://wiki.wireshark.org/Development/LibpcapFileFormat */
typedef struct janus_text2pcap_global_header {
	guint32 magic_number;	/* Magic number */
	guint16 version_major;	/* Major version number */
	guint16 version_minor;	/* Minor version number */
	gint32  thiszone;		/* GMT to local correction */
	guint32 sigfigs;		/* Accuracy of timestamps */
	guint32 snaplen;		/* Max length of captured packets, in octets */
	guint32 network;		/* Data link type */
} janus_text2pcap_global_header;

/* Helper struct to define a libpcap packet header
 * https://wiki.wireshark.org/Development/LibpcapFileFormat */
typedef struct janus_text2pcap_packet_header {
	guint32 ts_sec;			/* Timestamp seconds */
	guint32 ts_usec;		/* Timestamp microseconds */
	guint32 incl_len;		/* Number of octets of packet saved in file */
	guint32 orig_len;		/* Actual length of packet */
} janus_text2pcap_packet_header;

/* Ethernet header */
typedef struct janus_text2pcap_ethernet_header {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
} janus_text2pcap_ethernet_header;
static void janus_text2pcap_ethernet_header_init(janus_text2pcap_ethernet_header *eth) {
	memset(eth, 0, sizeof(*eth));
	eth->type = htons(0x0800);
}

/* IP header */
typedef struct janus_text2pcap_ip_header {
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
} janus_text2pcap_ip_header;
static void janus_text2pcap_ip_header_init(janus_text2pcap_ip_header *ip, gboolean incoming, int psize) {
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
	ip->src[1] = incoming ? 1 : 2;
	ip->src[2] = incoming ? 1 : 2;
	ip->src[3] = incoming ? 1 : 2;
	ip->dst[0] = 10;
	ip->dst[1] = incoming ? 2 : 1;
	ip->dst[2] = incoming ? 2 : 1;
	ip->dst[3] = incoming ? 2 : 1;
}

/* UDP header */
typedef struct janus_text2pcap_udp_header {
	uint16_t srcport;
	uint16_t dstport;
	uint16_t len;
	uint16_t csum;
} janus_text2pcap_udp_header;
static void janus_text2pcap_udp_header_init(janus_text2pcap_udp_header *udp, gboolean incoming, int psize) {
	udp->srcport = htons(incoming ? 1000 : 2000);
	udp->dstport = htons(incoming ? 2000 : 1000);
	udp->len = htons(8+psize);
	udp->csum = 0;
}


janus_text2pcap *janus_text2pcap_create(const char *dir, const char *filename, int truncate, gboolean text) {
	janus_text2pcap *tp;
	char newname[1024];
	char *fname;
	FILE *f;

	if(truncate < 0)
		return NULL;

	/* Copy given filename or generate a random one */
	if (filename == NULL) {
		g_snprintf(newname, sizeof(newname),
		    "janus-text2pcap-%"SCNu32".%s", janus_random_uint32(), text ? "txt" : "pcap");
	} else {
		g_strlcpy(newname, filename, sizeof(newname));
	}

	if(dir != NULL) {
		/* Create the directory, if needed */
		if(janus_mkdir(dir, 0755) < 0) {
			JANUS_LOG(LOG_ERR, "mkdir error: %d\n", errno);
			return NULL;
		}
		fname = g_strdup_printf("%s/%s", dir, newname);
	} else {
		fname = g_strdup(newname);
	}

	/* Try opening the file now */
	f = fopen(fname, "ab");
	if (f == NULL) {
		JANUS_LOG(LOG_ERR, "fopen(%s) error: %d\n", fname, errno);
		g_free(fname);
		return NULL;
	}

	/* Create the text2pcap instance */
	tp = g_malloc(sizeof(janus_text2pcap));
	tp->filename = fname;
	tp->file = f;
	tp->truncate = truncate;
	tp->text = text;
	g_atomic_int_set(&tp->writable, 1);
	janus_mutex_init(&tp->mutex);

	/* If we're saving to .pcap directly, generate a global header */
	if(!text) {
		janus_text2pcap_global_header header = {
			0xa1b2c3d4, 2, 4, 0, 0, 65535, 1
		};
		fwrite(&header, sizeof(char), sizeof(header), f);
	}

	return tp;
}

int janus_text2pcap_dump(janus_text2pcap *instance,
		janus_text2pcap_packet type, gboolean incoming, char *buf, int len, const char *format, ...) {
	if(instance == NULL || buf == NULL || len < 1)
		return -1;
	janus_mutex_lock_nodebug(&instance->mutex);
	if(instance->file == NULL || !g_atomic_int_get(&instance->writable)) {
		janus_mutex_unlock_nodebug(&instance->mutex);
		return -1;
	}
	/* If we're saving to .pcap directly, generate a packet header and save the payload */
	if(!instance->text) {
		/* Are we truncating? */
		int size = instance->truncate ? (len > instance->truncate ? instance->truncate : len) : len;
		int hsize = sizeof(janus_text2pcap_ethernet_header) + sizeof(janus_text2pcap_ip_header) +
			sizeof(janus_text2pcap_udp_header);
		int hsize_cut = hsize + size;
		int hsize_tot = hsize + len;
		/* We need a fake Ethernet/IP/UDP encapsulation for this packet */
		janus_text2pcap_ethernet_header eth;
		janus_text2pcap_ethernet_header_init(&eth);
		janus_text2pcap_ip_header ip;
		janus_text2pcap_ip_header_init(&ip, incoming, len);
		janus_text2pcap_udp_header udp;
		janus_text2pcap_udp_header_init(&udp, incoming, len);
		/* Now prepare the packet header */
		struct timeval tv;
		gettimeofday(&tv, NULL);
		janus_text2pcap_packet_header header = {
			tv.tv_sec, tv.tv_usec, hsize_cut, hsize_tot
		};
		fwrite(&header, sizeof(char), sizeof(header), instance->file);
		fwrite(&eth, sizeof(char), sizeof(eth), instance->file);
		fwrite(&ip, sizeof(char), sizeof(ip), instance->file);
		fwrite(&udp, sizeof(char), sizeof(udp), instance->file);
		/* The write the packet itself (or part of it) */
		int temp = 0, tot = size;
		while(tot > 0) {
			temp = fwrite(buf+size-tot, sizeof(char), tot, instance->file);
			if(temp <= 0) {
				JANUS_LOG(LOG_ERR, "Error dumping packet...\n");
				janus_mutex_unlock_nodebug(&instance->mutex);
				return -2;
			}
			tot -= temp;
		}
		/* Done */
		janus_mutex_unlock_nodebug(&instance->mutex);
		return 0;
	}
	/* If we got here, we need to prepare a text representation of the packet */
	char buffer[5000], timestamp[20], usec[10], byte[10];
	memset(timestamp, 0, sizeof(timestamp));
	memset(usec, 0, sizeof(usec));
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm);
	g_snprintf(usec, sizeof(usec), ".%06ld", tv.tv_usec);
	g_strlcat(timestamp, usec, sizeof(timestamp));
	memset(buffer, 0, sizeof(buffer));
	g_snprintf(buffer, sizeof(buffer), "%s %s 000000 ", incoming ? "I" : "O", timestamp);
	int i=0;
	int stop = instance->truncate ? (len > instance->truncate ? instance->truncate : len) : len;
	for(i=0; i<stop; i++) {
		memset(byte, 0, sizeof(byte));
		g_snprintf(byte, sizeof(byte), " %02x", (unsigned char)buf[i]);
		g_strlcat(buffer, byte, sizeof(buffer));
	}
	g_strlcat(buffer, " ", sizeof(buffer));
	g_strlcat(buffer, janus_text2pcap_packet_string(type), sizeof(buffer));
	if(format) {
		/* This callback has variable arguments (error string) */
		char custom[512];
		va_list ap;
		va_start(ap, format);
		g_vsnprintf(custom, sizeof(custom), format, ap);
		va_end(ap);
		g_strlcat(buffer, " ", sizeof(buffer));
		g_strlcat(buffer, custom, sizeof(buffer));
	}
	g_strlcat(buffer, "\r\n", sizeof(buffer));
	/* Save textified packet on file */
	int temp = 0, buflen = strlen(buffer), tot = buflen;
	while(tot > 0) {
		temp = fwrite(buffer+buflen-tot, sizeof(char), tot, instance->file);
		if(temp <= 0) {
			JANUS_LOG(LOG_ERR, "Error dumping packet...\n");
			janus_mutex_unlock_nodebug(&instance->mutex);
			return -2;
		}
		tot -= temp;
	}
	/* Done */
	janus_mutex_unlock_nodebug(&instance->mutex);
	return 0;
}

int janus_text2pcap_close(janus_text2pcap *instance) {
	if(instance == NULL)
		return -1;
	janus_mutex_lock_nodebug(&instance->mutex);
	if(!g_atomic_int_compare_and_exchange(&instance->writable, 1, 0)) {
		janus_mutex_unlock_nodebug(&instance->mutex);
		return 0;
	}
	fclose(instance->file);
	instance->file = NULL;
	janus_mutex_unlock_nodebug(&instance->mutex);
	return 0;
}

void janus_text2pcap_free(janus_text2pcap *instance) {
	if(instance == NULL)
		return;
	janus_text2pcap_close(instance);
	g_free(instance->filename);
	g_free(instance);
}
