/*! \file    pcap2mjr.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Helper tool to convert .pcap files to Janus .mjr recordings
 * \details  Our Janus WebRTC gateway provides a simple helper (janus_recorder)
 * to allow plugins to record audio, video and text frames sent by users.
 * These recordings can then be processed and converted to playable files,
 * or replayed via WebRTC again. The \c pcap2mjr tool is a simple utility
 * that allows you take .pcap network captures, extract a specific RTP
 * session via its SSRC, and convert it to an .mjr Janus recording instead.
 * Its main purpose is helping convert .pcap captures to media files, or
 * make it easier to replay them via Janus.
 *
 * Using the utility is quite simple. Just pass, as arguments to the tool,
 * the SSRC to extract, the codec used for the RTP packets originally, the
 * path to the .pcap source file, and the path to the destination file, e.g.:
 *
\verbatim
./pcap2mjr -c vp8 -s 12345678 /path/to/source.pcap /path/to/destination.mjr
\endverbatim
 *
 * If the tool can't detect any RTP packet with that SSRC, it will result in an error.
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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <errno.h>

#include <glib.h>
#include <jansson.h>

#include <pcap.h>
#include <pcap/sll.h>

#include "../debug.h"
#include "p2m-cmdline.h"
#include "pp-rtp.h"


#define htonll(x) ((1==htonl(1)) ? (x) : ((gint64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((gint64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

int janus_log_level = 4;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = TRUE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;

int working = 0;

/* Info header in the structured recording */
static const char *header = "MJR00002";
/* Frame header in the structured recording */
static const char *frame_header = "MEET";

/* Ethernet header */
typedef struct pcap2mjr_ethernet_header {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
} pcap2mjr_ethernet_header;


/* Signal handler */
static void janus_p2m_handle_signal(int signum) {
	working = 0;
}

/* Main Code */
int main(int argc, char *argv[])
{
	struct gengetopt_args_info args_info;
	/* Let's call our cmdline parser */
	if(cmdline_parser(argc, argv, &args_info) != 0)
		exit(1);

	janus_log_init(FALSE, TRUE, NULL);
	atexit(janus_log_destroy);

	/* Evaluate arguments to find source and target */
	uint32_t ssrc = args_info.ssrc_arg;
	const char *codec = args_info.codec_arg;
	gboolean show_warnings = args_info.warnings_given;
	gboolean video = FALSE;
	if(!strcasecmp(codec, "vp8") || !strcasecmp(codec, "vp9") || !strcasecmp(codec, "h264")
			|| !strcasecmp(codec, "av1") || !strcasecmp(codec, "h265")) {
		video = TRUE;
	} else if(!strcasecmp(codec, "opus") || !strcasecmp(codec, "multiopus")
			|| !strcasecmp(codec, "g711") || !strcasecmp(codec, "pcmu") || !strcasecmp(codec, "pcma")
			|| !strcasecmp(codec, "g722")) {
		video = FALSE;
	} else if(!strcasecmp(codec, "text") || !strcasecmp(codec, "binary")) {
		/* We only do processing for RTP */
		JANUS_LOG(LOG_ERR, "Data channels not supported by this tool\n");
		cmdline_parser_free(&args_info);
		exit(1);
	} else {
		JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", codec);
		cmdline_parser_free(&args_info);
		exit(1);
	}
	char *source = NULL, *destination = NULL, *setting = NULL;
	int i=0;
	for(i=1; i<argc; i++) {
		if(argv[i] == NULL || strlen(argv[i]) == 0) {
			setting = NULL;
			continue;
		}
		if(argv[i][0] == '-') {
			setting = argv[i];
			continue;
		}
		if(setting == NULL || (
				(strcmp(setting, "-c")) && (strcmp(setting, "--codec")) &&
				(strcmp(setting, "-s")) && (strcmp(setting, "--ssrc"))
		)) {
			if(source == NULL)
				source = argv[i];
			else if(destination == NULL)
				destination = argv[i];
		}
		setting = NULL;
	}
	if(source == NULL || destination == NULL) {
		cmdline_parser_print_help();
		cmdline_parser_free(&args_info);
		exit(1);
	}
	JANUS_LOG(LOG_INFO, "[%s/%"SCNu32"] %s --> %s\n", codec, ssrc, source, destination);

	/* Open and parse the pcap file */
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_offline(source, errbuf);
	if(pcap == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s: %s\n", source, errbuf);
		cmdline_parser_free(&args_info);
		exit(1);
	}
	int link = pcap_datalink(pcap);
	if(link != DLT_LINUX_SLL && link != DLT_EN10MB) {
		JANUS_LOG(LOG_ERR, "Unsupported link type %d (%s) in capture\n",
			link, pcap_datalink_val_to_name(link));
		cmdline_parser_free(&args_info);
		exit(1);
	}

	/* Create the target file */
	FILE *outfile = fopen(destination, "wb");
	if(outfile == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
		cmdline_parser_free(&args_info);
		pcap_close(pcap);
		exit(1);
	}
	/* Write the first part of the header */
	size_t res = fwrite(header, sizeof(char), strlen(header), outfile);
	if(res != strlen(header)) {
		JANUS_LOG(LOG_ERR, "Couldn't write .mjr header (%zu != %zu, %s)\n",
			res, strlen(header), strerror(errno));
		cmdline_parser_free(&args_info);
		pcap_close(pcap);
		exit(1);
	}

	/* Handle SIGINT */
	working = 1;
	signal(SIGINT, janus_p2m_handle_signal);

	/* TODO Loop */
    struct pcap_pkthdr *header = NULL;
    const u_char *buffer = NULL, *temp = NULL;
	uint32_t count = 0, written = 0, pssrc = 0;
    int ret = 0;
    size_t min_size = sizeof(pcap2mjr_ethernet_header) + sizeof(struct iphdr) +
		sizeof(struct udphdr) + 12, pkt_size = 0;
	gboolean header_written = FALSE;
	gint64 start_ts = 0, pkt_ts = 0;
    while(working && (ret = pcap_next_ex(pcap, &header, &buffer)) >= 0) {
		count++;
		if(header->len != header->caplen) {
			if(show_warnings) {
				JANUS_LOG(LOG_WARN, "Packet and capture lengths differ (%d != %d), skipping packet #%"SCNu32"\n",
					header->len, header->caplen, count);
			}
			continue;
		}
		if(header->len < min_size) {
			if(show_warnings) {
				JANUS_LOG(LOG_WARN, "Packet too small (< %zu), skipping packet #%"SCNu32"\n", min_size, count);
			}
			continue;
		}
		temp = buffer;
		pkt_size = header->len;
		pkt_ts = header->ts.tv_sec*G_USEC_PER_SEC + header->ts.tv_usec;
		if(start_ts == 0)
			start_ts = pkt_ts;
		/* Traverse all the headers */
		int protocol = 0;
		if(link == DLT_EN10MB) {
			/* Ethernet */
			pcap2mjr_ethernet_header *eth = (pcap2mjr_ethernet_header *)temp;
			protocol = ntohs(eth->type);
			temp += sizeof(pcap2mjr_ethernet_header);
			pkt_size -= sizeof(pcap2mjr_ethernet_header);
		} else {
			/* Linux Cooked Capture */
			struct sll_header *lcc = (struct sll_header *)temp;
			protocol = ntohs(lcc->sll_protocol);
			temp += sizeof(struct sll_header);
			pkt_size -= sizeof(struct sll_header);
		}
		if(protocol == 0x0800) {
			/* IPv4 */
			struct iphdr *v4 = (struct iphdr *)temp;
			protocol = v4->protocol;
			temp += sizeof(struct iphdr);
			pkt_size -= sizeof(struct iphdr);
		} else if(protocol == 0x86DD) {
			/* IPv6 */
			struct ip6_hdr *v6 = (struct ip6_hdr *)temp;
			protocol = v6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
			temp += sizeof(struct ip6_hdr);
			pkt_size -= sizeof(struct ip6_hdr);
		} else {
			if(show_warnings) {
				JANUS_LOG(LOG_WARN, "Not an IPv4 or IPv6 packet, skipping\n");
			}
			continue;
		}
		if(protocol != 17) {
			if(show_warnings) {
				JANUS_LOG(LOG_WARN, "Not an UDP packet, skipping\n");
			}
			continue;
		}
		/* UDP */
		temp += sizeof(struct udphdr);
		pkt_size -= sizeof(struct udphdr);
		/* Make sure this is an RTP packet */
		janus_pp_rtp_header *rtp = (janus_pp_rtp_header *)temp;
		if(rtp->version != 2 || (rtp->type >= 64 && rtp->type < 96)) {
			if(show_warnings) {
				JANUS_LOG(LOG_WARN, "Not an RTP packet, skipping packet #%"SCNu32"\n", count);
			}
			continue;
		}
		pssrc = htonl(rtp->ssrc);
		if(pssrc != ssrc) {
			if(show_warnings) {
				JANUS_LOG(LOG_WARN, "Not the SSRC we need (%"SCNu32" != %"SCNu32"), skipping packet #%"SCNu32"\n",
					pssrc, ssrc, count);
			}
			continue;
		}
		/* Save the packet, but first check if we've written the .mjr header already */
		if(!header_written) {
			/* Write info header as a JSON formatted info */
			header_written = TRUE;
			json_t *info = json_object();
			/* FIXME Codecs should be configurable in the future */
			const char *type = NULL;
			if(video)
				type = "v";
			else
				type = "a";
			json_object_set_new(info, "t", json_string(type));
			json_object_set_new(info, "c", json_string(codec));
			json_object_set_new(info, "s", json_integer(pkt_ts));
			json_object_set_new(info, "u", json_integer(pkt_ts));
			gchar *info_text = json_dumps(info, JSON_PRESERVE_ORDER);
			json_decref(info);
			uint16_t info_bytes = htons(strlen(info_text));
			size_t res = fwrite(&info_bytes, sizeof(uint16_t), 1, outfile);
			if(res != 1) {
				JANUS_LOG(LOG_WARN, "Couldn't write size of JSON header in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
					res, sizeof(uint16_t), strerror(errno));
			}
			res = fwrite(info_text, sizeof(char), strlen(info_text), outfile);
			if(res != strlen(info_text)) {
				JANUS_LOG(LOG_WARN, "Couldn't write JSON header in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
					res, strlen(info_text), strerror(errno));
			}
			free(info_text);
		}
		/* Write frame header (fixed part[4], timestamp[4], length[2]) */
		size_t res = fwrite(frame_header, sizeof(char), strlen(frame_header), outfile);
		if(res != strlen(frame_header)) {
			JANUS_LOG(LOG_WARN, "Couldn't write frame header in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
				res, strlen(frame_header), strerror(errno));
		}
		uint32_t timestamp = (uint32_t)(pkt_ts > start_ts ? ((pkt_ts - start_ts)/1000) : 0);
		timestamp = htonl(timestamp);
		res = fwrite(&timestamp, sizeof(uint32_t), 1, outfile);
		if(res != 1) {
			JANUS_LOG(LOG_WARN, "Couldn't write frame timestamp in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
				res, sizeof(uint32_t), strerror(errno));
		}
		uint16_t header_bytes = htons(pkt_size);
		res = fwrite(&header_bytes, sizeof(uint16_t), 1, outfile);
		if(res != 1) {
			JANUS_LOG(LOG_WARN, "Couldn't write size of frame in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
				res, sizeof(uint16_t), strerror(errno));
		}
		/* Save packet on file */
		written++;
		int tmp = 0, tot = pkt_size;
		while(tot > 0) {
			tmp = fwrite(temp+pkt_size-tot, sizeof(char), tot, outfile);
			if(tmp <= 0) {
				JANUS_LOG(LOG_ERR, "Error saving frame, stopping here...\n");
				goto done;
			}
			tot -= tmp;
		}
	}
	JANUS_LOG(LOG_INFO, "Saved %"SCNu32" out of %"SCNu32" packets\n", written, count);

done:
	/* We're done */
	pcap_close(pcap);
	fclose(outfile);
	outfile = fopen(destination, "rb");
	if(outfile == NULL) {
		JANUS_LOG(LOG_WARN, "No destination file %s??\n", destination);
	} else {
		fseek(outfile, 0L, SEEK_END);
		size_t fsize = ftell(outfile);
		fseek(outfile, 0L, SEEK_SET);
		JANUS_LOG(LOG_INFO, "%s is %zu bytes\n", destination, fsize);
		fclose(outfile);
	}

	cmdline_parser_free(&args_info);
	JANUS_LOG(LOG_INFO, "Bye!\n");
	return 0;
}
