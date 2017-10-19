/*! \file    text2pcap.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Dumping of RTP/RTCP packets to text2pcap format
 * \details  Implementation of a simple helper utility that can be used
 * to dump incoming and outgoing RTP/RTCP packets to text2pcap format.
 * The resulting file can then be passed to the \c text2pcap application
 * in order to get a \c .pcap or \c .pcapng file that can be analyzed
 * via Wireshark or similar applications, e.g.:
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

#include <sys/time.h>
 
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

janus_text2pcap *janus_text2pcap_create(const char *dir, const char *filename, int truncate) {
	if(truncate < 0)
		return NULL;
	/* Create the text2pcap instance */
	janus_text2pcap *tp = g_malloc0(sizeof(janus_text2pcap));
	if(tp == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	tp->filename = NULL;
	tp->file = NULL;
	tp->truncate = truncate;
	g_atomic_int_set(&tp->writable, 0);
	if(dir != NULL) {
		/* Create the directory, if needed */
		if(janus_mkdir(dir, 0755) < 0) {
			JANUS_LOG(LOG_ERR, "mkdir error: %d\n", errno);
			return NULL;
		}
	}
	char newname[1024];
	memset(newname, 0, 1024);
	if(filename == NULL) {
		/* Choose a random username */
		g_snprintf(newname, 1024, "janus-text2pcap-%"SCNu32".txt", janus_random_uint32());
	} else {
		/* Just copy the filename */
		g_snprintf(newname, 1024, "%s", filename);
	}
	/* Try opening the file now */
	if(dir == NULL) {
		tp->file = fopen(newname, "ab");
		if(tp->file == NULL)
			tp->file = fopen(newname, "wb");
		if(tp->file != NULL)
			tp->filename = g_strdup(newname);
	} else {
		char path[1024];
		memset(path, 0, 1024);
		g_snprintf(path, 1024, "%s/%s", dir, newname);
		tp->file = fopen(path, "ab");
		if(tp->file == NULL)
			tp->file = fopen(path, "wb");
		if(tp->file != NULL)
			tp->filename = g_strdup(path);
	}
	if(tp->file == NULL) {
		JANUS_LOG(LOG_ERR, "fopen error: %d\n", errno);
		return NULL;
	}
	g_atomic_int_set(&tp->writable, 1);
	janus_mutex_init(&tp->mutex);
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
	/* Prepare text representation of the packet */
	char buffer[5000], timestamp[20], usec[10], byte[10];
	memset(timestamp, 0, sizeof(timestamp));
	memset(usec, 0, sizeof(usec));
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm);
	g_snprintf(usec, sizeof(usec), ".%ld", tv.tv_usec);
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
