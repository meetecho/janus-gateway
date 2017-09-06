/*! \file    text2pcap.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Dumping of RTP/RTCP packets to text2pcap format (headers)
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
 
#ifndef _JANUS_TEXT2PCAP_H
#define _JANUS_TEXT2PCAP_H

#include <glib.h>

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mutex.h"

/*! \brief Instance of a text2pcap recorder */
typedef struct janus_text2pcap {
	/*! \brief Absolute path to where the text2pcap file is stored */ 
	char *filename;
	/*! \brief Pointer to the file handle */
	FILE *file;
	/*! \brief Number of bytes to truncate at */
	int truncate;
	/*! \brief Whether we can write to this file or not */
	volatile int writable;
	/*! \brief Mutex to lock/unlock this recorder instance */ 
	janus_mutex mutex;
} janus_text2pcap;

/*! \brief Packet types we can dump */
typedef enum janus_text2pcap_packet {
	JANUS_TEXT2PCAP_RTP,
	JANUS_TEXT2PCAP_RTCP,
	JANUS_TEXT2PCAP_DATA
} janus_text2pcap_packet;
const char *janus_text2pcap_packet_string(janus_text2pcap_packet type);

/*! \brief Create a text2pcap recorder
 * \note If no target directory is provided, the current directory will be used. If no filename
 * is passed, a random filename will be used.
 * @param[in] dir Path of the directory to save the recording into (will try to create it if it doesn't exist)
 * @param[in] filename Filename to use for the recording
 * @param[in] truncate Number of bytes to truncate each packet at (0 to not truncate at all)
 * @returns A valid janus_text2pcap instance in case of success, NULL otherwise */
janus_text2pcap *janus_text2pcap_create(const char *dir, const char *filename, int truncate);

/*! \brief Dump an RTP or RTCP packet
 * @param[in] instance Instance of the janus_text2pcap recorder to dump the packet to
 * @param[in] type Type of the packet we're going to dump
 * @param[in] incoming Whether this is an incoming or outgoing packet
 * @param[in] buf Packet data to dump
 * @param[in] len Size of the packet data to dump
 * @param[in] format Format for the optional string to append to the line, if any
 * @returns 0 in case of success, a negative integer otherwise */
int janus_text2pcap_dump(janus_text2pcap *instance,
	janus_text2pcap_packet type, gboolean incoming, char *buf, int len, const char *format, ...) G_GNUC_PRINTF(6, 7);

/*! \brief Close a text2pcap recorder
 * @param[in] instance Instance of the janus_text2pcap recorder to close
 * @returns 0 in case of success, a negative integer otherwise */
int janus_text2pcap_close(janus_text2pcap *instance);

/*! \brief Free a text2pcap instance
 * @param[in] instance Instance of the janus_text2pcap recorder to free */
void janus_text2pcap_free(janus_text2pcap *instance);

#endif
