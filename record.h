/*! \file    record.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Audio/Video recorder (headers)
 * \details  Implementation of a simple recorder utility that plugins
 * can make use of to record audio/video frames to a Janus file. This
 * file just saves RTP frames in a structured way, so that they can be
 * post-processed later on to get a valid container file (e.g., a .opus
 * file for Opus audio or a .webm file for VP8 video) and keep things
 * simpler on the plugin and core side. Check the \ref recordings
 * documentation for more details.
 * \note If you want to record both audio and video, you'll have to use
 * two different recorders. Any muxing in the same container will have
 * to be done in the post-processing phase.
 *
 * \ingroup core
 * \ref core
 */

#ifndef JANUS_RECORD_H
#define JANUS_RECORD_H

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mutex.h"
#include "refcount.h"


/*! \brief Media types we can record */
typedef enum janus_recorder_medium {
	JANUS_RECORDER_AUDIO,
	JANUS_RECORDER_VIDEO,
	JANUS_RECORDER_DATA
} janus_recorder_medium;

/*! \brief Structure that represents a recorder */
typedef struct janus_recorder {
	/*! \brief Absolute path to the directory where the recorder file is stored */
	char *dir;
	/*! \brief Filename of this recorder file */
	char *filename;
	/*! \brief Recording file */
	FILE *file;
	/*! \brief Codec the packets to record are encoded in ("vp8", "vp9", "h264", "opus", "pcma", "pcmu", "g722") */
	char *codec;
	/*! \brief Codec-specific info (e.g., H.264 or VP9 profile) */
	char *fmtp;
	/*! \brief List of RTP extensions (as a hashtable, indexed by ID) in this recording */
	GHashTable *extensions;
	/*! \brief When the recording file has been created and started */
	gint64 created, started;
	/*! \brief Media this instance is recording */
	janus_recorder_medium type;
	/*! \brief Whether the recording contains end-to-end encrypted media or not */
	gboolean encrypted;
	/*! \brief Whether the info header for this recorder instance has already been written or not */
	volatile int header;
	/*! \brief Whether this recorder instance can be used for writing or not */
	volatile int writable;
	/*! \brief Mutex to lock/unlock this recorder instance */
	janus_mutex mutex;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
} janus_recorder;

/*! \brief Initialize the recorder code
 * @param[in] tempnames Whether the filenames should have a temporary extension, while saving, or not
 * @param[in] extension Extension to add in case tempnames is true */
void janus_recorder_init(gboolean tempnames, const char *extension);
/*! \brief De-initialize the recorder code */
void janus_recorder_deinit(void);

/*! \brief Create a new recorder
 * \note If no target directory is provided, the current directory will be used. If no filename
 * is passed, a random filename will be used.
 * @param[in] dir Path of the directory to save the recording into (will try to create it if it doesn't exist)
 * @param[in] codec Codec the packets to record are encoded in ("vp8", "opus", "h264", "g711", "vp9")
 * @param[in] filename Filename to use for the recording
 * @returns A valid janus_recorder instance in case of success, NULL otherwise */
janus_recorder *janus_recorder_create(const char *dir, const char *codec, const char *filename);
/*! \brief Create a new recorder with additional info
 * \note This is to allow adding more arguments to janus_recorder_create, but
 * still keep janus_recorder_create in place for backwards compatibility.
 * @param[in] dir Path of the directory to save the recording into (will try to create it if it doesn't exist)
 * @param[in] codec Codec the packets to record are encoded in ("vp8", "opus", "h264", "g711", "vp9")
 * @param[in] fmtp Codec-specific details (e.g., the H.264 or VP9 profile)
 * @param[in] filename Filename to use for the recording
 * @returns A valid janus_recorder instance in case of success, NULL otherwise */
janus_recorder *janus_recorder_create_full(const char *dir, const char *codec, const char *fmtp, const char *filename);
/*! \brief Add an RTP extension to this recording
 * \note This will only be possible BEFORE the first frame is written, as it needs to
 * be reflected in the .mjr header: doing this after that will return an error.
 * @param[in] recorder The janus_recorder instance to add the extension to
 * @param[in] id Numeric ID of the RTP extension
 * @param[in] extmap Namespace of the RTP extension
 * @returns 0 in case of success, a negative integer otherwise */
int janus_recorder_add_extmap(janus_recorder *recorder, int id, const char *extmap);
/*! \brief Mark this recorder as end-to-end encrypted (e.g., via Insertable Streams)
 * \note This will only be possible BEFORE the first frame is written, as it needs to
 * be reflected in the .mjr header: doing this after that will return an error. Also
 * notice that an encrypted recording will NOT be processable with \c janus-pp-rec
 * out of the box, since the post-processor will not have access to unencrypted media
 * @param[in] recorder The janus_recorder instance to mark as encrypted
 * @returns 0 in case of success, a negative integer otherwise */
int janus_recorder_encrypted(janus_recorder *recorder);
/*! \brief Save an RTP frame in the recorder
 * @param[in] recorder The janus_recorder instance to save the frame to
 * @param[in] buffer The frame data to save
 * @param[in] length The frame data length
 * @returns 0 in case of success, a negative integer otherwise */
int janus_recorder_save_frame(janus_recorder *recorder, char *buffer, uint length);
/*! \brief Close the recorder
 * @param[in] recorder The janus_recorder instance to close
 * @returns 0 in case of success, a negative integer otherwise */
int janus_recorder_close(janus_recorder *recorder);
/*! \brief Destroy the recorder instance
 * @param[in] recorder The janus_recorder instance to destroy */
void janus_recorder_destroy(janus_recorder *recorder);

#endif
