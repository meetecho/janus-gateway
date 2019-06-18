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

#ifndef _JANUS_RECORD_H
#define _JANUS_RECORD_H

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
	/*! \brief When the recording file has been created */
	gint64 created;
	/*! \brief Media this instance is recording */
	janus_recorder_medium type;
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
