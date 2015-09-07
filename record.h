/*! \file    record.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Audio/Video recorder (headers)
 * \details  Implementation of a simple recorder utility that plugins
 * can make use of to record audio/video frames to a Janus file. This
 * file just saves RTP frames in a structured way, so that they can be
 * post-processed later on to get a valid container file (e.g., a .opus
 * file for Opus audio or a .webm file for VP8 video) and keep things
 * simpler on the plugin and core side.
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


/*! \brief Structure that represents a recorder */
typedef struct janus_recorder {
	/*! \brief Absolute path to the directory where the recorder file is stored */ 
	char *dir;
	/*! \brief Filename of this recorder file */ 
	char *filename;
	/*! \brief Recording file */
	FILE *file;
	/*! \brief When the recording file has been created */
	gint64 created;
	/*! \brief Whether this recorder instance is going to record video or audio */ 
	int video:1;
	/*! \brief Whether the info header for this recorder instance has already been written or not */
	int header:1;
	/*! \brief Whether this recorder instance can be used for writing or not */ 
	int writable:1;
	/*! \brief Mutex to lock/unlock this recorder instance */ 
	janus_mutex mutex;
} janus_recorder;


/*! \brief Create a new recorder
 * \note If no target directory is provided, the current directory will be used. If no filename
 * is passed, a random filename will be used.
 * @param[in] dir Path of the directory to save the recording into (will try to create it if it doesn't exist)
 * @param[in] video If this recorder is for video or audio
 * @param[in] filename Filename to use for the recording
 * @returns A valid janus_recorder instance in case of success, NULL otherwise */
janus_recorder *janus_recorder_create(const char *dir, int video, const char *filename);
/*! \brief Save an RTP frame in the recorder
 * @param[in] recorder The janus_recorder instance to save the frame to
 * @param[in] buffer The frame data to save
 * @param[in] length The frame data length
 * @returns 0 in case of success, a negative integer otherwise */
int janus_recorder_save_frame(janus_recorder *recorder, char *buffer, int length);
/*! \brief Close the recorder
 * @param[in] recorder The janus_recorder instance to close
 * @returns 0 in case of success, a negative integer otherwise */
int janus_recorder_close(janus_recorder *recorder);
/*! \brief Free the recorder resources
 * @param[in] recorder The janus_recorder instance to free
 * @returns 0 in case of success, a negative integer otherwise */
int janus_recorder_free(janus_recorder *recorder);

#endif
