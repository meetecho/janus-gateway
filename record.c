/*! \file    record.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Audio/Video recorder
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
 
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>

#include <glib.h>
#include <jansson.h>

#include "record.h"
#include "debug.h"
#include "utils.h"


/* Info header in the structured recording */
static const char *header = "MJR00001";
/* Frame header in the structured recording */
static const char *frame_header = "MEETECHO";


janus_recorder *janus_recorder_create(const char *dir, int video, const char *filename) {
	janus_recorder *rc = g_malloc0(sizeof(janus_recorder));
	if(rc == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	rc->dir = NULL;
	rc->filename = NULL;
	rc->file = NULL;
	rc->created = janus_get_real_time();
	if(dir != NULL) {
		/* Check if this directory exists, and create it if needed */
		struct stat s;
		int err = stat(dir, &s);
		if(err == -1) {
			if(ENOENT == errno) {
				/* Directory does not exist, try creating it */
				if(janus_mkdir(dir, 0755) < 0) {
					JANUS_LOG(LOG_ERR, "mkdir error: %d\n", errno);
					return NULL;
				}
			} else {
				JANUS_LOG(LOG_ERR, "stat error: %d\n", errno);
				return NULL;
			}
		} else {
			if(S_ISDIR(s.st_mode)) {
				/* Directory exists */
				JANUS_LOG(LOG_VERB, "Directory exists: %s\n", dir);
			} else {
				/* File exists but it's not a directory? */
				JANUS_LOG(LOG_ERR, "Not a directory? %s\n", dir);
				return NULL;
			}
		}
	}
	char newname[1024];
	memset(newname, 0, 1024);
	if(filename == NULL) {
		/* Choose a random username */
		g_snprintf(newname, 1024, "janus-recording-%"SCNu32".mjr", g_random_int());
	} else {
		/* Just append the extension */
		g_snprintf(newname, 1024, "%s.mjr", filename);
	}
	/* Try opening the file now */
	if(dir == NULL) {
		rc->file = fopen(newname, "wb");
	} else {
		char path[1024];
		memset(path, 0, 1024);
		g_snprintf(path, 1024, "%s/%s", dir, newname);
		rc->file = fopen(path, "wb");
	}
	if(rc->file == NULL) {
		JANUS_LOG(LOG_ERR, "fopen error: %d\n", errno);
		return NULL;
	}
	if(dir)
		rc->dir = g_strdup(dir);
	rc->filename = g_strdup(newname);
	rc->video = video;
	/* Write the first part of the header */
	fwrite(header, sizeof(char), strlen(header), rc->file);
	rc->writable = 1;
	/* We still need to also write the info header first */
	rc->header = 0;
	janus_mutex_init(&rc->mutex);
	return rc;
}

int janus_recorder_save_frame(janus_recorder *recorder, char *buffer, int length) {
	if(!recorder)
		return -1;
	janus_mutex_lock_nodebug(&recorder->mutex);
	if(!buffer || length < 1) {
		janus_mutex_unlock_nodebug(&recorder->mutex);
		return -2;
	}
	if(!recorder->file) {
		janus_mutex_unlock_nodebug(&recorder->mutex);
		return -3;
	}
	if(!recorder->writable) {
		janus_mutex_unlock_nodebug(&recorder->mutex);
		return -4;
	}
	if(!recorder->header) {
		/* Write info header as a JSON formatted info */
		json_t *info = json_object();
		/* FIXME Codecs should be configurable in the future */
		json_object_set_new(info, "t", json_string(recorder->video ? "v" : "a"));		/* Audio/Video */
		json_object_set_new(info, "c", json_string(recorder->video ? "vp8" : "opus"));	/* Media codec */
		json_object_set_new(info, "s", json_integer(recorder->created));				/* Created time */
		json_object_set_new(info, "u", json_integer(janus_get_real_time()));			/* First frame written time */
		gchar *info_text = json_dumps(info, JSON_PRESERVE_ORDER);
		json_decref(info);
		uint16_t info_bytes = htons(strlen(info_text));
		fwrite(&info_bytes, sizeof(uint16_t), 1, recorder->file);
		fwrite(info_text, sizeof(char), strlen(info_text), recorder->file);
		/* Done */
		recorder->header = 1;
	}
	/* Write frame header */
	fwrite(frame_header, sizeof(char), strlen(frame_header), recorder->file);
	uint16_t header_bytes = htons(length);
	fwrite(&header_bytes, sizeof(uint16_t), 1, recorder->file);
	/* Save packet on file */
	int temp = 0, tot = length;
	while(tot > 0) {
		temp = fwrite(buffer+length-tot, sizeof(char), tot, recorder->file);
		if(temp <= 0) {
			JANUS_LOG(LOG_ERR, "Error saving frame...\n");
			janus_mutex_unlock_nodebug(&recorder->mutex);
			return -5;
		}
		tot -= temp;
	}
	/* Done */
	janus_mutex_unlock_nodebug(&recorder->mutex);
	return 0;
}

int janus_recorder_close(janus_recorder *recorder) {
	if(!recorder || !recorder->writable)
		return -1;
	janus_mutex_lock_nodebug(&recorder->mutex);
	recorder->writable = 0;
	if(recorder->file) {
		fseek(recorder->file, 0L, SEEK_END);
		size_t fsize = ftell(recorder->file);
		fseek(recorder->file, 0L, SEEK_SET);
		JANUS_LOG(LOG_INFO, "File is %zu bytes: %s\n", fsize, recorder->filename);
	}
	janus_mutex_unlock_nodebug(&recorder->mutex);
	return 0;
}

int janus_recorder_free(janus_recorder *recorder) {
	if(!recorder)
		return -1;
	janus_recorder_close(recorder);
	janus_mutex_lock_nodebug(&recorder->mutex);
	if(recorder->dir)
		g_free(recorder->dir);
	recorder->dir = NULL;
	if(recorder->filename)
		g_free(recorder->filename);
	recorder->filename = NULL;
	if(recorder->file)
		fclose(recorder->file);
	recorder->file = NULL;
	janus_mutex_unlock_nodebug(&recorder->mutex);
	g_free(recorder);
	return 0;
}
