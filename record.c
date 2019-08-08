/*! \file    record.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Audio/Video recorder
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

#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>

#include <glib.h>
#include <jansson.h>

#include "record.h"
#include "debug.h"
#include "utils.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((gint64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((gint64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))


/* Info header in the structured recording */
static const char *header = "MJR00002";
/* Frame header in the structured recording */
static const char *frame_header = "MEET";

/* Whether the filenames should have a temporary extension, while saving, or not (default=false) */
static gboolean rec_tempname = FALSE;
/* Extension to add in case tempnames is true (default="tmp" --> ".tmp") */
static char *rec_tempext = NULL;

void janus_recorder_init(gboolean tempnames, const char *extension) {
	JANUS_LOG(LOG_INFO, "Initializing recorder code\n");
	if(tempnames) {
		rec_tempname = TRUE;
		if(extension == NULL) {
			rec_tempext = g_strdup("tmp");
			JANUS_LOG(LOG_INFO, "  -- No extension provided, using default one (tmp)\n");
		} else {
			rec_tempext = g_strdup(extension);
			JANUS_LOG(LOG_INFO, "  -- Using temporary extension .%s\n", rec_tempext);
		}
	}
}

void janus_recorder_deinit(void) {
	rec_tempname = FALSE;
	g_free(rec_tempext);
}

static void janus_recorder_free(const janus_refcount *recorder_ref) {
	janus_recorder *recorder = janus_refcount_containerof(recorder_ref, janus_recorder, ref);
	/* This recorder can be destroyed, free all the resources */
	janus_recorder_close(recorder);
	g_free(recorder->dir);
	recorder->dir = NULL;
	g_free(recorder->filename);
	recorder->filename = NULL;
	fclose(recorder->file);
	recorder->file = NULL;
	g_free(recorder->codec);
	recorder->codec = NULL;
	g_free(recorder);
}

janus_recorder *janus_recorder_create(const char *dir, const char *codec, const char *filename) {
	janus_recorder_medium type = JANUS_RECORDER_AUDIO;
	if(codec == NULL) {
		JANUS_LOG(LOG_ERR, "Missing codec information\n");
		return NULL;
	}
	if(!strcasecmp(codec, "vp8") || !strcasecmp(codec, "vp9") || !strcasecmp(codec, "h264")) {
		type = JANUS_RECORDER_VIDEO;
	} else if(!strcasecmp(codec, "opus")
			|| !strcasecmp(codec, "g711") || !strcasecmp(codec, "pcmu") || !strcasecmp(codec, "pcma")
			|| !strcasecmp(codec, "g722")) {
		type = JANUS_RECORDER_AUDIO;
	} else if(!strcasecmp(codec, "text")) {
		/* FIXME We only handle text on data channels, so that's the only thing we can save too */
		type = JANUS_RECORDER_DATA;
	} else {
		/* We don't recognize the codec: while we might go on anyway, we'd rather fail instead */
		JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", codec);
		return NULL;
	}
	/* Create the recorder */
	janus_recorder *rc = g_malloc0(sizeof(janus_recorder));
	rc->dir = NULL;
	rc->filename = NULL;
	rc->file = NULL;
	rc->codec = g_strdup(codec);
	rc->created = janus_get_real_time();
	const char *rec_dir = NULL;
	const char *rec_file = NULL;
	char *copy_for_parent = NULL;
	char *copy_for_base = NULL;
	/* Check dir and filename values */
	if (filename != NULL) {
		/* Helper copies to avoid overwriting */
		copy_for_parent = g_strdup(filename);
		copy_for_base = g_strdup(filename);
		/* Get filename parent folder */
		const char *filename_parent = dirname(copy_for_parent);
		/* Get filename base file */
		const char *filename_base = basename(copy_for_base);
		if (!dir) {
			/* If dir is NULL we have to create filename_parent and filename_base */
			rec_dir = filename_parent;
			rec_file = filename_base;
		} else {
			/* If dir is valid we have to create dir and filename*/
			rec_dir = dir;
			rec_file = filename;
			if (strcasecmp(filename_parent, ".") || strcasecmp(filename_base, filename)) {
				JANUS_LOG(LOG_WARN, "Unsupported combination of dir and filename %s %s\n", dir, filename);
			}
		}
	}
	if(rec_dir != NULL) {
		/* Check if this directory exists, and create it if needed */
		struct stat s;
		int err = stat(rec_dir, &s);
		if(err == -1) {
			if(ENOENT == errno) {
				/* Directory does not exist, try creating it */
				if(janus_mkdir(rec_dir, 0755) < 0) {
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
				JANUS_LOG(LOG_VERB, "Directory exists: %s\n", rec_dir);
			} else {
				/* File exists but it's not a directory? */
				JANUS_LOG(LOG_ERR, "Not a directory? %s\n", rec_dir);
				return NULL;
			}
		}
	}
	char newname[1024];
	memset(newname, 0, 1024);
	if(rec_file == NULL) {
		/* Choose a random username */
		if(!rec_tempname) {
			/* Use .mjr as an extension right away */
			g_snprintf(newname, 1024, "janus-recording-%"SCNu32".mjr", janus_random_uint32());
		} else {
			/* Append the temporary extension to .mjr, we'll rename when closing */
			g_snprintf(newname, 1024, "janus-recording-%"SCNu32".mjr.%s", janus_random_uint32(), rec_tempext);
		}
	} else {
		/* Just append the extension */
		if(!rec_tempname) {
			/* Use .mjr as an extension right away */
			g_snprintf(newname, 1024, "%s.mjr", rec_file);
		} else {
			/* Append the temporary extension to .mjr, we'll rename when closing */
			g_snprintf(newname, 1024, "%s.mjr.%s", rec_file, rec_tempext);
		}
	}
	/* Try opening the file now */
	if(rec_dir == NULL) {
		rc->file = fopen(newname, "wb");
	} else {
		char path[1024];
		memset(path, 0, 1024);
		g_snprintf(path, 1024, "%s/%s", rec_dir, newname);
		rc->file = fopen(path, "wb");
	}
	if(rc->file == NULL) {
		JANUS_LOG(LOG_ERR, "fopen error: %d\n", errno);
		return NULL;
	}
	if(rec_dir)
		rc->dir = g_strdup(rec_dir);
	rc->filename = g_strdup(newname);
	rc->type = type;
	/* Write the first part of the header */
	fwrite(header, sizeof(char), strlen(header), rc->file);
	g_atomic_int_set(&rc->writable, 1);
	/* We still need to also write the info header first */
	g_atomic_int_set(&rc->header, 0);
	janus_mutex_init(&rc->mutex);
	/* Done */
	g_atomic_int_set(&rc->destroyed, 0);
	janus_refcount_init(&rc->ref, janus_recorder_free);
	g_free(copy_for_parent);
	g_free(copy_for_base);
	return rc;
}

int janus_recorder_save_frame(janus_recorder *recorder, char *buffer, uint length) {
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
	if(!g_atomic_int_get(&recorder->writable)) {
		janus_mutex_unlock_nodebug(&recorder->mutex);
		return -4;
	}
	gint64 now = janus_get_monotonic_time();
	if(!g_atomic_int_get(&recorder->header)) {
		/* Write info header as a JSON formatted info */
		json_t *info = json_object();
		/* FIXME Codecs should be configurable in the future */
		const char *type = NULL;
		if(recorder->type == JANUS_RECORDER_AUDIO)
			type = "a";
		else if(recorder->type == JANUS_RECORDER_VIDEO)
			type = "v";
		else if(recorder->type == JANUS_RECORDER_DATA)
			type = "d";
		json_object_set_new(info, "t", json_string(type));								/* Audio/Video/Data */
		json_object_set_new(info, "c", json_string(recorder->codec));					/* Media codec */
		json_object_set_new(info, "s", json_integer(recorder->created));				/* Created time */
		json_object_set_new(info, "u", json_integer(janus_get_real_time()));			/* First frame written time */
		gchar *info_text = json_dumps(info, JSON_PRESERVE_ORDER);
		json_decref(info);
		uint16_t info_bytes = htons(strlen(info_text));
		fwrite(&info_bytes, sizeof(uint16_t), 1, recorder->file);
		fwrite(info_text, sizeof(char), strlen(info_text), recorder->file);
		free(info_text);
		/* Done */
		recorder->started = now;
		g_atomic_int_set(&recorder->header, 1);
	}
	/* Write frame header (fixed part[4], timestamp[4], length[2]) */
	fwrite(frame_header, sizeof(char), strlen(frame_header), recorder->file);
	uint32_t timestamp = (uint32_t)(now > recorder->started ? ((now - recorder->started)/1000) : 0);
	timestamp = htonl(timestamp);
	fwrite(&timestamp, sizeof(uint32_t), 1, recorder->file);
	uint16_t header_bytes = htons(recorder->type == JANUS_RECORDER_DATA ? (length+sizeof(gint64)) : length);
	fwrite(&header_bytes, sizeof(uint16_t), 1, recorder->file);
	if(recorder->type == JANUS_RECORDER_DATA) {
		/* If it's data, then we need to prepend timing related info, as it's not there by itself */
		gint64 now = htonll(janus_get_real_time());
		fwrite(&now, sizeof(gint64), 1, recorder->file);
	}
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
	if(!recorder || !g_atomic_int_compare_and_exchange(&recorder->writable, 1, 0))
		return -1;
	janus_mutex_lock_nodebug(&recorder->mutex);
	if(recorder->file) {
		fseek(recorder->file, 0L, SEEK_END);
		size_t fsize = ftell(recorder->file);
		fseek(recorder->file, 0L, SEEK_SET);
		JANUS_LOG(LOG_INFO, "File is %zu bytes: %s\n", fsize, recorder->filename);
	}
	if(rec_tempname) {
		/* We need to rename the file, to remove the temporary extension */
		char newname[1024];
		memset(newname, 0, 1024);
		g_snprintf(newname, strlen(recorder->filename)-strlen(rec_tempext), "%s", recorder->filename);
		char oldpath[1024];
		memset(oldpath, 0, 1024);
		char newpath[1024];
		memset(newpath, 0, 1024);
		if(recorder->dir) {
			g_snprintf(newpath, 1024, "%s/%s", recorder->dir, newname);
			g_snprintf(oldpath, 1024, "%s/%s", recorder->dir, recorder->filename);
		} else {
			g_snprintf(newpath, 1024, "%s", newname);
			g_snprintf(oldpath, 1024, "%s", recorder->filename);
		}
		if(rename(oldpath, newpath) != 0) {
			JANUS_LOG(LOG_ERR, "Error renaming %s to %s...\n", recorder->filename, newname);
		} else {
			JANUS_LOG(LOG_INFO, "Recording renamed: %s\n", newname);
			g_free(recorder->filename);
			recorder->filename = g_strdup(newname);
		}
	}
	janus_mutex_unlock_nodebug(&recorder->mutex);
	return 0;
}

void janus_recorder_destroy(janus_recorder *recorder) {
	if(!recorder || !g_atomic_int_compare_and_exchange(&recorder->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&recorder->ref);
}
