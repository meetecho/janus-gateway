/*! \file    janus-pp-rec.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Simple utility to post-process .mjr \ref recordings saved by Janus
 * \details  As explained in the \ref recordings documentation,
 * our Janus WebRTC server provides a simple helper (janus_recorder)
 * to allow plugins to record audio, video and text frames sent by users. At the time
 * of writing, this helper has been integrated in several plugins in Janus.
 * To keep things simple on the Janus side, though, no processing
 * at all is done in the recording step: this means that the recorder
 * actually only dumps the RTP frames it receives to a file in a structured way,
 * so that they can be post-processed later on to extract playable media
 * files. This utility allows you to process those files, in order to
 * get a working media file you can playout with an external player.
 * The tool will generate a .webm if the recording includes VP8 frames,
 * an .opus if the recording includes Opus frames, an .mp4 if the recording
 * includes H.264 frames, and a .wav file if the recording includes
 * G.711 (mu-law or a-law) frames. In case the recording contains text
 * frames as received via data channels, instead, a .srt file will be
 * generated with the text content and the related timing information.
 *
 * Using the utility is quite simple. Just pass, as arguments to the tool,
 * the path to the .mjr source file you want to post-process, and the
 * path to the destination file, e.g.:
 *
\verbatim
./janus-pp-rec /path/to/source.mjr /path/to/destination.[opus|wav|webm|h264|srt]
\endverbatim
 *
 * An attempt to specify an output format that is not compliant with the
 * recording content (e.g., a .webm for H.264 frames) will result in an
 * error since, again, no transcoding is involved.
 *
 * You can also just print the internal header of the recording, or parse
 * it without processing it (e.g., for debugging), by invoking the tool
 * in a different way:
 *
\verbatim
./janus-pp-rec --json /path/to/source.mjr
./janus-pp-rec --header /path/to/source.mjr
./janus-pp-rec --parse /path/to/source.mjr
\endverbatim
 *
 * For a more complete overview of the available command line settings,
 * launch the tool with no arguments or by passing \c --help and it will
 * show something like this:
 *
\verbatim
Usage: janus-pp-rec [OPTIONS] source.mjr [destination.[opus|wav|webm|mp4|srt]]

  -h, --help                    Print help and exit
  -V, --version                 Print version and exit
  -j, --json                    Only print JSON header  (default=off)
  -H, --header                  Only parse .mjr header  (default=off)
  -p, --parse                   Only parse and re-order packets  (default=off)
  -m, --metadata=metadata       Save this metadata string in the target file
  -r, --postreset-trigger=count Number of packets needed to detect a timestamp
                                  reset (default=200)
  -i, --ignore-first=count      Number of first packets to ignore when
                                  processing, e.g., in case they're cause of
                                  issues (default=0)
  -a, --audiolevel-ext=id       ID of the audio-levels RTP extension
                                  (default=none)
  -v, --videoorient-ext=id      ID of the video-orientation RTP extension
                                  (default=none)
  -d, --debug-level=1-7         Debug/logging level (0=disable debugging,
                                  7=maximum debug level; default=4)
  -D, --debug-timestamps        Enable debug/logging timestamps  (default=off)
  -o, --disable-colors          Disable color in the logging  (default=off)
  -f, --format=STRING           Specifies the output format (overrides the
                                  format from the destination)  (possible
                                  values="opus", "wav", "webm", "mp4",
                                  "srt")
\endverbatim
 *
 * \note This utility does not do any form of transcoding. It just
 * depacketizes the RTP frames in order to get the payload, and saves
 * the frames in a valid container. Any further post-processing (e.g.,
 * muxing audio and video belonging to the same media session in a single
 * .webm file) is up to third-party applications.
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

#include <jansson.h>

#include "../debug.h"
#include "../version.h"
#include "pp-cmdline.h"
#include "pp-rtp.h"
#include "pp-webm.h"
#include "pp-h264.h"
#include "pp-av1.h"
#include "pp-h265.h"
#include "pp-opus.h"
#include "pp-g711.h"
#include "pp-g722.h"
#include "pp-srt.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((gint64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((gint64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

int janus_log_level = 4;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = TRUE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;

gboolean janus_faststart = FALSE;

static janus_pp_frame_packet *list = NULL, *last = NULL;
static char *metadata = NULL;
static int working = 0;

#define DEFAULT_POST_RESET_TRIGGER	200
static int post_reset_trigger = DEFAULT_POST_RESET_TRIGGER;
static int ignore_first_packets = 0;

#define SKEW_DETECTION_WAIT_TIME_SECS 10
#define DEFAULT_AUDIO_SKEW_TH 0
static int audioskew_th = DEFAULT_AUDIO_SKEW_TH;


/* Signal handler */
static void janus_pp_handle_signal(int signum) {
	working = 0;
}

/* Helper method to return an audio level from the related RTP extension, if any */
static int audio_level_extmap_id = -1;
static int janus_pp_rtp_header_extension_parse_audio_level(char *buf, int len, int id, int *level);
/* Helper method to return the video rotation from the related RTP extension, if any */
static int video_orient_extmap_id = -1;
static int janus_pp_rtp_header_extension_parse_video_orientation(char *buf, int len, int id, int *rotation);

typedef struct janus_pp_rtp_skew_context {
	guint32 ssrc, rate;
	guint32 reference_time, start_time, evaluating_start_time;
	guint32 start_ts, last_ts, prev_ts, target_ts;
	guint16 last_seq, prev_seq;
	gint32 prev_delay, active_delay;
	guint32 ts_offset;
	gint16 seq_offset;
} janus_pp_rtp_skew_context;
static gint janus_pp_skew_compensate_audio(janus_pp_frame_packet *pkt, janus_pp_rtp_skew_context *context);

/* Main Code */
int main(int argc, char *argv[])
{
	struct gengetopt_args_info args_info;
	/* Let's call our cmdline parser */
	if(cmdline_parser(argc, argv, &args_info) != 0)
		exit(1);

	janus_log_init(FALSE, TRUE, NULL);
	atexit(janus_log_destroy);

	/* If we're asked to print the JSON header as it is, we must not print anything else */
	gboolean jsonheader_only = FALSE, header_only = FALSE, parse_only = FALSE;
	if(args_info.json_given)
		jsonheader_only = TRUE;
	if(args_info.header_given && !jsonheader_only)
		header_only = TRUE;
	if(args_info.parse_given && !jsonheader_only && !header_only)
		parse_only = TRUE;

	/* We support both command line arguments and, for backwards compatibility, env variables in some cases */
	if(args_info.debug_level_given || (g_getenv("JANUS_PPREC_DEBUG") != NULL)) {
		int val = args_info.debug_level_given ? args_info.debug_level_arg : atoi(g_getenv("JANUS_PPREC_DEBUG"));
		if(val >= LOG_NONE && val <= LOG_MAX)
			janus_log_level = val;
	}
	if(args_info.disable_colors_given)
		janus_log_colors = FALSE;
	if(args_info.debug_timestamps_given)
		janus_log_timestamps = TRUE;
	if(args_info.metadata_given || (g_getenv("JANUS_PPREC_METADATA") != NULL)) {
		metadata = g_strdup(args_info.metadata_given ? args_info.metadata_arg : g_getenv("JANUS_PPREC_METADATA"));
	}
	if(args_info.postreset_trigger_given || (g_getenv("JANUS_PPREC_POSTRESETTRIGGER") != NULL)) {
		int val = args_info.postreset_trigger_given ? args_info.postreset_trigger_arg : atoi(g_getenv("JANUS_PPREC_POSTRESETTRIGGER"));
		if(val >= 0)
			post_reset_trigger = val;
	}
	if(args_info.ignore_first_given || (g_getenv("JANUS_PPREC_IGNOREFIRST") != NULL)) {
		int val = args_info.ignore_first_given ? args_info.ignore_first_arg : atoi(g_getenv("JANUS_PPREC_IGNOREFIRST"));
		if(val >= 0)
			ignore_first_packets = val;
	}

	if(args_info.audiolevel_ext_given || (g_getenv("JANUS_PPREC_AUDIOLEVELEXT") != NULL)) {
		int val = args_info.audiolevel_ext_given ? args_info.audiolevel_ext_arg : atoi(g_getenv("JANUS_PPREC_AUDIOLEVELEXT"));
		if(val >= 0)
			audio_level_extmap_id = val;
	}
	if(args_info.videoorient_ext_given || (g_getenv("JANUS_PPREC_VIDEOORIENTEXT") != NULL)) {
		int val = args_info.videoorient_ext_given ? args_info.videoorient_ext_arg : atoi(g_getenv("JANUS_PPREC_VIDEOORIENTEXT"));
		if(val >= 0)
			video_orient_extmap_id = val;
	}
	char *extension = NULL;
	if(args_info.format_given || (g_getenv("JANUS_PPREC_FORMAT") != NULL)) {
		extension = g_strdup(args_info.format_given ? args_info.format_arg : g_getenv("JANUS_PPREC_FORMAT"));
	}
	if(args_info.faststart_given)
		janus_faststart = TRUE;
	if(args_info.audioskew_given || (g_getenv("JANUS_PPREC_AUDIOSKEW") != NULL)) {
		int val = args_info.audioskew_given ? args_info.audioskew_arg : atoi(g_getenv("JANUS_PPREC_AUDIOSKEW"));
		if(val >= 0)
			audioskew_th = val;
	}

	/* Evaluate arguments to find source and target */
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
				(strcmp(setting, "-m")) && (strcmp(setting, "--metadata")) &&
				(strcmp(setting, "-r")) && (strcmp(setting, "--postreset-trigger")) &&
				(strcmp(setting, "-i")) && (strcmp(setting, "--ignore-first")) &&
				(strcmp(setting, "-a")) && (strcmp(setting, "--audiolevel-ext")) &&
				(strcmp(setting, "-v")) && (strcmp(setting, "--videoorient-ext")) &&
				(strcmp(setting, "-d")) && (strcmp(setting, "--debug-level")) &&
				(strcmp(setting, "-f")) && (strcmp(setting, "--format")) &&
				(strcmp(setting, "-S")) && (strcmp(setting, "--audioskew"))
		)) {
			if(source == NULL)
				source = argv[i];
			else if(destination == NULL)
				destination = argv[i];
		}
		setting = NULL;
	}
	if(source == NULL || (destination == NULL && !jsonheader_only && !header_only && !parse_only)) {
		cmdline_parser_print_help();
		cmdline_parser_free(&args_info);
		exit(1);
	}

	if(!jsonheader_only) {
		JANUS_LOG(LOG_INFO, "Janus version: %d (%s)\n", janus_version, janus_version_string);
		JANUS_LOG(LOG_INFO, "Janus commit: %s\n", janus_build_git_sha);
		JANUS_LOG(LOG_INFO, "Compiled on:  %s\n\n", janus_build_git_time);
		JANUS_LOG(LOG_INFO, "Logging level: %d\n", janus_log_level);
		if(metadata)
			JANUS_LOG(LOG_INFO, "Metadata: %s\n", metadata);
		if(post_reset_trigger != DEFAULT_POST_RESET_TRIGGER)
			JANUS_LOG(LOG_INFO, "Post reset trigger: %d\n", post_reset_trigger);
		if(audioskew_th != DEFAULT_AUDIO_SKEW_TH)
			JANUS_LOG(LOG_INFO, "Audio skew threshold: %d\n", audioskew_th);
		if(ignore_first_packets > 0)
			JANUS_LOG(LOG_INFO, "Ignoring first packets: %d\n", ignore_first_packets);
		if(audio_level_extmap_id > 0)
			JANUS_LOG(LOG_INFO, "Audio level extension ID: %d\n", audio_level_extmap_id);
		if(video_orient_extmap_id > 0)
			JANUS_LOG(LOG_INFO, "Video orientation extension ID: %d\n", video_orient_extmap_id);
		JANUS_LOG(LOG_INFO, "\n");
		if(source != NULL)
			JANUS_LOG(LOG_INFO, "Source file: %s\n", source);
		if(header_only)
			JANUS_LOG(LOG_INFO, "  -- Showing header only\n");
		if(parse_only)
			JANUS_LOG(LOG_INFO, "  -- Parsing header only\n");
		if(destination != NULL)
			JANUS_LOG(LOG_INFO, "Target file: %s\n", destination);
		JANUS_LOG(LOG_INFO, "\n");
	}

	if((destination != NULL) && (extension == NULL)) {
		/* Check the extension of the target file */
		extension = strrchr(destination, '.');
		if(extension == NULL) {
			/* No extension? */
			JANUS_LOG(LOG_ERR, "No extension? Unsupported target file\n");
			cmdline_parser_free(&args_info);
			exit(1);
		}
		extension++;
		if(strcasecmp(extension, "opus") && strcasecmp(extension, "wav") &&
				strcasecmp(extension, "webm") && strcasecmp(extension, "mp4") &&
				strcasecmp(extension, "srt")) {
			/* Unsupported extension? */
			JANUS_LOG(LOG_ERR, "Unsupported extension '%s'\n", extension);
			cmdline_parser_free(&args_info);
			exit(1);
		}
	}

	if (janus_faststart && strcasecmp(extension, "mp4")) {
		JANUS_LOG(LOG_ERR, "Faststart only supported for MP4");
		cmdline_parser_free(&args_info);
		exit(1);
	}

	FILE *file = fopen(source, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s\n", source);
		cmdline_parser_free(&args_info);
		exit(1);
	}
	fseek(file, 0L, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);
	if(!jsonheader_only)
		JANUS_LOG(LOG_INFO, "File is %zu bytes\n", fsize);

	/* Handle SIGINT */
	working = 1;
	signal(SIGINT, janus_pp_handle_signal);

	/* Pre-parse */
	if(!jsonheader_only)
		JANUS_LOG(LOG_INFO, "Pre-parsing file to generate ordered index...\n");
	gboolean has_timestamps = FALSE;
	gboolean parsed_header = FALSE;
	gboolean video = FALSE, data = FALSE;
	gboolean opus = FALSE, g711 = FALSE, g722 = FALSE,
		vp8 = FALSE, vp9 = FALSE, h264 = FALSE, av1 = FALSE, h265 = FALSE;
	gboolean e2ee = FALSE;
	gint64 c_time = 0, w_time = 0;
	int bytes = 0, skip = 0;
	long offset = 0;
	uint16_t len = 0;
	uint32_t count = 0;
	uint32_t ssrc = 0;
	char prebuffer[1500];
	memset(prebuffer, 0, 1500);
	char prebuffer2[1500];
	memset(prebuffer2, 0, 1500);
	/* Let's look for timestamp resets first */
	while(working && offset < fsize) {
		if(header_only && parsed_header) {
			/* We only needed to parse the header */
			cmdline_parser_free(&args_info);
			exit(0);
		}
		/* Read frame header */
		skip = 0;
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
				/* This is the main header */
				parsed_header = TRUE;
				JANUS_LOG(LOG_WARN, "Old .mjr header format\n");
				if(jsonheader_only) {	/* No JSON header to print */
					cmdline_parser_free(&args_info);
					exit(1);
				}
				bytes = fread(prebuffer, sizeof(char), 5, file);
				if(prebuffer[0] == 'v') {
					JANUS_LOG(LOG_INFO, "This is a video recording, assuming VP8\n");
					video = TRUE;
					data = FALSE;
					vp8 = TRUE;
					if(extension && strcasecmp(extension, "webm")) {
						JANUS_LOG(LOG_ERR, "VP8 RTP packets can only be converted to a .webm file\n");
						cmdline_parser_free(&args_info);
						exit(1);
					}
				} else if(prebuffer[0] == 'a') {
					JANUS_LOG(LOG_INFO, "This is an audio recording, assuming Opus\n");
					video = FALSE;
					data = FALSE;
					opus = TRUE;
					if(extension && strcasecmp(extension, "opus")) {
						JANUS_LOG(LOG_ERR, "Opus RTP packets can only be converted to an .opus file\n");
						cmdline_parser_free(&args_info);
						exit(1);
					}
				} else if(prebuffer[0] == 'd') {
					JANUS_LOG(LOG_INFO, "This is a text data recording, assuming SRT\n");
					video = FALSE;
					data = TRUE;
					if(extension && strcasecmp(extension, "srt")) {
						JANUS_LOG(LOG_ERR, "Data channel packets can only be converted to a .srt file\n");
						cmdline_parser_free(&args_info);
						exit(1);
					}
				} else {
					JANUS_LOG(LOG_WARN, "Unsupported recording media type...\n");
					cmdline_parser_free(&args_info);
					exit(1);
				}
				offset += len;
				continue;
			} else if(!data && len < 12) {
				/* Not RTP, skip */
				if(!jsonheader_only)
					JANUS_LOG(LOG_VERB, "Skipping packet (not RTP?)\n");
				offset += len;
				continue;
			}
		} else if(prebuffer[1] == 'J') {
			/* New .mjr format, the header may contain useful info */
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
				parsed_header = TRUE;
				prebuffer[len] = '\0';
				if(jsonheader_only) {
					/* Print the header as it is and exit */
					JANUS_PRINT("%s\n", prebuffer);
					cmdline_parser_free(&args_info);
					exit(0);
				}
				json_error_t error;
				json_t *info = json_loads(prebuffer, 0, &error);
				if(!info) {
					JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
					JANUS_LOG(LOG_WARN, "Error parsing info header...\n");
					cmdline_parser_free(&args_info);
					exit(1);
				}
				/* First of all let's check if this is an end-to-end encrypted recording */
				json_t *e = json_object_get(info, "e");
				if(e && json_is_true(e))
					e2ee = TRUE;
				/* Is it audio or video? */
				json_t *type = json_object_get(info, "t");
				if(!type || !json_is_string(type)) {
					JANUS_LOG(LOG_WARN, "Missing/invalid recording type in info header...\n");
					cmdline_parser_free(&args_info);
					exit(1);
				}
				const char *t = json_string_value(type);
				if(!strcasecmp(t, "v")) {
					video = TRUE;
					data = FALSE;
				} else if(!strcasecmp(t, "a")) {
					video = FALSE;
					data = FALSE;
				} else if(!strcasecmp(t, "d")) {
					video = FALSE;
					data = TRUE;
				} else {
					JANUS_LOG(LOG_WARN, "Unsupported recording type '%s' in info header...\n", t);
					cmdline_parser_free(&args_info);
					exit(1);
				}
				/* What codec was used? */
				json_t *codec = json_object_get(info, "c");
				if(!codec || !json_is_string(codec)) {
					JANUS_LOG(LOG_WARN, "Missing recording codec in info header...\n");
					cmdline_parser_free(&args_info);
					exit(1);
				}
				const char *c = json_string_value(codec);
				if(video) {
					if(!strcasecmp(c, "vp8")) {
						vp8 = TRUE;
						if(extension && strcasecmp(extension, "webm")) {
							JANUS_LOG(LOG_ERR, "VP8 RTP packets can only be converted to a .webm file\n");
							cmdline_parser_free(&args_info);
							exit(1);
						}
					} else if(!strcasecmp(c, "vp9")) {
						vp9 = TRUE;
						if(extension && strcasecmp(extension, "webm")) {
							JANUS_LOG(LOG_ERR, "VP9 RTP packets can only be converted to a .webm file\n");
							cmdline_parser_free(&args_info);
							exit(1);
						}
					} else if(!strcasecmp(c, "h264")) {
						h264 = TRUE;
						if(extension && strcasecmp(extension, "mp4")) {
							JANUS_LOG(LOG_ERR, "H.264 RTP packets can only be converted to a .mp4 file\n");
							cmdline_parser_free(&args_info);
							exit(1);
						}
					} else if(!strcasecmp(c, "av1")) {
						av1 = TRUE;
						if(extension && strcasecmp(extension, "mp4")) {
							JANUS_LOG(LOG_ERR, "AV1 RTP packets can only be converted to a .mp4 file\n");
							cmdline_parser_free(&args_info);
							exit(1);
						}
					} else if(!strcasecmp(c, "h265")) {
						h265 = TRUE;
						if(extension && strcasecmp(extension, "mp4")) {
							JANUS_LOG(LOG_ERR, "H.265 RTP packets can only be converted to a .mp4 file\n");
							cmdline_parser_free(&args_info);
							exit(1);
						}
					} else {
						JANUS_LOG(LOG_WARN, "The post-processor only supports VP8, VP9 and H.264 video for now (was '%s')...\n", c);
						cmdline_parser_free(&args_info);
						exit(1);
					}
				} else if(!video && !data) {
					if(!strcasecmp(c, "opus")) {
						opus = TRUE;
						if(extension && strcasecmp(extension, "opus")) {
							JANUS_LOG(LOG_ERR, "Opus RTP packets can only be converted to an .opus file\n");
							cmdline_parser_free(&args_info);
							exit(1);
						}
					} else if(!strcasecmp(c, "multiopus")) {
						JANUS_LOG(LOG_ERR, "Surround Opus RTP packets are not supported, at the moment\n");
						cmdline_parser_free(&args_info);
						exit(1);
					} else if(!strcasecmp(c, "g711") || !strcasecmp(c, "pcmu") || !strcasecmp(c, "pcma")) {
						g711 = TRUE;
						if(extension && strcasecmp(extension, "wav")) {
							JANUS_LOG(LOG_ERR, "G.711 RTP packets can only be converted to a .wav file\n");
							cmdline_parser_free(&args_info);
							exit(1);
						}
					} else if(!strcasecmp(c, "g722")) {
						g722 = TRUE;
						if(extension && strcasecmp(extension, "wav")) {
							JANUS_LOG(LOG_ERR, "G.722 RTP packets can only be converted to a .wav file\n");
							cmdline_parser_free(&args_info);
							exit(1);
						}
					} else {
						JANUS_LOG(LOG_WARN, "The post-processor only supports Opus, G.711 and G.722 audio for now (was '%s')...\n", c);
						cmdline_parser_free(&args_info);
						exit(1);
					}
				} else if(data) {
					if(strcasecmp(c, "text")) {
						JANUS_LOG(LOG_WARN, "The post-processor only supports text data for now (was '%s')...\n", c);
						cmdline_parser_free(&args_info);
						exit(1);
					}
					if(extension && strcasecmp(extension, "srt")) {
						JANUS_LOG(LOG_ERR, "Data channel packets can only be converted to a .srt file\n");
						cmdline_parser_free(&args_info);
						exit(1);
					}
				}
				/* Any codec-specific info? (just informational) */
				const char *f = json_string_value(json_object_get(info, "f"));
				/* When was the file created? */
				json_t *created = json_object_get(info, "s");
				if(!created || !json_is_integer(created)) {
					JANUS_LOG(LOG_WARN, "Missing recording created time in info header...\n");
					cmdline_parser_free(&args_info);
					exit(1);
				}
				c_time = json_integer_value(created);
				/* When was the first frame written? */
				json_t *written = json_object_get(info, "u");
				if(!written || !json_is_integer(written)) {
					JANUS_LOG(LOG_WARN, "Missing recording written time in info header...\n");
					cmdline_parser_free(&args_info);
					exit(1);
				}
				w_time = json_integer_value(written);
				/* Summary */
				JANUS_LOG(LOG_INFO, "This is %s recording:\n", video ? "a video" : (data ? "a text data" : "an audio"));
				JANUS_LOG(LOG_INFO, "  -- Codec:   %s\n", c);
				if(f != NULL)
					JANUS_LOG(LOG_INFO, "  -- -- fmtp: %s\n", f);
				JANUS_LOG(LOG_INFO, "  -- Created: %"SCNi64"\n", c_time);
				JANUS_LOG(LOG_INFO, "  -- Written: %"SCNi64"\n", w_time);
				if(e2ee)
					JANUS_LOG(LOG_INFO, "  -- Recording is end-to-end encrypted\n");
				/* Save the original string as a metadata to save in the media container, if possible */
				if(metadata == NULL)
					metadata = g_strdup(prebuffer);
				json_decref(info);
			}
		} else {
			JANUS_LOG(LOG_ERR, "Invalid header...\n");
			cmdline_parser_free(&args_info);
			exit(1);
		}
		/* Skip data for now */
		offset += len;
	}
	if(!working || jsonheader_only) {
		cmdline_parser_free(&args_info);
		exit(0);
	}
	/* Now let's parse the frames and order them */
	uint32_t pkt_ts = 0, last_ts = 0, reset = 0;
	int times_resetted = 0;
	int post_reset_pkts = 0;
	int ignored = 0;
	offset = 0;
	/* Extensions, if any */
	int audiolevel = 0, rotation = 0, last_rotation = -1, rotated = -1;
	/* Timestamp reset related stuff */
	last_ts = 0;
	reset = 0;
	times_resetted = 0;
	post_reset_pkts = 0;
	uint64_t max32 = UINT32_MAX;
	/* Start loop */
	while(working && offset < fsize) {
		/* Read frame header */
		skip = 0;
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
		prebuffer[(has_timestamps && prebuffer[1] != 'J') ? 4 : 8] = '\0';
		JANUS_LOG(LOG_VERB, "Header: %s\n", prebuffer);
		offset += 8;
		bytes = fread(&len, sizeof(uint16_t), 1, file);
		len = ntohs(len);
		JANUS_LOG(LOG_VERB, "  -- Length: %"SCNu16"\n", len);
		offset += 2;
		if(prebuffer[1] == 'J' || (!data && len < 12)) {
			/* Not RTP, skip */
			JANUS_LOG(LOG_VERB, "  -- Not RTP, skipping\n");
			offset += len;
			continue;
		}
		if(has_timestamps) {
			JANUS_LOG(LOG_VERB, "  -- Time: %"SCNu32"ms\n", pkt_ts);
		}
		if(!data && len > 1500) {
			/* Way too large, very likely not RTP, skip */
			JANUS_LOG(LOG_VERB, "  -- Too large packet (%d bytes), skipping\n", len);
			offset += len;
			continue;
		}
		if(ignore_first_packets && ignored < ignore_first_packets) {
			/* We've been told to ignore the first X packets */
			ignored++;
			offset += len;
			continue;
		}
		if(data) {
			/* Things are simpler for data, no reordering is needed: start by the data time */
			gint64 when = 0;
			bytes = fread(&when, sizeof(gint64), 1, file);
			when = ntohll(when);
			offset += sizeof(gint64);
			len -= sizeof(gint64);
			/* Generate frame packet and insert in the ordered list */
			janus_pp_frame_packet *p = g_malloc(sizeof(janus_pp_frame_packet));
			p->version = has_timestamps ? 2 : 1;
			p->p_ts = pkt_ts;
			p->seq = 0;
			/* We "abuse" the timestamp field for the timing info */
			p->ts = when-c_time;
			p->len = len;
			p->pt = 0;
			p->drop = 0;
			p->offset = offset;
			p->skip = 0;
			p->audiolevel = -1;
			p->rotation = -1;
			p->next = NULL;
			p->prev = NULL;
			if(list == NULL) {
				list = p;
			} else {
				last->next = p;
			}
			last = p;
			/* Done */
			offset += len;
			continue;
		}
		/* Only read RTP header */
		bytes = fread(prebuffer, sizeof(char), len > 24 ? 24: len, file);
		janus_pp_rtp_header *rtp = (janus_pp_rtp_header *)prebuffer;
		JANUS_LOG(LOG_VERB, "  -- RTP packet (ssrc=%"SCNu32", pt=%"SCNu16", ext=%"SCNu16", seq=%"SCNu16", ts=%"SCNu32")\n",
				ntohl(rtp->ssrc), rtp->type, rtp->extension, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
		if(rtp->csrccount) {
			JANUS_LOG(LOG_VERB, "  -- -- Skipping CSRC list\n");
			skip += rtp->csrccount*4;
		}
		audiolevel = -1;
		rotation = -1;
		if(rtp->extension) {
			janus_pp_rtp_header_extension *ext = (janus_pp_rtp_header_extension *)(prebuffer+12+skip);
			JANUS_LOG(LOG_VERB, "  -- -- RTP extension (type=0x%"PRIX16", length=%"SCNu16")\n",
				ntohs(ext->type), ntohs(ext->length));
			skip += 4 + ntohs(ext->length)*4;
			if(audio_level_extmap_id > 0)
				janus_pp_rtp_header_extension_parse_audio_level(prebuffer, len, audio_level_extmap_id, &audiolevel);
			if(video_orient_extmap_id > 0) {
				janus_pp_rtp_header_extension_parse_video_orientation(prebuffer, len, video_orient_extmap_id, &rotation);
				if(rotation != -1 && rotation != last_rotation) {
					last_rotation = rotation;
					rotated++;
				}
			}
		}
		if(ssrc == 0) {
			ssrc = ntohl(rtp->ssrc);
			JANUS_LOG(LOG_INFO, "SSRC detected: %"SCNu32"\n", ssrc);
		}
		if(ssrc != ntohl(rtp->ssrc)) {
			JANUS_LOG(LOG_WARN, "Dropping packet with unexpected SSRC: %"SCNu32" != %"SCNu32"\n",
				ntohl(rtp->ssrc), ssrc);
			/* Skip data */
			offset += len;
			count++;
			continue;
		}
		/* Generate frame packet and insert in the ordered list */
		janus_pp_frame_packet *p = g_malloc0(sizeof(janus_pp_frame_packet));
		p->header = rtp;
		p->version = has_timestamps ? 2 : 1;
		p->p_ts = pkt_ts;
		p->seq = ntohs(rtp->seq_number);
		p->pt = rtp->type;
		/* Due to resets, we need to mess a bit with the original timestamps */
		if(last_ts == 0) {
			/* Simple enough... */
			p->ts = ntohl(rtp->timestamp);
		} else {
			/* Is the new timestamp smaller than the next one, and if so, is it a timestamp reset or simply out of order? */
			gboolean late_pkt = FALSE;
			if(ntohl(rtp->timestamp) < last_ts && (last_ts-ntohl(rtp->timestamp) > 2*1000*1000*1000)) {
				if(post_reset_pkts > post_reset_trigger) {
					reset = ntohl(rtp->timestamp);
					JANUS_LOG(LOG_WARN, "Timestamp reset: %"SCNu32"\n", reset);
					times_resetted++;
					post_reset_pkts = 0;
				}
			} else if(ntohl(rtp->timestamp) > reset && ntohl(rtp->timestamp) > last_ts &&
					(ntohl(rtp->timestamp)-last_ts > 2*1000*1000*1000)) {
				if(post_reset_pkts < post_reset_trigger) {
					JANUS_LOG(LOG_WARN, "Late pre-reset packet after a timestamp reset: %"SCNu32"\n", ntohl(rtp->timestamp));
					late_pkt = TRUE;
					times_resetted--;
				}
			} else if(ntohl(rtp->timestamp) < reset) {
				if(post_reset_pkts < post_reset_trigger) {
					JANUS_LOG(LOG_WARN, "Updating latest timestamp reset: %"SCNu32" (was %"SCNu32")\n", ntohl(rtp->timestamp), reset);
					reset = ntohl(rtp->timestamp);
				} else {
					reset = ntohl(rtp->timestamp);
					JANUS_LOG(LOG_WARN, "Timestamp reset: %"SCNu32"\n", reset);
					times_resetted++;
					post_reset_pkts = 0;
				}
			}
			/* Take into account the number of resets when setting the internal, 64-bit, timestamp */
			p->ts = (times_resetted*max32)+ntohl(rtp->timestamp);
			if(late_pkt)
				times_resetted++;
		}
		p->len = len;
		p->drop = 0;
		if(rtp->padding) {
			/* There's padding data, let's check the last byte to see how much data we should skip */
			fseek(file, offset + len - 1, SEEK_SET);
			bytes = fread(prebuffer2, sizeof(char), 1, file);
			uint8_t padlen = (uint8_t)prebuffer2[0];
			JANUS_LOG(LOG_VERB, "Padding at sequence number %hu: %d/%d\n",
				ntohs(rtp->seq_number), padlen, p->len);
			p->len -= padlen;
			if((p->len - skip - 12) <= 0) {
				/* Only padding, take note that we should drop the packet later */
				p->drop = 1;
				JANUS_LOG(LOG_VERB, "  -- All padding, marking packet as dropped\n");
			}
		}
		if(p->len <= 12) {
			/* Only header? take note that we should drop the packet later */
			p->drop = 1;
			JANUS_LOG(LOG_VERB, "  -- Only RTP header, marking packet as dropped\n");
		}
		last_ts = ntohl(rtp->timestamp);
		post_reset_pkts++;
		/* Fill in the rest of the details */
		p->offset = offset;
		p->skip = skip;
		p->audiolevel = audiolevel;
		p->rotation = rotation;
		p->next = NULL;
		p->prev = NULL;
		if(list == NULL) {
			/* First element becomes the list itself (and the last item), at least for now */
			list = p;
			last = p;
		} else if(!p->drop) {
			/* Check where we should insert this, starting from the end */
			int added = 0;
			janus_pp_frame_packet *tmp = last;
			while(tmp) {
				if(tmp->ts < p->ts) {
					/* The new timestamp is greater than the last one we have, append */
					added = 1;
					if(tmp->next != NULL) {
						/* We're inserting */
						tmp->next->prev = p;
						p->next = tmp->next;
					} else {
						/* Update the last packet */
						last = p;
					}
					tmp->next = p;
					p->prev = tmp;
					break;
				} else if(tmp->ts == p->ts) {
					/* Same timestamp, check the sequence number */
					if(tmp->seq < p->seq && (abs(tmp->seq - p->seq) < 10000)) {
						/* The new sequence number is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					} else if(tmp->seq > p->seq && (abs(tmp->seq - p->seq) > 10000)) {
						/* The new sequence number (resetted) is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					} else if(tmp->seq == p->seq) {
						/* Maybe a retransmission? Skip */
						JANUS_LOG(LOG_WARN, "Skipping duplicate packet (seq=%"SCNu16")\n", p->seq);
						p->drop = 1;
						break;
					}
				}
				/* If either the timestamp ot the sequence number we just got is smaller, keep going back */
				tmp = tmp->prev;
			}
			if(p->drop) {
				/* We don't need this */
				g_free(p);
			} else if(!added) {
				/* We reached the start */
				p->next = list;
				list->prev = p;
				list = p;
			}
		}
		/* Skip data for now */
		offset += len;
		count++;
	}
	if(!working) {
		cmdline_parser_free(&args_info);
		exit(0);
	}

	JANUS_LOG(LOG_INFO, "Counted %"SCNu32" RTP packets\n", count);
	janus_pp_frame_packet *tmp = list;
	count = 0;
	int rate = video ? 90000 : 48000;
	if(g711 || g722)
		rate = 8000;
	while(tmp) {
		count++;
		if(!data)
			JANUS_LOG(LOG_VERB, "[%10lu][%4d] seq=%"SCNu16", ts=%"SCNu64", time=%.2fs pts=%.2fs\n", tmp->offset, tmp->len, tmp->seq, tmp->ts, (double)(tmp->ts-list->ts)/(double)rate, (double)tmp->p_ts/1000);
		else
			JANUS_LOG(LOG_VERB, "[%10lu][%4d] time=%"SCNu64"s\n", tmp->offset, tmp->len, tmp->ts);
		tmp = tmp->next;
	}
	JANUS_LOG(LOG_INFO, "Counted %"SCNu32" frame packets\n", count);
	if(rotated != -1) {
		if(rotated == 0 && last_rotation != 0) {
			JANUS_LOG(LOG_INFO, "The video is rotated\n");
		} else if(rotated > 0) {
			JANUS_LOG(LOG_INFO, "The video changed orientation %d times\n", rotated);
		}
	}

	if(video) {
		/* Look for maximum width and height, if possible, and for the average framerate */
		if(vp8 || vp9) {
			if(janus_pp_webm_preprocess(file, list, vp8) < 0) {
				JANUS_LOG(LOG_ERR, "Error pre-processing %s RTP frames...\n", vp8 ? "VP8" : "VP9");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		} else if(h264) {
			if(janus_pp_h264_preprocess(file, list) < 0) {
				JANUS_LOG(LOG_ERR, "Error pre-processing H.264 RTP frames...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		} else if(av1) {
			if(janus_pp_av1_preprocess(file, list) < 0) {
				JANUS_LOG(LOG_ERR, "Error pre-processing AV1 RTP frames...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		} else if(h265) {
			if(janus_pp_h265_preprocess(file, list) < 0) {
				JANUS_LOG(LOG_ERR, "Error pre-processing H.265 RTP frames...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		}
	}

	if(parse_only) {
		/* We only needed to parse and re-order the packets, we're done here */
		JANUS_LOG(LOG_INFO, "Parsing and reordering completed, bye!\n");
		cmdline_parser_free(&args_info);
		exit(0);
	}

	/* Now we have to start working: stop here if it's an end-to-end encrypted
	 * recording, though, as the processed file would NOT be playable... In
	 * the future we may want to provide ways for users to pass custom decrypt
	 * functions to the processor (e.g., for users with legitimate access to
	 * the key to decrypt the content), but at the moment we just drop it */
	if(e2ee) {
		JANUS_LOG(LOG_ERR, "End-to-end encrypted media recording, can't process...\n");
		cmdline_parser_free(&args_info);
		exit(1);
	}

	if(!video && !data && audioskew_th > 0) {
		tmp = list;
		janus_pp_rtp_skew_context context = {};
		context.ssrc = ssrc;
		context.rate = rate;
		context.reference_time = tmp->p_ts;
		context.start_time = tmp->p_ts;
		context.start_ts = tmp->ts;
		janus_pp_frame_packet *to_drop;
		while(tmp) {
			int ret = janus_pp_skew_compensate_audio(tmp, &context);
			if(ret < 0) {
				JANUS_LOG(LOG_WARN, "audio skew SSRC=%"SCNu32" dropping %d packets, source clock is too fast\n", ssrc, -ret);
				to_drop = tmp;
				/* Actually returns -1, so drop just one pkt */
				if (tmp->prev != NULL)
					tmp->prev->next = tmp->next;
				if (tmp->next != NULL)
					tmp->next->prev = tmp->prev;
				g_free(to_drop);
			} else if(ret > 0) {
				JANUS_LOG(LOG_WARN, "audio skew SSRC=%"SCNu32" jumping %d RTP sequence numbers, source clock is too slow\n", ssrc, ret);
			}
			tmp = tmp->next;
		}
	}

	if(!video && !data) {
		if(opus) {
			if(janus_pp_opus_create(destination, metadata) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .opus file...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		} else if(g711) {
			if(janus_pp_g711_create(destination, metadata) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .wav file...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		} else if(g722) {
			if(janus_pp_g722_create(destination, metadata) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .wav file...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		}
	} else if(data) {
		if(janus_pp_srt_create(destination, metadata) < 0) {
			JANUS_LOG(LOG_ERR, "Error creating .srt file...\n");
			cmdline_parser_free(&args_info);
			exit(1);
		}
	} else {
		if(vp8 || vp9) {
			if(janus_pp_webm_create(destination, metadata, vp8) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .webm file...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		} else if(h264) {
			if(janus_pp_h264_create(destination, metadata, janus_faststart) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .mp4 file...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		} else if(av1) {
			if(janus_pp_av1_create(destination, metadata, janus_faststart) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .mp4 file...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		} else if(h265) {
			if(janus_pp_h265_create(destination, metadata, janus_faststart) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .mp4 file...\n");
				cmdline_parser_free(&args_info);
				exit(1);
			}
		}
	}

	/* Loop */
	if(!video && !data) {
		if(opus) {
			if(janus_pp_opus_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing Opus RTP frames...\n");
			}
		} else if(g711) {
			if(janus_pp_g711_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing G.711 RTP frames...\n");
			}
		} else if(g722) {
			if(janus_pp_g722_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing G.722 RTP frames...\n");
			}
		}
	} else if(data) {
		if(janus_pp_srt_process(file, list, &working) < 0) {
			JANUS_LOG(LOG_ERR, "Error processing text data frames...\n");
		}
	} else {
		if(vp8 || vp9) {
			if(janus_pp_webm_process(file, list, vp8, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing %s RTP frames...\n", vp8 ? "VP8" : "VP9");
			}
		} else if(h264) {
			if(janus_pp_h264_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing H.264 RTP frames...\n");
			}
		} else if(av1) {
			if(janus_pp_av1_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing AV1 RTP frames...\n");
			}
		} else if(h265) {
			if(janus_pp_h265_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing H.265 RTP frames...\n");
			}
		}
	}

	/* Clean up */
	if(video) {
		if(vp8 || vp9) {
			janus_pp_webm_close();
		} else if(h264) {
			janus_pp_h264_close();
		} else if(av1) {
			janus_pp_av1_close();
		} else if(h265) {
			janus_pp_h265_close();
		}
	} else if(data) {
		janus_pp_srt_close();
	} else {
		if(opus) {
			janus_pp_opus_close();
		} else if(g711) {
			janus_pp_g711_close();
		} else if(g722) {
			janus_pp_g722_close();
		}
	}
	fclose(file);

	file = fopen(destination, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_INFO, "No destination file %s??\n", destination);
	} else {
		fseek(file, 0L, SEEK_END);
		fsize = ftell(file);
		fseek(file, 0L, SEEK_SET);
		JANUS_LOG(LOG_INFO, "%s is %zu bytes\n", destination, fsize);
		fclose(file);
	}
	janus_pp_frame_packet *temp = list, *next = NULL;
	while(temp) {
		next = temp->next;
		g_free(temp);
		temp = next;
	}

	cmdline_parser_free(&args_info);

	JANUS_LOG(LOG_INFO, "Bye!\n");
	return 0;
}

/* Static helper to quickly find the extension data */
static int janus_pp_rtp_header_extension_find(char *buf, int len, int id,
		uint8_t *byte, uint32_t *word, char **ref) {
	if(!buf || len < 12)
		return -1;
	janus_pp_rtp_header *rtp = (janus_pp_rtp_header *)buf;
	int hlen = 12;
	if(rtp->csrccount)	/* Skip CSRC if needed */
		hlen += rtp->csrccount*4;
	if(rtp->extension) {
		janus_pp_rtp_header_extension *ext = (janus_pp_rtp_header_extension *)(buf+hlen);
		int extlen = ntohs(ext->length)*4;
		hlen += 4;
		if(len > (hlen + extlen)) {
			/* 1-Byte extension */
			if(ntohs(ext->type) == 0xBEDE) {
				const uint8_t padding = 0x00, reserved = 0xF;
				uint8_t extid = 0, idlen;
				int i = 0;
				while(i < extlen) {
					extid = buf[hlen+i] >> 4;
					if(extid == reserved) {
						break;
					} else if(extid == padding) {
						i++;
						continue;
					}
					idlen = (buf[hlen+i] & 0xF)+1;
					if(extid == id) {
						/* Found! */
						if(byte)
							*byte = buf[hlen+i+1];
						if(word)
							*word = ntohl(*(uint32_t *)(buf+hlen+i));
						if(ref)
							*ref = &buf[hlen+i];
						return 0;
					}
					i += 1 + idlen;
				}
			}
			hlen += extlen;
		}
	}
	return -1;
}

static int janus_pp_rtp_header_extension_parse_audio_level(char *buf, int len, int id, int *level) {
	uint8_t byte = 0;
	if(janus_pp_rtp_header_extension_find(buf, len, id, &byte, NULL, NULL) < 0)
		return -1;
	/* a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level */
	int value = byte & 0x7F;
	if(level)
		*level = value;
	return 0;
}

static int janus_pp_rtp_header_extension_parse_video_orientation(char *buf, int len, int id, int *rotation) {
	uint8_t byte = 0;
	if(janus_pp_rtp_header_extension_find(buf, len, id, &byte, NULL, NULL) < 0)
		return -1;
	/* a=extmap:4 urn:3gpp:video-orientation */
	gboolean r1bit = (byte & 0x02) >> 1;
	gboolean r0bit = byte & 0x01;
	if(rotation) {
		if(!r0bit && !r1bit)
			*rotation = 0;
		else if(r0bit && !r1bit)
			*rotation = 90;
		else if(!r0bit && r1bit)
			*rotation = 180;
		else if(r0bit && r1bit)
			*rotation = 270;
	}
	return 0;
}

static gint janus_pp_skew_compensate_audio(janus_pp_frame_packet *pkt, janus_pp_rtp_skew_context *context) {
	/* N 	: a N sequence number jump has been performed on the packet */
	/* 0  	: no skew compensation needs to be done */
	/* -N  	: a N packets drop must be performed by the caller */
	gint exit_status = 0;

	context->prev_seq = context->last_seq;
	context->last_seq = pkt->seq;
	context->prev_ts = context->last_ts;
	context->last_ts = pkt->ts;

	guint32 pts = pkt->p_ts;
	guint32 akhz = context->rate / 1000;

	/* Do not execute skew analysis in the first seconds */
	if (pts - context->reference_time < SKEW_DETECTION_WAIT_TIME_SECS / 2 * 1000) {
		return 0;
	} else if (!context->start_time) {
		context->start_time = pts;
		if (!context->start_time)
			context->start_time = 1;
		context->evaluating_start_time = context->start_time;
		context->start_ts = context->last_ts;
		JANUS_LOG(LOG_INFO, "audio skew SSRC=%"SCNu32" evaluation phase start, start_time=%"SCNu32" start_ts=%"SCNu32"\n", context->ssrc, context->start_time, context->start_ts);
	}

	/* Skew analysis */
	/* Are we waiting for a target timestamp? (a negative skew has been evaluated in a previous iteration) */
	if (context->target_ts > 0 && (gint32)(context->target_ts - context->last_ts) > 0) {
		context->seq_offset--;
		exit_status = -1;
	} else {
		context->target_ts = 0;
		/* Do not execute analysis for out of order packets or multi-packets frame */
		if (context->last_seq == context->prev_seq + 1 && context->last_ts != context->prev_ts) {
			/* Evaluate the local RTP timestamp according to the local clock */
			guint32 expected_ts = ((pts - context->start_time) * akhz) + context->start_ts;
			/* Evaluate current delay */
			gint32 delay_now = context->last_ts - expected_ts;
			/* Exponentially weighted moving average estimation */
			gint32 delay_estimate = (63 * context->prev_delay + delay_now) / 64;
			/* Save previous delay for the next iteration*/
			context->prev_delay = delay_estimate;
			/* Evaluate the distance between active delay and current delay estimate */
			gint32 offset = context->active_delay - delay_estimate;
			JANUS_LOG(LOG_HUGE, "audio skew SSRC=%"SCNu32" status RECVD_TS=%"SCNu32" EXPTD_TS=%"SCNu32" AVG_OFFSET=%"SCNi32" TS_OFFSET=%"SCNi32" SEQ_OFFSET=%"SCNi16"\n", context->ssrc, context->last_ts, expected_ts, offset, context->ts_offset, context->seq_offset);
			gint32 skew_th = audioskew_th * akhz;

			/* Evaluation phase */
			if (context->evaluating_start_time) {
				/* Check if the offset has surpassed half the threshold during the evaluating phase */
				if (pts - context->evaluating_start_time <= SKEW_DETECTION_WAIT_TIME_SECS / 2 * 1000) {
					if (abs(offset) <= skew_th/2) {
						JANUS_LOG(LOG_HUGE, "audio skew SSRC=%"SCNu32" evaluation phase continue\n", context->ssrc);
					} else {
						JANUS_LOG(LOG_VERB, "audio skew SSRC=%"SCNu32" evaluation phase reset\n", context->ssrc);
						context->start_time = pts;
						if (!context->start_time)
							context->start_time = 1;
						context->evaluating_start_time = context->start_time;
						context->start_ts = context->last_ts;
					}
				} else {
					JANUS_LOG(LOG_INFO, "audio skew SSRC=%"SCNu32" evaluation phase stop, start_time=%"SCNu32" start_ts=%"SCNu32"\n", context->ssrc, context->start_time, context->start_ts);
					context->evaluating_start_time = 0;
				}
				return 0;
			}

			/* Check if the offset has surpassed the threshold */
			if (offset >= skew_th) {
				/* The source is slowing down */
				/* Update active delay */
				context->active_delay = delay_estimate;
				/* Adjust ts offset */
				context->ts_offset += skew_th;
				/* Calculate last ts increase */
				guint32 ts_incr = context->last_ts - context->prev_ts;
				/* Evaluate sequence number jump */
				guint16 jump = (skew_th + ts_incr - 1) / ts_incr;
				/* Adjust seq num offset */
				context->seq_offset += jump;
				exit_status = jump;
			} else if (offset <= -skew_th) {
				/* The source is speeding up*/
				/* Update active delay */
				context->active_delay = delay_estimate;
				/* Adjust ts offset */
				context->ts_offset -= skew_th;
				/* Set target ts */
				context->target_ts = context->last_ts + skew_th;
				if (context->target_ts == 0)
					context->target_ts = 1;
				/* Adjust seq num offset */
				context->seq_offset--;
				exit_status = -1;
			}
		}
	}

	/* Skew compensation */
	/* Fix header timestamp considering the active offset */
	guint32 fixed_rtp_ts = context->last_ts + context->ts_offset;
	pkt->ts = fixed_rtp_ts;
	pkt->header->timestamp = htonl(fixed_rtp_ts);
	/* Fix header sequence number considering the total offset */
	guint16 fixed_rtp_seq = context->last_seq + context->seq_offset;
	pkt->seq = fixed_rtp_seq;
	pkt->header->seq_number = htons(fixed_rtp_seq);

	return exit_status;
}
