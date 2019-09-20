/*! \file   janus_lua_data.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Lua data/session definition (headers)
 * \details  The Janus Lua plugin implements all the mandatory hooks to
 * allow the C code to interact with a custom Lua script, and viceversa.
 * That said, the janus_lua_extra.c code allows for custom hooks to be
 * added in C, to expose additional Lua functions and implement more
 * complex media management than the one provided by the stock plugin.
 * For this to work, though, the janus_lua_session object and its
 * indexing in the hashtable need to be defined externally, which is
 * what this file is for.
 *
 * Notice that all the management associated to sessions (creating or
 * destroying sessions, locking their global mutex, updating the
 * hashtable) is done in the core of the Lua plugin: here we only
 * define them, so that they can be accessed/used by the extra code too.
 *
 * \ingroup luapapi
 * \ref luapapi
 */

#ifndef JANUS_LUA_DATA_H
#define JANUS_LUA_DATA_H

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "plugin.h"

#include "debug.h"
#include "apierror.h"
#include "config.h"
#include "mutex.h"
#include "rtp.h"
#include "rtcp.h"
#include "sdp-utils.h"
#include "record.h"
#include "utils.h"

/* Core pointer and related flags */
extern volatile gint lua_initialized, lua_stopping;
extern janus_callbacks *janus_core;

/* Lua state: we define state and mutex as extern */
extern lua_State *lua_state;
extern janus_mutex lua_mutex;

/* Lua session: we keep only the barebone stuff here, the rest will be in the Lua script */
typedef struct janus_lua_session {
	janus_plugin_session *handle;		/* Pointer to the core-plugin session */
	uint32_t id;						/* Unique session ID (will be used to correlate with the Lua script) */
	/* The following are only needed for media manipulation, feedback and routing, and may not all be used */
	gboolean accept_audio;				/* Whether incoming audio can be accepted or must be dropped */
	gboolean accept_video;				/* Whether incoming video can be accepted or must be dropped */
	gboolean accept_data;				/* Whether incoming data can be accepted or must be dropped */
	gboolean send_audio;				/* Whether outgoing audio can be sent or must be dropped */
	gboolean send_video;				/* Whether outgoing video can be sent or must be dropped */
	gboolean send_data;					/* Whether outgoing data can be sent or must be dropped */
	janus_rtp_switching_context rtpctx;	/* Needed in case the source changes (e.g., stale operator/customer) */
	uint32_t bitrate;					/* Bitrate limit */
	uint16_t pli_freq;					/* Regular PLI frequency (0=disabled) */
	gint64 pli_latest;					/* Time of latest sent PLI (to avoid flooding) */
	GSList *recipients;					/* Sessions that should receive media from this session */
	struct janus_lua_session *sender;	/* Other session this session is receiving media from */
	janus_mutex recipients_mutex;		/* Mutex to lock the recipients list */
	janus_recorder *arc;				/* The Janus recorder instance for audio, if enabled */
	janus_recorder *vrc;				/* The Janus recorder instance for video, if enabled */
	janus_recorder *drc;				/* The Janus recorder instance for data, if enabled */
	janus_mutex rec_mutex;				/* Mutex to protect the recorders from race conditions */
	volatile gint started;				/* Whether this session's PeerConnection is ready or not */
	volatile gint hangingup;			/* Whether this session's PeerConnection is hanging up */
	volatile gint destroyed;			/* Whether this session's been marked as destroyed */
	/* If you need any additional property (e.g., for hooks you added in janus_lua_extra.c) add them below this line */

	/* Reference counter */
	janus_refcount ref;
} janus_lua_session;
extern GHashTable *lua_sessions, *lua_ids;
extern janus_mutex lua_sessions_mutex;
janus_lua_session *janus_lua_lookup_session(janus_plugin_session *handle);

#endif
