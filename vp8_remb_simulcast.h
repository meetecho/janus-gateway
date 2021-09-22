#include <glib.h>
#include "rtp.h"
#include "mutex.h"

/* This is a helper object that is used to pass publisher related data to the methods of the vp8_remb_simulcast implementation */
typedef struct janus_vp8_remb_publisher {
	/* Unique ID of the publisher */
	gchar *user_id_str;
	/* Display name (just for fun) */
	gchar *display;
 	/* Pointer to the original publisher object, to be handed over in the callback isMultiCasting */
	void *pOriginalPublisherObject;
 	/* Callback that is called inside a mutex context to verify if the publisher is simulcasting */
	gboolean (*isMultiCasting)(void *pOriginalPublisherObject);
	/* Callback to request a PLI / FIR on the subscribers peerConnection */
	void (*sendPLI)(void *pOriginalPublisherObject, const char *reason);

} janus_vp8_remb_publisher;

/* This is a helper object that is used to pass subscriber related data to the methods of the vp8_remb_simulcast implementation */
typedef struct janus_vp8_remb_subscriber {
	/*! Opaque pointer to the Janus core-level handle */
	void *gateway_handle;
	/* The last received remb value */
	guint32 last_bitrate;
	/* stores wether we have already received a valid bitrate from remb or not yet, the first valid remb value sets this to true even if the value then drops to 0 afterwards */
	gboolean last_bitrate_valid;
	/* Simulcasting context of the subscribers peer Connection */
	janus_rtp_simulcasting_context *pSimContext;
	/* Mutex one has to lock to safely access the publishers feed */
	janus_mutex* pFeedMutex;
	/* Pointer to the publisher of this subscription */
	janus_vp8_remb_publisher *pFeed;
} janus_vp8_remb_subscriber;

/* Entry point to allow remb based switching simulcast layers
   This method needs to be called when the remb value has been aquired from the rtcp data
*/
void janus_vp8_remb_simulcast_based_subscriber_simulcast_switching(janus_vp8_remb_subscriber *pSubscriber, uint32_t bitrate);
