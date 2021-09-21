#include <glib.h>
#include "rtp.h"
#include "mutex.h"

/* This is a helper object that is used to pass publisher related data to the methods of the vp8_remb_simulcast implementation */
typedef struct janus_vp8_remb_publisher {
	/* Unique ID of the publisher (when using strings) */
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
	/* The last received remb value */
	guint32 last_bitrate;
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
