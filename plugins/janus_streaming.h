#ifndef _JANUS_STREAMING_H
#define _JANUS_STREAMING_H

typedef struct janus_streaming_ardrone3_frame {
	uint8_t *data;
	gint length;
	uint64_t ts;
} janus_streaming_ardrone3_frame;

typedef struct janus_streaming_ardrone3_source {
	BD_MANAGER_t *deviceManager;
	GAsyncQueue *frames;
} janus_streaming_ardrone3_source;


#endif