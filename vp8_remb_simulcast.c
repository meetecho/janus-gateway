/* New methods for an REMB based simulcast layer switching on a subscriber peerConnection
 *
 * What janus currently sadly lacks in is tried to be covered with the logic in this file.
 * It's a first idea and definetly needs fine tuning and furhter improvements (more later)
 *
 * The idea:
 * On the publisher side the sending browser controls which simulcast layers it shall send based
 * on the available bitrate it sees using transport-cc.
 * Transport-cc is pretty complex but Philip Hancke came up with janus is missing some header to support REMB.
 * (If you are not familiar with either transport-cc or REMB. Both try to gather the available bitrate on a PeerConnection.
 * Transport-cc is would be done on the sender side (for the subscriptions janus) where REMB is done on the client side (browser for the subscriptions)
 * REMB is slower than Transport-cc, currently lacks in probing (therefore just estimates based on the data currently beeing send) but its a starting point
 * (As it estimates, without probing, based on the data beeing send the value on REMB does not really see whats possible.
 * e.g. If you transport 150kBit and have no technical limit on the PC the REMB estimation goes up to ~280kBit.
 *
 * If we know the bandwidth we can try to map the available to the bitrates we need to the different simulcast layers
 * We currently do not map that to the real bitrates of the layers janus receives on the publisher PeerConnection.
 * We map it to what we told the browser to use for the different layers. In order to use this implementation you
 * need to let janus know what the browser will be configured for the different layers.
 * We do that with adding a json array with the bitrates [L,M,H] in either the configure or the join as publisher command
 *
 * We now build a ramp for going to higher or lower bitrates. We switch not only the substream but also the temporal layers as
 * we otherwise have blind areas where the REMB does not reach a value that allows us to switch to a higher layer.
 * The ramp consists of 6 positions:
 * Ramp positions:
 * Substream 0 (L) - Temporal 15fps -> 0
 * Substream 0 (L) - Temporal 30fps -> 1
 * Substream 1 (M) - Temporal 15fps -> 2
 * Substream 1 (M) - Temporal 30fps -> 3
 * Substream 2 (H) - Temporal 15fps -> 4
 * Substream 2 (H) - Temporal 30fps -> 5
 * These ramp position are associated with a certain bitrate we need to see to be able to switch to it.
 *
 * If the REMB value now goes above the required bitrate for the next layer or falls below the bitrate of the current layer
 * A helper variable is increased or decreased (this ensures that we do not switch instantly but if the new bitrate has settled.
 * If the variable falls to -20 we ramp down, if it goes to 20 we ramp up.
 *
 * The logic takes in charge what the client wanted to receive on a subscription
 * Thus we expose if we are in a limit situation through the eventing
 * The videoroom subscription events announce if we were forced to limit the substream or temporal layers where the client actually wanted to receive higher layers
 * (substream_remb_limited_to / temporal_remb_limited_to)
 *
 * The implementation has been test against the following browsers as subscribers:
 *
 * - Windows FireFox 92.0 - REMB ramp up takes pretty long if we start to send H 30fps in the beginning
 * - Windows Chrome Windows - No REMB ramp up when sending H 30fps - proper remb value right from the start
 * - Apple Safari 14.1.1 - No REMB ramp up when sending H 30fps - proper remb value right from the start
 * - IOS Safari (14.6) - No REMB ramp up when sending H 30fps - proper remb value right from the start
 *
 * Whats missing (and currently not target with the PR):
 * - Expose the currently seen REMB value in the general peerConnection statistics (just missing for completeness as other pc related values are exposed and helpful for external debugging)
 * - REMB probing on the subscription peerconnection (would speed up the REMB detection and would allow a switching without changing the temporal layers)
 * - transport-cc which would dramatically improve the probing (hard to implement especially in C, so nothing we target now)
 * - Gather the currently really used bitrates directly from the publishers peerconnection and not from the configure/join values
 * - Support for VP9 (the current approach only targets VP8)
 * - We currently start to send the layers as requested by the client
 *
 * - if i configure or start a subscription i want o be able to:
 * - - force a certain higher layer to start with (if i am using chromium based or safari, that works out of the box)
 * - - tell janus to achive that layer through remb ramping up
 * - - tell janus not to do it for this subscription (e.g. i have ones that must send a certain layer)
 */

#include "vp8_remb_simulcast.h"
#include "ice.h"

/* Enables console debugging */
#define REMB_CONSOLE_DEBUGGING 1
/* This is a correction factor we use to calculate the bitrate if we transport 15fps instead of 3) *
   The bitrates we handshake with the client are for 30fps, so we need to calculate the values for 15fps internally */
#define CORRECTION_FACTOR_15FPS 0.6
/* If we ramp up and need to ramp down within that period of time we call this ramp up failed */
#define TIME_RAMP_UP_FAILED 7
/* Defines how much we increase the bitrate for the failing layer per fail (10%) */
#define REQUIRED_BITRATE_INCREASE_PER_FAIL 0.1

/* Forward declarations */
uint32_t janus_vp8_remb_simulcast_get_client_requested_ramp_position(janus_rtp_simulcasting_context *pSim);
uint32_t janus_vp8_remb_simulcast_get_current_ramp_position(janus_rtp_simulcasting_context *pSim);
uint32_t janus_vp8_remb_simulcast_get_bitrate_for_ramp_position(janus_rtp_simulcasting_remb_context *pRembContext, uint32_t rampPos);
void janus_vp8_remb_simulcast_get_neighbour_ramp_positions(janus_rtp_simulcasting_context *pSim, uint32_t rampPos, uint32_t *pNextLower, uint32_t *pNextUpper);
double janus_vp8_remb_simulcast_calculate_bitrate_change(janus_vp8_remb_subscriber *pSubscriber, uint32_t remb);
void janus_vp8_remb_simulcast_update_last_bitrate_change(janus_rtp_simulcasting_remb_context *pRempContext, double change);
gboolean janus_vp8_remb_simulcast_set_flags_for_ramp_position(janus_rtp_simulcasting_remb_context *pRembContext, uint32_t position);
const char* janus_vp8_remb_simulcast_get_debug_substream_to_text(uint32_t substream);
const char* janus_vp8_remb_simulcast_get_debug_temporal_to_text(uint32_t temporal);
void janus_vp8_remb_simulcast_get_simulcast_requested_debug(char *szBuffer, gsize bufSize, janus_rtp_simulcasting_context *pSim);
void janus_vp8_remb_simulcast_get_simulcast_current_debug(char *szBuffer, gsize bufSize, janus_rtp_simulcasting_context *pSim);

/* This method implements the remb based subscriber simulcast switching as described above
 * @param pSubscriber - the subscriber object we are handling
 * @param bitrate - the received REMB bitrate value on the peerConnection
 */
void janus_vp8_remb_simulcast_based_subscriber_simulcast_switching(janus_vp8_remb_subscriber *pSubscriber, uint32_t bitrate) {
	/* start - Implementation for an REMB based simulcast layer switching on a subscriber peerConnection */
	janus_rtp_simulcasting_context *pSim = pSubscriber->pSimContext;
	janus_rtp_simulcasting_remb_context *pRembContext = &pSim->remb_context;

	/* Did the publisher announce layer bitrates via the api? */
	if(bitrate && pRembContext->publisher_simulcast_layer_count && pSim->substream != -1) {
		/*! Calculate the % change from the last to the current remb values */
		double dbBitrateChange = janus_vp8_remb_simulcast_calculate_bitrate_change(pSubscriber, bitrate);
		/*! Whats the ramp position we are currently sending and the one the client requested? */
        uint32_t currentRampPos = janus_vp8_remb_simulcast_get_current_ramp_position(pSim);
		uint32_t requestedRampPos = janus_vp8_remb_simulcast_get_client_requested_ramp_position(pSim);

        if((int)requestedRampPos != pRembContext->last_requested_ramp_position) {
            // What the client requested has changed...
            pRembContext->last_requested_ramp_position = requestedRampPos;
            if(requestedRampPos < currentRampPos) {
                // Client is requesting something that is lower than what we currently dispatch
                // Reset the last ramp up values
				pRembContext->failed_highest_ramp_pos = -1;
				pRembContext->failed_counter = 0;
                pRembContext->tm_last_ramp_up = 0;
            }
        }
		uint32_t nextHigherRampPos = currentRampPos;
		uint32_t nextLowerRampPos = currentRampPos;
		janus_vp8_remb_simulcast_get_neighbour_ramp_positions(pSim, currentRampPos, &nextLowerRampPos, &nextHigherRampPos);
        if(nextLowerRampPos > currentRampPos) {
		    nextHigherRampPos = currentRampPos;
		    nextLowerRampPos = currentRampPos;
		    janus_vp8_remb_simulcast_get_neighbour_ramp_positions(pSim, currentRampPos, &nextLowerRampPos, &nextHigherRampPos);
        }
		uint32_t current_bitrate = janus_vp8_remb_simulcast_get_bitrate_for_ramp_position(pRembContext, currentRampPos);
		uint32_t higher_bitrate = 0;
		if(nextHigherRampPos > currentRampPos)
			higher_bitrate = janus_vp8_remb_simulcast_get_bitrate_for_ramp_position(pRembContext, nextHigherRampPos);

		int lastLayerCounter = pRembContext->substream_switch_layer_counter;

        // Start if we have a valid last bitrate we can use for calculations (2. remb package allows us to see wether the value goes up or down)
        if(pSubscriber->last_bitrate_valid) {
            double compareValue = dbBitrateChange;
            if(pRembContext->last_bitrate_change > compareValue) {
                compareValue = pRembContext->last_bitrate_change;
            }

    		/* We have layer bitrates so the remb simulcast switching shall be active */
    		if(currentRampPos > 0 && bitrate < current_bitrate) {
                /* We are above layer 0 and the bitrate is currently lower than we need for the current layer */
    			if(bitrate < current_bitrate * 0.8 && compareValue < 0.2)	// If we are 20% below the lower bitrate and the bitself itself is not increasing by at least 0.2% between two remb messages
    				pRembContext->substream_switch_layer_counter -= 4;
    			else if(bitrate < current_bitrate * 0.9 && compareValue < 0.5) // If we are 10% below the lower bitrate and the bitself itself is not increasing by at least 0.5% between two remb messages
    				pRembContext->substream_switch_layer_counter -= 2;
    			else if(compareValue < 1) // If we are just below the lower bitrate and the bitrate is not growing by 1% between two remb messages
    				pRembContext->substream_switch_layer_counter -= 1;
    		}
    		else if(bitrate > current_bitrate) {
    			/* If the current bitrate is sufficient for the current layer increase the switcher value to 0 if it was negative before */
    			if(pRembContext->substream_switch_layer_counter < 0)
    				pRembContext->substream_switch_layer_counter ++;
    			/* We are below the highest layer and the bitrate is currently higher than we need for the current layer */
    			if(higher_bitrate && bitrate > higher_bitrate) {
    				/* The current bitrate is higher than the next layer above */
    				if(bitrate > higher_bitrate * 1.2)	// If we are 20% above the higher bitrate
    					pRembContext->substream_switch_layer_counter += 4;
    				else if(bitrate > higher_bitrate * 1.1) // If we are 10% above the higher bitrate
    					pRembContext->substream_switch_layer_counter += 2;
    				else  // If we are just above the higher bitrate
    					pRembContext->substream_switch_layer_counter += 1;
    			}
    		}
        }

		double db_time_since_last_ramp_up = 0;
		if(pRembContext->tm_last_ramp_up) {
			db_time_since_last_ramp_up = (double)(g_get_monotonic_time() - pRembContext->tm_last_ramp_up) / 1000000;
			if(pRembContext->failed_highest_ramp_pos >= 0 && db_time_since_last_ramp_up > TIME_RAMP_UP_FAILED && (int)currentRampPos >= pRembContext->failed_highest_ramp_pos) {
				/* Ramp up succeeded -> cleanup failing information */
				pRembContext->failed_highest_ramp_pos = -1;
				pRembContext->failed_counter = 0;
			}
		}

#ifdef REMB_CONSOLE_DEBUGGING
		if(lastLayerCounter != pRembContext->substream_switch_layer_counter || bitrate != pSubscriber->last_bitrate) {
			/* Only log if something relevant changed (either the counter or the remb value) */
			char szCurrent[10] = {};
			char szRequested[10] = {};
			janus_ice_handle *pCoreHandle = (janus_ice_handle*)pSubscriber->gateway_handle;
			janus_vp8_remb_simulcast_get_simulcast_current_debug(szCurrent, 10, pSim);
			janus_vp8_remb_simulcast_get_simulcast_requested_debug(szRequested, 10, pSim);
			JANUS_LOG(LOG_INFO, "%lu - br:%d (%.2f/%.2f) rmp:%d (cur:%s req:%s) cur:%d nxt:%d dir:%d t_r_up:%.1fs\n", pCoreHandle->handle_id, bitrate, dbBitrateChange, pRembContext->last_bitrate_change, currentRampPos, szCurrent, szRequested, current_bitrate, higher_bitrate, pRembContext->substream_switch_layer_counter, db_time_since_last_ramp_up);
		}
#endif

		if(pRembContext->substream_switch_layer_counter <= -20 || pRembContext->substream_switch_layer_counter >= 20) {
			/* Retrieve the publisher */
			janus_mutex_lock(pSubscriber->pFeedMutex);
			janus_vp8_remb_publisher *pPublisher = pSubscriber->pFeed;

			/* Is the publisher really simulcasting? */
			if(pPublisher->isMultiCasting(pPublisher->pOriginalPublisherObject)) {
				if(pRembContext->substream_switch_layer_counter < 0) {
					if(pRembContext->tm_last_ramp_up) {
						if(db_time_since_last_ramp_up < TIME_RAMP_UP_FAILED) {
							/* Ramping up failed -> let's store that to tune the next possible ramp up */
							pRembContext->failed_highest_ramp_pos = currentRampPos;
							pRembContext->failed_counter++;
							JANUS_LOG(LOG_WARN, "Ramping up to %d failed (%d. time%s) after %.2fs\n", currentRampPos, pRembContext->failed_counter, pRembContext->failed_counter > 1 ? "s" : "", db_time_since_last_ramp_up);
						}
						pRembContext->tm_last_ramp_up = 0;
					}

					if(janus_vp8_remb_simulcast_set_flags_for_ramp_position(pRembContext, nextLowerRampPos)) {
						uint32_t lower_bitrate = janus_vp8_remb_simulcast_get_bitrate_for_ramp_position(&pSim->remb_context, nextLowerRampPos);
						/* Switching down */
						JANUS_LOG(LOG_WARN, "Current bitrate forces to switch to a lower ramp pos: %d (%s %s %d)) \n",
							nextLowerRampPos,
							janus_vp8_remb_simulcast_get_debug_substream_to_text(pRembContext->substream_limit_by_remb != -1 ? pRembContext->substream_limit_by_remb : pSim->substream_target),
							janus_vp8_remb_simulcast_get_debug_temporal_to_text(pRembContext->templayer_limit_by_remb != -1 ? pRembContext->templayer_limit_by_remb : pSim->templayer_target),
							lower_bitrate);

						pPublisher->sendPLI(pPublisher->pOriginalPublisherObject, "Simulcasting substream change");
					}
				} else {
					if(janus_vp8_remb_simulcast_set_flags_for_ramp_position(pRembContext, nextHigherRampPos)) {
						/* Store the time when we ramped up (to get to know if it failed) */
						pRembContext->tm_last_ramp_up = g_get_monotonic_time();
						/* Switching up */
						JANUS_LOG(LOG_INFO, "Current bitrate allows to switch to a higher ramp pos: %d (%s %s %d)) \n",
							nextHigherRampPos,
							janus_vp8_remb_simulcast_get_debug_substream_to_text(pRembContext->substream_limit_by_remb != -1 ? pRembContext->substream_limit_by_remb : pSim->substream_target),
							janus_vp8_remb_simulcast_get_debug_temporal_to_text(pRembContext->templayer_limit_by_remb != -1 ? pRembContext->templayer_limit_by_remb : pSim->templayer_target),
							higher_bitrate);

						pPublisher->sendPLI(pPublisher->pOriginalPublisherObject, "Simulcasting substream change");
					}
				}
				pRembContext->substream_switch_layer_counter = 0;
			} else {
				JANUS_LOG(LOG_ERR, "REMB values trigger to switch to a differnt layer but it looks like the publisher (%s, %s) is not doing simulcast\n", pPublisher->user_id_str, pPublisher->display ? pPublisher->display : "??");
				pRembContext->publisher_simulcast_layer_count = 0;
			}
			janus_mutex_unlock(pSubscriber->pFeedMutex);
		}
		janus_vp8_remb_simulcast_update_last_bitrate_change(pRembContext, dbBitrateChange);
	} else {
		JANUS_LOG(LOG_INFO, "Nothing todo: remb:%d, publisher layercount:%d, substream:%d substream_target:%d\n", bitrate, pRembContext->publisher_simulcast_layer_count, pSim->substream, pSim->substream_target);
	}
}

/* Calculates the % delta between the current and the last remb messages.
 *
 * @param pSubscriber - the subscriber object we are handling
 * @param bitrate - the received REMB bitrate value on the peerConnection
 * @returns the delta between the last and the current remb value as signed % value (-100 <-> +100)
 */
double janus_vp8_remb_simulcast_calculate_bitrate_change(janus_vp8_remb_subscriber *pSubscriber, uint32_t bitrate) {
	double change = 0;
	if(pSubscriber->last_bitrate > 0 && bitrate)
		change = ((double)bitrate * 100 / (double)pSubscriber->last_bitrate) - 100;
	return change;
}

/* Updates the % remb change value in the janus_rtp_simulcasting_remb_context
 * the value always covers the median change over the last two remb values
 * (add the current value to the last_bitrate_change, if the value was set before divide it by 2)
 * due to this mathematic approach it is a dragged/towed value that gives you a feeling about the change in the last requests
 *
 * @param pRembContext - the currently used REMB simulcasting context
 * @param change - the % change value as calculated above
 */
void janus_vp8_remb_simulcast_update_last_bitrate_change(janus_rtp_simulcasting_remb_context *pRempContext, double change) {
	if(pRempContext->last_bitrate_change) {
		pRempContext->last_bitrate_change += change;
		pRempContext->last_bitrate_change /= 2;
	} else {
		pRempContext->last_bitrate_change += change;
	}
}

/* Retrieve the ramp position the client has chosen to receive
 *
 * @param pSim - the currently used simulcasting context
 * @returns the current ramp position based on the currently send substream and temporal layer
 */
uint32_t janus_vp8_remb_simulcast_get_client_requested_ramp_position(janus_rtp_simulcasting_context *pSim) {
	uint32_t rampPos = 0;
	int substream = (pSim->substream_target_temp == -1) ? pSim->substream_target : pSim->substream_target_temp;
	switch(substream) {
		case 1:
			rampPos = 2;
			break;
		case 2:
			rampPos = 4;
			break;
		default:
			rampPos = 0;
			break;
	}
	if(pSim->templayer_target == -1 || pSim->templayer_target == 2)
		rampPos++;
	return rampPos;
}

/* Retrieve the ramp position we currently sending to the client (client requested reduced by optional limits)
 *
 * @param pSim - the currently used simulcasting context
 * @returns the current ramp position based on the client requested and possible limits
 */
uint32_t janus_vp8_remb_simulcast_get_current_ramp_position(janus_rtp_simulcasting_context *pSim) {
 	uint32_t rampPos = 0;
	switch(pSim->substream) {
		case 1:
			rampPos = 2;
			break;
		case 2:
			rampPos = 4;
			break;
		default:
			rampPos = 0;
			break;
	}
	if(pSim->templayer == -1 || pSim->templayer == 2)
		rampPos++;
	return rampPos;
}

/*
 * Retrieve the bitrate of a dedicated ramp position, 0 if the bitrate could not be determined
 * In a failing ramp up the bitrate is automatically adjusted by +5% for each fail to eliminiate cycling
 *
 * @param pRembContext - the currently used REMB simulcasting context
 * @param rampPos - The ramp position we want to get the bitrate for
 * @returns - the bitrate value
 */
uint32_t janus_vp8_remb_simulcast_get_bitrate_for_ramp_position(janus_rtp_simulcasting_remb_context *pRembContext, uint32_t rampPos) {
	uint32_t next = 0;
	switch(rampPos) {
		case 0: /* Substream 0 L - Temporal 15fps */
			next = pRembContext->publisher_simulcast_bitrates[0] * CORRECTION_FACTOR_15FPS;
			break;
		case 1: /* Substream 0 L - Temporal 30fps */
			next = pRembContext->publisher_simulcast_bitrates[0];
			break;
		case 2: /* Substream 1 M - Temporal 15fps */
			if(pRembContext->publisher_simulcast_layer_count > 1)
				next = pRembContext->publisher_simulcast_bitrates[1] * CORRECTION_FACTOR_15FPS;
			break;
		case 3: /* Substream 1 M - Temporal 30fps */
			if(pRembContext->publisher_simulcast_layer_count > 1)
				next = pRembContext->publisher_simulcast_bitrates[1];
			break;
		case 4: /* Substream 2 H - Temporal 15fps */
			if(pRembContext->publisher_simulcast_layer_count > 2)
				next = pRembContext->publisher_simulcast_bitrates[2] * CORRECTION_FACTOR_15FPS;
			break;
		case 5: /* Substream 2 H - Temporal 30fps */
			if(pRembContext->publisher_simulcast_layer_count > 2)
				next = pRembContext->publisher_simulcast_bitrates[2];
			break;
		default:
			break;
	}

	// We had a failing in ramping up, so we adopt the bitrate of the failing layer by 5% for each failing
	// 1. failing we require 5% more
	// 2. failing we require 10% more ...
	if(pRembContext->failed_highest_ramp_pos != -1 && pRembContext->failed_highest_ramp_pos == (int)rampPos) {
		next *= 1 + pRembContext->failed_counter * REQUIRED_BITRATE_INCREASE_PER_FAIL;
	}

	return next;
}

/*
 * Retrieve the neighbour ramp positions (lower, upper) of the current one
 * As the client may have selected to receive a certain temporal/substream, the next lower layer may be not -1
 *
 * @param pSim - the currently used simulcasting context
 * @param rampPos - The current ramp position we are using
 * @param pNextLower - The next lower ramp position value
 * @param pNextHigher - The next upper ramp position value
 * @returns - the bitrate value
 */
void janus_vp8_remb_simulcast_get_neighbour_ramp_positions(janus_rtp_simulcasting_context *pSim, uint32_t rampPos, uint32_t *pNextLower, uint32_t *pNextHigher) {
	int nextLower = rampPos;
	int nextHigher = rampPos;

	if(nextLower > 0) {
		/* Decrease the ramp Position */
		nextLower--;

		/* Check that a preselected temporal from the client does not conflict our ramping up */
		if(nextLower % 2) {
			/* 1,3,5 are the layers where we switch to 30fps, */
			if (pSim->templayer_target == 0 || pSim->templayer_target == 1) {
				/* if the client is requesting a lower temporal (7fps, 15fps)
				 * we cannot use it and need to switch directly to the next lower */
				nextLower--;
			}
		}

		if(nextLower < 0)
			nextLower = 0;
	}

	if(nextHigher < 5) {
		/* Increase the ramp Position */
		nextHigher++;

		/* Check that a preselected temporal from the client does not conflict our ramping up */
		if(nextHigher % 2) {
			/* 1,3,5 are the layers where we switch to 30fps, */
			if (pSim->templayer_target == 0 || pSim->templayer_target == 1) {
				/* if the client is requesting a lower temporal (7fps, 15fps)
				 * we cannot use it and need to switch directly to the next substream */
				nextHigher++;
			}
		}

		/* whats the currently selected substream target layer from the client? (-1 means not defined, so we say highest) */
		int substream_target = pSim->substream_target;
		if (substream_target == -1)
			substream_target = 2;

		/* Check that a preselected substream layer from the client does not conflict our ramping up
		 * Ramping up next would be substream high (2), but the client requested low or mid */
		if (nextHigher > 3 && substream_target < 2)
			nextHigher = 0;

		/* Ramping up next would be substream mid (1), but the client requested low */
		else if (nextHigher > 1 && substream_target < 1)
			nextHigher = 0;
	}

	*pNextLower = (uint32_t)nextLower;
	*pNextHigher = (uint32_t)nextHigher;
}

/*
 * Sets the flags (limits) for a given ramp position in the simulcasting context
 *
 * @param pRembContext - the currently used REMB simulcasting context
 * @param rampPos - The ramp position to set the flags for
 * @returns - true in case the value was set or false
 */
gboolean janus_vp8_remb_simulcast_set_flags_for_ramp_position(janus_rtp_simulcasting_remb_context *pRembContext, uint32_t position) {
	switch(position) {
		case 0: /* Substream 0 - Temporal 15fps */
			pRembContext->substream_limit_by_remb = 0;
			pRembContext->templayer_limit_by_remb = 1;
			return TRUE;
		case 1: /* Substream 0 - Temporal 30fps */
			pRembContext->substream_limit_by_remb = 0;
			pRembContext->templayer_limit_by_remb = -1;
			return TRUE;
		case 2: /* Substream 1 - Temporal 15fps */
			pRembContext->substream_limit_by_remb = 1;
			pRembContext->templayer_limit_by_remb = 1;
			return TRUE;
		case 3: /* Substream 1 - Temporal 30fps */
			pRembContext->substream_limit_by_remb = 1;
			pRembContext->templayer_limit_by_remb = -1;
			return TRUE;
		case 4: /* Substream 2 - Temporal 15fps */
			pRembContext->substream_limit_by_remb = -1;
			pRembContext->templayer_limit_by_remb = 1;
			return TRUE;
		case 5: /* Substream 2 - Temporal 30fps */
			pRembContext->substream_limit_by_remb = -1;
			pRembContext->templayer_limit_by_remb = -1;
			return TRUE;
		default:
			return FALSE;
	}
}

/*
 * Retrieve diagnostic log text for a substream layer (L,M,H)
 *
 * @param substream - the substream layer we want to have the text for
 * @returns - L,M,H for the different substreams or unknown if the value could not get converted
 */
const char* janus_vp8_remb_simulcast_get_debug_substream_to_text(uint32_t substream) {
	switch(substream) {
		case 0:
			return "L";
		case 1:
			return "M";
		case -1:
		case 2:
			return "H";
		default:
			return "unknown";
	}
}

/*
 * Retrieve diagnostic log text for a temporal layer (7fps, 15fps, 30fps)
 *
 * @param temporal - the temporal layer we want to have the text for
 * @returns - 7fps,15fps,30fps for the different temporals or unknown if the value could not get converted
 */
const char* janus_vp8_remb_simulcast_get_debug_temporal_to_text(uint32_t temporal) {
	switch(temporal) {
		case 0:
			return "7fps";
		case 1:
			return "15fps";
		case -1:
		case 2:
			return "30fps";
		default:
			return "unknown";
	}
}

/*
 * Creates diagnostic log for the requested simulcast layers
 *
 * @param szBuffer - the buffer to copy the log to
 * @param bufSize - the buffer size in bytes
 * @param pSim - the simulcasting context
 */
void janus_vp8_remb_simulcast_get_simulcast_requested_debug(char *szBuffer, gsize bufSize, janus_rtp_simulcasting_context *pSim) {
	g_strlcat(szBuffer, janus_vp8_remb_simulcast_get_debug_substream_to_text(pSim->substream_target), bufSize);
	g_strlcat(szBuffer, " ", bufSize);
	g_strlcat(szBuffer, janus_vp8_remb_simulcast_get_debug_temporal_to_text(pSim->templayer_target), bufSize);
}

/*
 * Creates diagnostic log for the currently transported simulcast layers
 *
 * @param szBuffer - the buffer to copy the log to
 * @param bufSize - the buffer size in bytes
 * @param pSim - the simulcasting context
 */
void janus_vp8_remb_simulcast_get_simulcast_current_debug(char *szBuffer, gsize bufSize, janus_rtp_simulcasting_context *pSim) {
	g_strlcat(szBuffer, janus_vp8_remb_simulcast_get_debug_substream_to_text(pSim->substream), bufSize);
	g_strlcat(szBuffer, " ", bufSize);
	g_strlcat(szBuffer, janus_vp8_remb_simulcast_get_debug_temporal_to_text(pSim->templayer), bufSize);
}
