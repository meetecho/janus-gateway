/*! \file   janus_videoroom.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus VideoRoom plugin
 * \details Check the \ref videoroom for more details.
 *
 * \ingroup plugins
 * \ref plugins
 *
 * \page videoroom VideoRoom plugin documentation
 * This is a plugin implementing a videoconferencing SFU
 * (Selective Forwarding Unit) for Janus, that is an audio/video router.
 * This means that the plugin implements a virtual conferencing room peers
 * can join and leave at any time. This room is based on a Publish/Subscribe
 * pattern. Each peer can publish his/her own live audio/video feeds: this
 * feed becomes an available stream in the room the other participants can
 * subscribe to. This means that this plugin allows the realization of several
 * different scenarios, ranging from a simple webinar (one speaker, several
 * watchers) to a fully meshed video conference (each peer sending and
 * receiving to and from all the others).
 *
 * Notice that, since Janus now supports multistream via Unified Plan,
 * subscriptions can be done either in "bulks" (you use a single PeerConnection
 * to subscribe to multiple streams from one or more publishers) or
 * separately (each PeerConnections represents a subscription to a single
 * publisher). Same thing for publishers: you may choose to publish, e.g.,
 * audio and video on one PeerConnection, and share your screen on another,
 * or publish everything on the same PeerConnection instead. While
 * functionally both approaches (multistream vs. legacy mode) are the same
 * (the same media flows in both cases), the differences are in how
 * resources are used, and in how the client has to handle incoming and
 * outgoing connections. Besides, one approach might make more sense in
 * some scenarios, and the other make more sense in different use cases.
 * As such, the approach to follow is left to the developer and the application.
 *
 * What is important to point out, though, is that publishers and subscribers
 * will in all cases require different PeerConnections. This means that,
 * even with multistream, you won't be able to use a single PeerConnection
 * to send your contributions and receive those from everyone else. This
 * is a choice done by design, to avoid the issues that would inevitably
 * arise when doing, for instance, renegotiations to update the streams.
 *
 * On a more general note and to give some more context with respect to the
 * core functionality in Janus, notice that, considering this plugin allows
 * for several different WebRTC PeerConnections to be on at the same time
 * for the same peer (different publishers and subscribers for sure, and
 * potentially more than one of each if multistream is not in use), each
 * peer will often need to attach several times to the same plugin for each
 * stream: this means that each peer needs to have at least one handle active
 * for managing its relation with the plugin (joining a room,
 * leaving a room, muting/unmuting, publishing, receiving events), and needs
 * to open others when they want to subscribe to a feed from other participants
 * (the number depends on the subscription approach of choice). Handles
 * used for subscriptions, though, would be logically "subjects" to the master one used for
 * managing the room: this means that they cannot be used, for instance,
 * to unmute in the room, as their only purpose would be to provide a
 * context in which creating the recvonly PeerConnections for the
 * subscription(s).
 *
 * Rooms to make available are listed in the plugin configuration file.
 * A pre-filled configuration file is provided in \c conf/janus.plugin.videoroom.jcfg
 * and includes a demo room for testing. The same plugin is also used
 * dynamically (that is, with rooms created on the fly via API) in the
 * Screen Sharing demo as well.
 *
 * To add more rooms or modify the existing one, you can use the following
 * syntax:
 *
 * \verbatim
room-<unique room ID>: {
	description = This is my awesome room
	is_private = true|false (private rooms don't appear when you do a 'list' request)
	secret = <optional password needed for manipulating (e.g. destroying) the room>
	pin = <optional password needed for joining the room>
	require_pvtid = true|false (whether subscriptions are required to provide a valid
				 a valid private_id to associate with a publisher, default=false)
	publishers = <max number of concurrent senders> (e.g., 6 for a video
				 conference or 1 for a webinar, default=3)
	bitrate = <max video bitrate for senders> (e.g., 128000)
	pli_freq = <send a PLI to publishers every pli_freq seconds> (0=disable)
	audiocodec = opus|g722|pcmu|pcma|isac32|isac16 (audio codec to force on publishers, default=opus
				can be a comma separated list in order of preference, e.g., opus,pcmu)
	videocodec = vp8|vp9|h264 (video codec to force on publishers, default=vp8
				can be a comma separated list in order of preference, e.g., vp9,vp8,h264)
	opus_fec = true|false (whether inband FEC must be negotiated; only works for Opus, default=false)
	video_svc = true|false (whether SVC support must be enabled; only works for VP9, default=false)
	audiolevel_ext = true|false (whether the ssrc-audio-level RTP extension must be
		negotiated/used or not for new publishers, default=true)
	audiolevel_event = true|false (whether to emit event to other users or not)
	audio_active_packets = 100 (number of packets with audio level, default=100, 2 seconds)
	audio_level_average = 25 (average value of audio level, 127=muted, 0='too loud', default=25)
	videoorient_ext = true|false (whether the video-orientation RTP extension must be
		negotiated/used or not for new publishers, default=true)
	playoutdelay_ext = true|false (whether the playout-delay RTP extension must be
		negotiated/used or not for new publishers, default=true)
	transport_wide_cc_ext = true|false (whether the transport wide CC RTP extension must be
		negotiated/used or not for new publishers, default=true)
	record = true|false (whether this room should be recorded, default=false)
	rec_dir = <folder where recordings should be stored, when enabled>
	notify_joining = true|false (optional, whether to notify all participants when a new
				participant joins the room. The Videoroom plugin by design only notifies
				new feeds (publishers), and enabling this may result extra notification
				traffic. This flag is particularly useful when enabled with \c require_pvtid
				for admin to manage listening only participants. default=false)
}
\endverbatim
 *
 * Note that recording will work with all codecs except iSAC.
 *
 * \section sfuapi Video Room API
 *
 * The Video Room API supports several requests, some of which are
 * synchronous and some asynchronous. There are some situations, though,
 * (invalid JSON, invalid request) which will always result in a
 * synchronous error response even for asynchronous requests.
 *
 * \c create , \c destroy , \c edit , \c exists, \c list, \c allowed, \c kick and
 * and \c listparticipants are synchronous requests, which means you'll
 * get a response directly within the context of the transaction.
 * \c create allows you to create a new video room dynamically, as an
 * alternative to using the configuration file; \c edit allows you to
 * dynamically edit some room properties (e.g., the PIN); \c destroy removes a
 * video room and destroys it, kicking all the users out as part of the
 * process; \c exists allows you to check whether a specific video room
 * exists; finally, \c list lists all the available rooms, while \c
 * listparticipants lists all the active (as in currentòy publishing
 * something) participants of a specific room and their details.
 *
 * The \c join , \c joinandconfigure , \c configure , \c publish ,
 * \c unpublish , \c start , \c pause , \c switch and \c leave
 * requests instead are all asynchronous, which
 * means you'll get a notification about their success or failure in
 * an event. \c join allows you to join a specific video room, specifying
 * whether that specific PeerConnection will be used for publishing or
 * watching; \c configure can be used to modify some of the participation
 * settings (e.g., bitrate cap); \c joinandconfigure combines the previous
 * two requests in a single one (just for publishers); \c publish can be
 * used to start sending media to broadcast to the other participants,
 * while \c unpublish does the opposite; \c start allows you to start
 * receiving media from a publisher you've subscribed to previously by
 * means of a \c join , while \c pause pauses the delivery of the media;
 * the \c switch request can be used to change the source of the media
 * flowing over a specific PeerConnection (e.g., I was watching Alice,
 * I want to watch Bob now) without having to create a new handle for
 * that; \c finally, \c leave allows you to leave a video room for good
 * (or, in the case of viewers, definitely closes a subscription).
 *
 * \c create can be used to create a new video room, and has to be
 * formatted as follows:
 *
\verbatim
{
	"request" : "create",
	"room" : <unique numeric ID, optional, chosen by plugin if missing>,
	"permanent" : <true|false, whether the room should be saved in the config file, default=false>,
	"description" : "<pretty name of the room, optional>",
	"secret" : "<password required to edit/destroy the room, optional>",
	"pin" : "<password required to join the room, optional>",
	"is_private" : <true|false, whether the room should appear in a list request>,
	"allowed" : [ array of string tokens users can use to join this room, optional],
	...
}
\endverbatim
 *
 * For the sake of brevity, not all of the available settings are listed
 * here. You can refer to the name of the properties in the configuration
 * file as a reference, as the ones used to programmatically create a new
 * room are exactly the same.
 *
 * A successful creation procedure will result in a \c created response:
 *
\verbatim
{
	"videoroom" : "created",
	"room" : <unique numeric ID>,
	"permanent" : <true if saved to config file, false if not>
}
\endverbatim
 *
 * If you requested a permanent room but a \c false value is returned
 * instead, good chances are that there are permission problems.
 *
 * An error instead (and the same applies to all other requests, so this
 * won't be repeated) would provide both an error code and a more verbose
 * description of the cause of the issue:
 *
\verbatim
{
	"videoroom" : "event",
	"error_code" : <numeric ID, check Macros below>,
	"error" : "<error description as a string>"
}
\endverbatim
 *
 * Notice that, in general, all users can create rooms. If you want to
 * limit this functionality, you can configure an admin \c admin_key in
 * the plugin settings. When configured, only "create" requests that
 * include the correct \c admin_key value in an "admin_key" property
 * will succeed, and will be rejected otherwise. Notice that you can
 * optionally extend this functionality to RTP forwarding as well, in
 * order to only allow trusted clients to use that feature.
 *
 * Once a room has been created, you can still edit some (but not all)
 * of its properties using the \c edit request. This allows you to modify
 * the room description, secret, pin and whether it's private or not: you
 * won't be able to modify other more static properties, like the room ID,
 * the sampling rate, the extensions-related stuff and so on. If you're
 * interested in changing the ACL, instead, check the \c allowed message.
 * An \c edit request has to be formatted as follows:
 *
\verbatim
{
	"request" : "edit",
	"room" : <unique numeric ID of the room to edit>,
	"secret" : "<room secret, mandatory if configured>",
	"new_description" : "<new pretty name of the room, optional>",
	"new_secret" : "<new password required to edit/destroy the room, optional>",
	"new_pin" : "<new password required to join the room, optional>",
	"new_is_private" : <true|false, whether the room should appear in a list request>,
	"new_require_pvtid" : <true|false, whether the room should require private_id from subscribers>,
	"new_bitrate" : <new bitrate cap to force on all publishers (except those with custom overrides)>,
	"new_pli_freq" : <new period for regular PLI keyframe requests to publishers>,
	"new_publishers" : <new cap on the number of concurrent active WebRTC publishers>,
	"permanent" : <true|false, whether the room should be also removed from the config file, default=false>
}
\endverbatim
 *
 * A successful edit procedure will result in an \c edited response:
 *
\verbatim
{
	"videoroom" : "edited",
	"room" : <unique numeric ID>
}
\endverbatim
 *
 * On the other hand, \c destroy can be used to destroy an existing video
 * room, whether created dynamically or statically, and has to be
 * formatted as follows:
 *
\verbatim
{
	"request" : "destroy",
	"room" : <unique numeric ID of the room to destroy>,
	"secret" : "<room secret, mandatory if configured>",
	"permanent" : <true|false, whether the room should be also removed from the config file, default=false>
}
\endverbatim
 *
 * A successful destruction procedure will result in a \c destroyed response:
 *
\verbatim
{
	"videoroom" : "destroyed",
	"room" : <unique numeric ID>
}
\endverbatim
 *
 * This will also result in a \c destroyed event being sent to all the
 * participants in the video room, which will look like this:
 *
\verbatim
{
	"videoroom" : "destroyed",
	"room" : <unique numeric ID of the destroyed room>
}
\endverbatim
 *
 * You can check whether a room exists using the \c exists request,
 * which has to be formatted as follows:
 *
\verbatim
{
	"request" : "exists",
	"room" : <unique numeric ID of the room to check>
}
\endverbatim
 *
 * A successful request will result in a \c success response:
 *
\verbatim
{
	"videoroom" : "success",
	"room" : <unique numeric ID>,
	"exists" : <true|false>
}
\endverbatim
 *
 * You can configure whether to check tokens or add/remove people who can join
 * a room using the \c allowed request, which has to be formatted as follows:
 *
\verbatim
{
	"request" : "allowed",
	"secret" : "<room secret, mandatory if configured>",
	"action" : "enable|disable|add|remove",
	"room" : <unique numeric ID of the room to update>,
	"allowed" : [
		// Array of strings (tokens users might pass in "join", only for add|remove)
	]
}
\endverbatim
 *
 * A successful request will result in a \c success response:
 *
\verbatim
{
	"videoroom" : "success",
	"room" : <unique numeric ID>,
	"allowed" : [
		// Updated, complete, list of allowed tokens (only for enable|add|remove)
	]
}
\endverbatim
 *
 * If you're the administrator of a room (that is, you created it and have access
 * to the secret) you can kick participants using the \c kick request. Notice
 * that this only kicks the user out of the room, but does not prevent them from
 * re-joining: to ban them, you need to first remove them from the list of
 * authorized users (see \c allowed request) and then \c kick them. The \c kick
 * request has to be formatted as follows:
 *
\verbatim
{
	"request" : "kick",
	"secret" : "<room secret, mandatory if configured>",
	"room" : <unique numeric ID of the room>,
	"id" : <unique numeric ID of the participant to kick>
}
\endverbatim
 *
 * A successful request will result in a \c success response:
 *
\verbatim
{
	"videoroom" : "success",
}
\endverbatim
 *
 * To get a list of the available rooms (excluded those configured or
 * created as private rooms) you can make use of the \c list request,
 * which has to be formatted as follows:
 *
\verbatim
{
	"request" : "list"
}
\endverbatim
 *
 * A successful request will produce a list of rooms in a \c success response:
 *
\verbatim
{
	"videoroom" : "success",
	"rooms" : [		// Array of room objects
		{	// Room #1
			"room" : <unique numeric ID>,
			"description" : "<Name of the room>",
			"pin_required" : <true|false, whether a PIN is required to join this room>,
			"max_publishers" : <how many publishers can actually publish via WebRTC at the same time>,
			"bitrate" : <bitrate cap that should be forced (via REMB) on all publishers by default>,
			"bitrate_cap" : <true|false, whether the above cap should act as a limit to dynamic bitrate changes by publishers>,
			"pli_freq" : <how often a keyframe request is sent via PLI to active publishers>,
			"audiocodec" : "<comma separated list of allowed audio codecs>",
			"videocodec" : "<comma separated list of allowed video codecs>",
			"record" : <true|false, whether the room is being recorded>,
			"record_dir" : "<if recording, the path where the .mjr files are being saved>",
			"num_participants" : <count of the participants (publisher role instances, active or not; not subscribers)>
		},
		// Other rooms
	]
}
\endverbatim
 *
 * To get a list of the participants in a specific room, instead, you
 * can make use of the \c listparticipants request, which has to be
 * formatted as follows:
 *
\verbatim
{
	"request" : "listparticipants",
	"room" : <unique numeric ID of the room>
}
\endverbatim
 *
 * A successful request will produce a list of participants in a
 * \c participants response:
 *
\verbatim
{
	"videoroom" : "participants",
	"room" : <unique numeric ID of the room>,
	"participants" : [		// Array of participant objects
		{	// Participant #1
			"id" : <unique numeric ID of the participant>,
			"display" : "<display name of the participant, if any; optional>",
			"publisher" : <true|false, whether user is an active publisher or not>,
			"talking" : <true|false, whether user is talking or not (only if audio levels are used)>
		},
		// Other participants
	]
}
\endverbatim
 *
 * This covers almost all the synchronous requests. All the asynchronous requests,
 * plus a couple of additional synchronous requests we'll cover later, refer
 * to participants instead, namely on how they can publish, subscribe, or
 * more in general manage the media streams they may be sending or receiving.
 *
 * Considering the different nature of publishers and subscribers in the room,
 * and more importantly how you establish PeerConnections in the respective
 * cases, their API requests are addressed in separate subsections.
 *
 * \subsection vroompub VideoRoom Publishers
 *
 * In a VideoRoom, publishers are those participant handles that are able
 * (although may choose not to, more on this later) publish media in the
 * room, and as such become feeds that you can subscribe to.
 *
 * To specify a handle will be associated with a publisher, you must use
 * the \c join request with \c ptype set to \c publisher (note that, as it
 * will be explained later, you can also use \c joinandconfigure for the
 * purpose). The exact syntax of the request is the following:
 *
\verbatim
{
	"request" : "join",
	"ptype" : "publisher",
	"room" : <unique ID of the room to join>,
	"id" : <unique ID to register for the publisher; optional, will be chosen by the plugin if missing>,
	"display" : "<display name for the publisher; optional>",
	"token" : "<invitation token, in case the room has an ACL; optional>"
}
\endverbatim
 *
 * This will add the user to the list of participants in the room, although
 * in a non-active role for the time being. Anyway, this participation
 * allows the user to receive notifications about several aspects of the
 * room on the related handle (including streams as they become available
 * and go away). As such, it can be used even just as a way to get
 * notifications in a room, without the need of ever actually publishing
 * any stream at all (which explains why the "publisher" role may actually
 * be a bit confusing in this context).
 *
 * A successful \c join will result in a \c joined event, which will contain
 * a list of the currently active (as in publishing via WebRTC) publishers,
 * and optionally a list of passive attendees (but only if the room was
 * configured with \c notify_joining set to \c TRUE ):
 *
\verbatim
{
	"videoroom" : "joined",
	"room" : <room ID>,
	"description" : <description of the room, if available>,
	"id" : <unique ID of the participant>,
	"private_id" : <a different unique ID associated to the participant; meant to be private>,
	"publishers" : [
		{
			"id" : <unique ID of active publisher #1>,
			"display" : "<display name of active publisher #1, if any>",
			"streams" : [
				{
					"type" : "<type of published stream #1 (audio|video|data)">,
					"mindex" : "<unique mindex of published stream #1>",
					"mid" : "<unique mid of of published stream #1>",
					"codec" : "<codec used for published stream #1>",
					"description" : "<text description of published stream #1, if any>",
					"simulcast" : "<true if published stream #1 uses simulcast (VP8 and H.264 only)>",
					"svc" : "<true if published stream #1 uses SVC (VP9 only)>",
					"talking" : <true|false, whether the publisher stream has audio activity or not (only if audio levels are used)>,
				},
				// Other streams, if any
			],
			"talking" : <true|false, whether the publisher is talking or not (only if audio levels are used); deprecated, use the stream specific ones>,
		},
		// Other active publishers
	],
	"attendees" : [		// Only present when notify_joining is set to TRUE for rooms
		{
			"id" : <unique ID of attendee #1>,
			"display" : "<display name of attendee #1, if any>"
		},
		// Other attendees
	]
}
\endverbatim
 *
 * Notice that the publishers list will of course be empty if no one is
 * currently active in the room. For what concerns the \c private_id
 * property, it is meant to be used by the user when they create subscriptions,
 * so that the plugin can associate subscriber handles (which are typically
 * anonymous) to a specific participant; they're usually optional, unless
 * required by the room configuration.
 *
 * As explained, with a simple \c join you're not an active publisher (there
 * is no WebRTC PeerConnection yet), which means that by default your presence
 * is not notified to other participants. In fact, the publish/subscribe nature
 * of the plugin implies that by default only active publishers are notified,
 * to allow participants to subscribe to existing feeds: notifying all joins/leaves,
 * even those related to who will just lurk, may be overly verbose and chatty,
 * especially in large rooms. Anyway, rooms can be configured to notify those
 * as well, if the \c notify_joining property is set to true: in that case,
 * regular joins will be notified too, in an event formatted like this:
 *
\verbatim
{
	"videoroom" : "event",
	"room" : <room ID>,
	"joining" : {
		"id" : <unique ID of the new participant>,
		"display" : "<display name of the new participant, if any>"
	}
}
\endverbatim
 *
 * If you're interested in publishing media within a room, you can do that
 * with a \c publish request. This request MUST be accompanied by a JSEP
 * SDP offer to negotiate a new PeerConnection. The plugin will match it
 * to the room configuration (e.g., to make sure the codecs you negotiated
 * are allowed in the room), and will reply with a JSEP SDP answer to
 * close the circle and complete the setup of the PeerConnection. As soon
 * as the PeerConnection has been established, the publisher will become
 * active, and a new active feed other participants can subscribe to.
 *
 * The syntax of a \c publish request is the following:
 *
\verbatim
{
	"request" : "publish",
	"audiocodec" : "<audio codec to prefer among the negotiated ones; optional>",
	"videocodec" : "<video codec to prefer among the negotiated ones; optional>",
	"bitrate" : <bitrate cap to return via REMB; optional, overrides the global room value if present>,
	"record" : <true|false, whether this publisher should be recorded or not; optional>,
	"filename" : "<if recording, the base path/file to use for the recording files; optional>",
	"display" : "<new display name to use in the room; optional>",
	"descriptions" : [	// Optional
		{
			"mid" : "<unique mid of a stream being published>",
			"description" : "<text description of the stream (e.g., My front webcam)>"
		},
		// Other descriptions, if any
	]
}
\endverbatim
 *
 * As anticipated, since this is supposed to be accompanied by a JSEP SDP
 * offer describing the publisher's media streams, the plugin will negotiate
 * and prepare a matching JSEP SDP answer. Notice that, in principle, all
 * published streams will be only identifier by their unique \c mid and
 * by their type (e.g., audio or video). In case you want to provide more
 * information about the streams being published (e.g., to let other
 * participants know that the first video is a camera, while the second
 * video is a screen share), you can use the \c descriptions array for
 * the purpose: each object in the array can be used to add a text description
 * to associate to a specific mid, in order to help with the UI rendering.
 * The \c descriptions property is optional, so no text will be provided
 * by default: notice these descriptions can be updated dynamically via
 * \c configure requests.
 *
 * If successful, a \c configured event will be sent back, formatted like this:
 *
\verbatim
{
	"videoroom" : "event",
	"configured" : "ok"
}
\endverbatim
 *
 * This event will be accompanied by the prepared JSEP SDP answer.
 *
 * Notice that you can also use \c configure as a request instead of
 * \c publish to start publishing. The two are functionally equivalent
 * for publishing, but from a semantic perspective \c publish is the
 * right message to send when publishing. The \c configure request, as
 * it will be clearer later, can also be used to update some properties
 * of the publisher session: in this case the \c publish request can NOT
 * be used, as it can only be invoked to publish, and will fail if you're
 * already publishing something.
 *
 * As an additional note, notice that you can also join and publish in
 * a single request, which is useful in case you're not interested in
 * first join as a passive attendee and only later publish something,
 * but want to publish something right away. In this case you can use
 * the \c joinandconfigure request, which as you can imagine combines
 * the properties of both \c join and \c publish in a single request:
 * the response to a \c joinandconfigure will be a \c joined event, and
 * will again be accompanied by a JSEP SDP answer as usual.
 *
 * However you decided to publish something, as soon as the PeerConnection
 * setup succeeds and the publisher becomes active, an event is sent to
 * all the participants in the room with information on the new feed.
 * The event must contain an array with a single element, and be formatted like this:
 *
\verbatim
{
	"videoroom" : "event",
	"room" : <room ID>,
	"publishers" : [
		{
			"id" : <unique ID of the new publisher>,
			"display" : "<display name of the new publisher, if any>",
			"streams" : [
				{
					"type" : "<type of published stream #1 (audio|video|data)">,
					"mindex" : "<unique mindex of published stream #1>",
					"mid" : "<unique mid of of published stream #1>",
					"codec" : "<codec used for published stream #1>",
					"description" : "<text description of published stream #1, if any>",
					"simulcast" : "<true if published stream #1 uses simulcast (VP8 and H.264 only)>",
					"svc" : "<true if published stream #1 uses SVC (VP9 only)>",
					"talking" : <true|false, whether the publisher stream has audio activity or not (only if audio levels are used)>,
				},
				// Other streams, if any
			],
			"talking" : <true|false, whether the publisher is talking or not (only if audio levels are used); deprecated, use the stream specific ones>,
		}
	]
}
\endverbatim
 *
 * To stop publishing and tear down the related PeerConnection, you can
 * use the \c unpublish request, which requires no arguments as the context
 * is implicit:
 *
\verbatim
{
	"request" : "unpublish"
}
\endverbatim
 *
 * This will have the plugin tear down the PeerConnection, and remove the
 * publisher from the list of active streams. If successful, the response
 * will look like this:
 *
\verbatim
{
	"videoroom" : "event",
	"unpublished" : "ok"
}
\endverbatim
 *
 * As soon as the PeerConnection is gone, all the other participants will
 * also be notified about the fact that the stream is no longer available:
 *
\verbatim
{
	"videoroom" : "event",
	"room" : <room ID>,
	"unpublished" : <unique ID of the publisher who unpublished>
}
\endverbatim
 *
 * Notice that the same event will also be sent whenever the publisher
 * feed disappears for reasons other than an explicit \c unpublish , e.g.,
 * because the handle was closed or the user lost their connection.
 * Besides, notice that you can publish and unpublish multiple times
 * within the context of the same publisher handle.
 *
 * As anticipated above, you can use a request called \c configure to
 * tweak some of the properties of an active publisher session. This
 * request must be formatted as follows:
 *
\verbatim
{
	"request" : "configure",
	"bitrate" : <bitrate cap to return via REMB; optional, overrides the global room value if present (unless bitrate_cap is set)>,
	"keyframe" : <true|false, whether we should send this publisher a keyframe request>,
	"record" : <true|false, whether this publisher should be recorded or not; optional>,
	"filename" : "<if recording, the base path/file to use for the recording files; optional>",
	"display" : "<new display name to use in the room; optional>",
	"mid" : <mid of the m-line to refer to for this configure request; optional>,
	"send" : <true|false, depending on whether the media addressed by the above mid should be relayed or not; optional>,
	"descriptions" : [
		// Updated descriptions for the published streams; see "publish" for syntax; optional
	]
}
\endverbatim
 *
 * As you can see, it's basically the same properties as those listed for
 * \c publish . This is why both requests can be used to start publishing,
 * as even in that case you configure some of the settings. If successful,
 * a \c configured event will be sent back as before, formatted like this:
 *
\verbatim
{
	"videoroom" : "event",
	"configured" : "ok"
}
\endverbatim
 *
 * An interesting feature VideoRoom publisher can take advantage of is
 * RTP forwarding. In fact, while the main purpose of this plugin is
 * getting media from WebRTC sources (publishers) and relaying it to
 * WebRTC destinations (subscribers), there are actually several use
 * cases and scenarios for making this media available to external,
 * notnecessarily WebRTC-compliant, components. These components may
 * benefit from having access to the RTP media sent by a publisher, e.g.,
 * for media processing, external recording, transcoding to other
 * technologies via other applications, scalability purposes or
 * whatever else makes sense in this context. This is made possible by
 * a request called \c rtp_forward which, as the name suggests, simply
 * forwards in real-time the media sent by a publisher via RTP (plain
 * or encrypted) to a remote backend. Notice that, although we're using
 * the term "RTP forwarder", this feature can be used to forward data
 * channel messages as well.
 *
 * You can add a new RTP forwarder for an existing publisher using the
 * \c rtp_forward request, which has to be formatted as follows:
 *
\verbatim
{
	"request" : "rtp_forward",
	"room" : <unique numeric ID of the room the publisher is in>,
	"publisher_id" : <unique numeric ID of the publisher to relay externally>,
	"host" : "<host address to forward the RTP and data packets to>",
	"streams" : [
		{
			"mid" : "<mid of publisher stream to forward>",
			"host" : "<host address to forward the packets to; optional, will use global one if missing>",
			"port" : <port to forward the packets to>,
			"ssrc" : <SSRC to use to use when forwarding; optional, and only for RTP streams, not data>,
			"pt" : <payload type to use when forwarding; optional, and only for RTP streams, not data>,
			"rtcp_port" : <port to contact to receive RTCP feedback from the recipient; optional, and only for RTP streams, not data>,
			"simulcast" : <whether we need to take simulcasting into account, for this video forwarder>,
			"port_2" : <if video and simulcasting, port to forward the packets from the second substream/layer to>,
			"ssrc_2" : <if video and simulcasting, SSRC to use to use the second substream/layer; optional>,
			"pt_2" : <if video and simulcasting, payload type to use the second substream/layer; optional>,
			"port_3" : <if video and simulcasting, port to forward the packets from the third substream/layer to>,
			"ssrc_3" : <if video and simulcasting, SSRC to use to use the third substream/layer; optional>,
			"pt_3" : <if video and simulcasting, payload type to use the third substream/layer; optional>,
		},
		{
			.. other streams, if needed..
		}
	],
	"srtp_suite" : <length of authentication tag (32 or 80); optional>,
	"srtp_crypto" : "<key to use as crypto (base64 encoded key as in SDES); optional>"
}
\endverbatim
 *
 * As you can see, you basically configure each stream to forward in a
 * dedicated object of the \c streams array: for RTP streams (audio, video)
 * this includes optionally overriding payload type or SSRC; simulcast
 * streams can be forwarded separately for each layer. The only parameters
 * you MUST specify are the host and port to send the packets to: the host
 * part can be put in the global part of the request, if all streams will
 * be sent to the same IP address, while the port must be specific to the
 * stream itself.
 *
 * Notice that, as explained above, in case you configured an \c admin_key
 * property and extended it to RTP forwarding as well, you'll need to provide
 * it in the request as well or it will be rejected as unauthorized. By
 * default no limitation is posed on \c rtp_forward .
 *
 * A successful request will result in an \c rtp_forward response, containing
 * the relevant info associated to the new forwarder(s):
 *
\verbatim
{
	"videoroom" : "rtp_forward",
	"room" : <unique numeric ID, same as request>,
	"publisher_id" : <unique numeric ID, same as request>,
	"forwarders" : [
		{
			"stream_id" : <unique numeric ID assigned to this forwarder, if any>,
			"type" : "<audio|video|data>",
			"ip" : "<IP this forwarder is streaming to, same as request>",
			"port" : <port this forwarder is streaming to, same as request if configured>,
			"local_rtcp_port" : <local port this forwarder is using to get RTCP feedback, if any>,
			"remote_rtcp_port" : <remote port this forwarder getting RTCP feedback from, if any>,
			"ssrc" : <SSRC this forwarder is using, same as request if configured>,
			"pt" : <payload type this forwarder is using, same as request if configured>,
			"substream" : <video substream this video forwarder is relaying, if any>,
			"srtp" : <true|false, whether the RTP stream is encrypted>
		},
		// Other forwarders, if configured
	]
}
\endverbatim
 *
 * To stop a previously created RTP forwarder and stop it, you can use
 * the \c stop_rtp_forward request, which has to be formatted as follows:
 *
\verbatim
{
	"request" : "stop_rtp_forward",
	"room" : <unique numeric ID of the room the publisher is in>,
	"publisher_id" : <unique numeric ID of the publisher to update>,
	"stream_id" : <unique numeric ID of the RTP forwarder>
}
\endverbatim
 *
 * A successful request will result in a \c stop_rtp_forward response:
 *
\verbatim
{
	"videoroom" : "stop_rtp_forward",
	"room" : <unique numeric ID, same as request>,
	"publisher_id" : <unique numeric ID, same as request>,
	"stream_id" : <unique numeric ID, same as request>
}
\endverbatim
 *
 * To get a list of all the forwarders in a specific room, instead, you
 * can make use of the \c listforwarders request, which has to be
 * formatted as follows:
 *
\verbatim
{
	"request" : "listforwarders",
	"room" : <unique numeric ID of the room>,
	"secret" : "<room secret; mandatory if configured>"
}
\endverbatim
 *
 * A successful request will produce a list of RTP forwarders in a
 * \c forwarders response:
 *
\verbatim
{
	"videoroom" : "forwarders",
	"room" : <unique numeric ID of the room>,
	"publishers" : [		// Array of publishers with RTP forwarders
		{	// Publisher #1
			"publisher_id" : <unique numeric ID of publisher #1>,
			"forwarders" : [		// Array of RTP forwarders
				{	// RTP forwarder #1
					"stream_id" : <unique numeric ID assigned to this forwarder, if any>,
					"type" : "<audio|video|data>",
					"ip" : "<IP this forwarder is streaming to>",
					"port" : <port this forwarder is streaming to>,
					"local_rtcp_port" : <local port this forwarder is using to get RTCP feedback, if any>,
					"remote_rtcp_port" : <remote port this forwarder getting RTCP feedback from, if any>,
					"ssrc" : <SSRC this forwarder is using, if any>,
					"pt" : <payload type this forwarder is using, if any>,
					"substream" : <video substream this video forwarder is relaying, if any>,
					"srtp" : <true|false, whether the RTP stream is encrypted>
				},
				// Other forwarders for this publisher
			],
		},
		// Other publishers
	]
}
\endverbatim *
 *
 * To conclude, you can leave a room you previously joined as publisher
 * using the \c leave request. This will also implicitly unpublish you
 * if you were an active publisher in the room. The \c leave request
 * looks like follows:
 *
\verbatim
{
	"request" : "leave"
}
\endverbatim
 *
 * If successful, the response will look like this:
 *
\verbatim
{
	"videoroom" : "event",
	"leaving" : "ok"
}
\endverbatim
 *
 * Other participants will receive a different event depending on whether
 * you were currently an active publisher ("unpublished") or simply
 * lurking ("leaving"):
 *
\verbatim
{
	"videoroom" : "event",
	"room" : <room ID>,
	"leaving|unpublished" : <unique ID of the publisher who left>
}
\endverbatim
 *
 * \subsection vroomsub VideoRoom Subscribers
 *
 * In a VideoRoom, subscribers are NOT participants, but simply handles
 * that will be used exclusively to receive media from one or more publishers
 * in the room. Since they're not participants per se, they're basically
 * streams that can be (and typically are) associated to publisher handles
 * as the ones we introduced in the previous section, whether active or not.
 * In fact, the typical use case is publishers being notified about new
 * participants becoming active in the room, and as a result new subscriber
 * sessions being created to receive their media streams; as soon as the
 * publisher goes away, other participants are notified so that the related
 * subscriber handles can be removed/updated accordingly as well. As such,
 * these subscriber sessions are dependent on feedback obtained by
 * publishers, and can't exist on their own, unless you feed them the
 * right info out of band.
 *
 * To specify a handle will be associated with a subscriber, you must use
 * the \c join request with \c ptype set to \c subscriber and specify which
 * feed to subscribe to. The exact syntax of the request is the following:
 *
\verbatim
{
	"request" : "join",
	"ptype" : "subscriber",
	"room" : <unique ID of the room to subscribe in>,
	"feed" : <unique ID of the publisher to subscribe to; mandatory>,
	"private_id" : <unique ID of the publisher that originated this request; optional, unless mandated by the room configuration>,
	"streams" : [
		{
			"feed_id" : <unique ID of publisher owning the stream to subscribe to>,
			"mid" : "<unique mid of the publisher stream to subscribe to; optional>"
			// Optionally, simulcast or SVC targets (defaults if missing)
		},
		// Other streams to subscribe to
	]
}
\endverbatim
 *
 * As you can see, it's just a matter of specifying the list of streams to
 * subscribe to: in particular, you have to provide an array of objects,
 * where each objects represents a specific stream (or group of streams)
 * you're interested in. For each object, the \c feed_id indicating the
 * publisher owning the stream(s) is mandatory, while the related \c mid
 * is optional: this gives you some flexibility when subscribing, as
 * only providing a \c feed_id will indicate you're interested in ALL
 * the stream from that publisher, while providing a \c mid as well will
 * indicate you're interested in a stream in particular. Since you can
 * provide an array of streams, just specifying the \c feed_id or explicitly
 * listing all the \c feed_id + \c mid combinations is equivalent: of
 * course, different objects in the array can indicate different publishers,
 * allowing you to combine streams from different sources in the same subscription.
 *
 * Depending on whether the subscription will refer to a
 * single publisher (legacy approach) or to streams coming from different
 * publishers (multistream), the list of streams may differ. The ability
 * to single out the streams to subscribe to is particularly useful in
 * case you don't want to, or can't, subscribe to all available media:
 * e.g., you know a publisher is sending both audio and video, but video
 * is in a codec you don't support or you don't have bandwidth for both;
 * or maybe there are 10 participants in the room, but you only want video
 * from the 3 most active speakers; and so on. The content of the \c streams
 * array will shape what the SDP offer the plugin will send will look like,
 * so that eventually a subscription for the specified streams will take place.
 * Notice that, while for backwards compatibility you can still use the
 * old \c feed, \c audio, \c video, \c data, \c offer_audio, \c offer_video and
 * \c offer_data named properties, they're now deprecated and so you're
 * highly encouraged to use this new drill-down \c streams list instead.
 *
 * As anticipated, if successful this request will generate a new JSEP SDP
 * offer, which will accompany an \c attached event:
 *
\verbatim
{
	"videoroom" : "attached",
	"room" : <room ID>,
	"streams" : [
		{
			"mindex" : <unique m-index of this stream>,
			"mid" : "<unique mid of this stream>",
			"type" : "<type of this stream's media (audio|video|data)>",
			"feed_id" : <unique ID of the publisher originating this stream>,
			"feed_mid" : "<unique mid of this publisher's stream>",
			"feed_display" : "<display name of this publisher, if any>",
			"send" : <true|false; whether we configured the stream to relay media>,
			"ready" : <true|false; whether this stream is ready to start sending media (will be false at the beginning)>
		},
		// Other streams in the subscription, if any
	]
}
\endverbatim
 *
 * As you can see, a summary of the streams we subscribed to will be sent back,
 * which will be useful on the client side for both mapping and rendering purposes.
 *
 * At this stage, to complete the setup of the PeerConnection the subscriber is
 * supposed to send a JSEP SDP answer back to the plugin. This is done
 * by means of a \c start request, which in this case MUST be associated
 * with a JSEP SDP answer but otherwise requires no arguments:
 *
\verbatim
{
	"request" : "start"
}
\endverbatim
 *
 * If successful this request returns a \c started event:
 *
\verbatim
{
	"videoroom" : "event",
	"started" : "ok"
}
\endverbatim
 *
 * Once this is done, all that's needed is waiting for the WebRTC PeerConnection
 * establishment to succeed. As soon as that happens, the VideoRoom plugin
 * can start relaying media the recipient subscribed to.
 *
 * Once a WebRTC PeerConnection has been established for a subscriber, in
 * case you want to update a subscription you have to use the \c subscribe
 * and \c unsubscribe methods: as the names of the requests suggest, the
 * former allows you to add more streams to subscribe to, while the latter
 * instructs the plugin to remove streams you're currently subscribe to.
 * Both requests will trigger a renegotiation, if they were successful,
 * meaning the plugin will send you a new JSEP offer you'll have to reply
 * to with an answer: to send the answer, just use the same \c start request
 * we already described above. Notice that renegotiations may not be
 * triggered right away, e.g., whenever you're trying to update a session
 * and the plugin is still in the process of renegoting a previous update
 * for the same subscription: in that case, an update will be scheduled
 * and a renegotiation will be triggered as soon as it's viable.
 *
 * The syntax of the \c subscribe mirrors the one for new subscriptions,
 * meaning you use the same \c streams array to address the new streams
 * you want to receive, and formatted the same way:
 *
\verbatim
{
	"request" : "subscribe",
	"streams" : [
		{
			"feed_id" : <unique ID of publisher owning the new stream to subscribe to>,
			"mid" : "<unique mid of the publisher stream to subscribe to; optional>"
			// Optionally, simulcast or SVC targets (defaults if missing)
		},
		// Other new streams to subscribe to
	]
}
\endverbatim
 *
 * This means the exact same considerations we made on \c streams before
 * apply here as well: whatever they represent, will indicate the willingness
 * to subscribe to the related stream. Notice that if you were already
 * subscribed to one of the new streams indicated here, you'll subscribe
 * to it again in a different m-line, so it's up to you to ensure you
 * avoid duplicates (unless that's what you wanted, e.g., for testing
 * purposes). In case the update was successful, you'll get an \c updated
 * event, containing the updated layout of all subscriptions (pre-existing
 * and new ones), and a new JSEP offer to renegotiate the session:
 *
\verbatim
{
	"videoroom" : "updated",
	"room" : <room ID>,
	"streams": [
		{
			"mindex" : <unique m-index of this stream>,
			"mid" : "<unique mid of this stream>",
			"type" : "<type of this stream's media (audio|video|data)>",
			"feed_id" : <unique ID of the publisher originating this stream>,
			"feed_mid" : "<unique mid of this publisher's stream>",
			"feed_display" : "<display name of this publisher, if any>",
			"send" : <true|false; whether we configured the stream to relay media>,
			"ready" : <true|false; whether this stream is ready to start sending media (will be false at the beginning)>
		},
		// Other streams in the subscription, if any; old and new
	]
}
\endverbatim
 *
 * As explained before, in case the message contains a JSEP offer (which may
 * not be the case if no change occurred), then clients will need to send
 * a new JSEP answer with a \c start request to close this renegotiation.
 *
 * The \c unsubscribe request works pretty much the same way, with the
 * difference that the \c streams array you provide to specify what to
 * unsubscribe from may look different. Specifically, the syntax looks
 * like this:
 *
\verbatim
{
	"request" : "unsubscribe",
	"streams" : [
		{
			"feed_id" : <unique ID of publisher owning the new stream to unsubscribe from; optional>,
			"mid" : "<unique mid of the publisher stream to unsubscribe from; optional>"
			"sub_mid" : "<unique mid of the subscriber stream to unsubscribe; optional>"
		},
		// Other streams to unsubscribe from
	]
}
\endverbatim
 *
 * This means that you have different ways to specify what to unsubscribe from:
 * if an object only specifies \c feed_id, then all the subscription streams that
 * were receiving media from that publisher will be removed; if an object
 * specifies \c feed_id and \c mid, then all the subscription streams that
 * were receiving media from the publisher stream with the related mid will be
 * removed; finally, if an object only specifies \c sub_mid instead, then
 * only the stream in the subscription that is addressed by the related mid
 * (subscription mid, no relation to the publishers') will be removed. As
 * such, you have a great deal of flexibility in how to unsubscribe from
 * media. Notice that multiple streams may be removed in case you refer
 * to the "source" ( \c feed_id ), rather than the "sink" ( \c sub_mid ),
 * especially in case the subscription contained duplicates or multiple
 * streams from the same publisher.
 *
 * A successful \c unsubscribe will result in exactly the same \c updated
 * event \c subscribe triggers, so the same considerations apply with
 * respect to the potential need of a renegotiation and how to complete
 * it with a \c start along a JSEP answer.
 *
 * Notice that, in case you want to trigger an ICE restart rather than
 * updating a subscription, you'll have to use a different request, named
 * \c configure: this will be explained in a few paragraphs.
 *
 * As a subscriber, you can temporarily pause and resume the whole media delivery
 * with a \c pause and, again, \c start request (in this case without any JSEP
 * SDP answer attached). Neither expect other arguments, as the context
 * is implicitly derived from the handle they're sent on:
 *
\verbatim
{
	"request" : "pause"
}
\endverbatim
 *
\verbatim
{
	"request" : "start"
}
\endverbatim
 *
 * Unsurprisingly, they just result in, respectively, \c paused and
 * \c started events:
 *
\verbatim
{
	"videoroom" : "event",
	"paused" : "ok"
}
\endverbatim
 *
\verbatim
{
	"videoroom" : "event",
	"started" : "ok"
}
\endverbatim
 *
 * For more drill-down manipulations of a subscription, a \c configure
 * request can be used instead. This request allows subscribers to dynamically
 * change some properties associated to their media subscription, e.g.,
 * in terms of what should and should not be sent at a specific time. A
 * \c configure request must be formatted as follows:
 *
\verbatim
{
	"request" : "configure",
	"mid" : <mid of the m-line to refer to for this configure request; optional>,
	"send" : <true|false, depending on whether the mindex media should be relayed or not; optional>,
	"substream" : <substream to receive (0-2), in case simulcasting is enabled; optional>,
	"temporal" : <temporal layers to receive (0-2), in case simulcasting is enabled; optional>,
	"spatial_layer" : <spatial layer to receive (0-2), in case VP9-SVC is enabled; optional>,
	"temporal_layer" : <temporal layers to receive (0-2), in case VP9-SVC is enabled; optional>,
	"restart" : <trigger an ICE restart; optional>
}
\endverbatim
 *
 * As you can see, the \c mid and \c send properties can be used as a media-level
 * pause/resume functionality ("only mute/unmute this mid"), whereas \c pause
 * and \c start simply pause and resume all streams at the same time.
 * The \c substream and \c temporal properties, instead, only make sense
 * when the mountpoint is configured with video simulcasting support, and
 * as such the viewer is interested in receiving a specific substream
 * or temporal layer, rather than any other of the available ones: notice
 * that for them to work you'll have to specify the \c mid as well, as the same
 * subscription may be receiving simulcast stream from multiple publishers.
 * The \c spatial_layer and \c temporal_layer have exactly the same meaning,
 * but within the context of VP9-SVC publishers, and will have no effect
 * on subscriptions associated to regular publishers.
 *
 * As anticipated, \c configure is also the request you use when you want
 * to trigger an ICE restart for a subscriber: in fact, while publishers
 * can force a restart themselves by providing the right JSEP offer, subscribers
 * always receive an offer from Janus instead, and as such have to
 * explicitly ask for a dedicated offer when an ICE restart is needed;
 * in that case, just set \c restart to \c true in a \c configure request,
 * and a new JSEP offer with ICE restart information will be sent to the
 * client, to which the client will have to reply, as usual, via \c start
 * along a JSEP answer. This documentation doesn't explain when or why
 * an ICE restart is needed or appropriate: please refer to the ICE RFC
 * or other sources of information for that.
 *
 * Another interesting feature that subscribers can take advantage of is the
 * so-called publisher "switching". Basically, when subscribed to one or more
 * publishers and receiving media from them, you can at any time "switch"
 * any of the subscription streams to a different publisher, and as such
 * start receiving media on the related m-line from that publisher instead,
 * all without doing a new \c subscribe or \c unsubscribe, and so without
 * the need of doing any renegotiation at all; just some logic changes.
 * Think of it as changing channel on a TV: you keep on using the same
 * PeerConnection, the plugin simply changes the source of the media
 * transparently. Of course, while powerful and effective this request has
 * some limitations: in fact, the source (audio or video) that you switch
 * to must have the same media configuration (e.g., same codec) as the source
 * you're replacing. In fact, since the same PeerConnection is used for this
 * feature and no renegotiation is taking place, switching to a stream with
 * a different configuration would result in media incompatible with the
 * PeerConnection setup being relayed to the subscriber (e.g., negotiated
 * VP9, but new source is H.264), and as such in no audio/video being played;
 * in that case, you'll need a \c subscribe instead, and a new m-line.
 *
 * That said, a \c switch request must be formatted like this:
 *
\verbatim
{
	"request" : "switch",
	"streams" : [
		{
			"feed" : <unique ID of the publisher the new source is from>,
			"mid" : "<unique mid of the source we want to switch to>",
			"sub_mid" : "<unique mid of the stream we want to pipe the new source to>"
		},
		{
			// Other updates, if any
		}
	]
}
\endverbatim
 *
 * While apparently convoluted, this is actually a quite effective and powerful
 * way of updating subscriptions without renegotiating. In fact, it allows for
 * full or partial switches: for instance, sometimes you may want to replace all
 * audio and video streams (e.g., switching from Bob to Alice in a "legacy"
 * VideoRoom usage, where each PeerConnection subscription is a different
 * publisher), or just replace a subset of them (e.g., you have a subscription
 * with three video slots, and you change one of them depending on the loudest
 * speaker). What to replace is dictated by the \c streams array, where each
 * object in the array contains all the info needed for the switch to take
 * place: in particular, you must specify which of your subscription m-lines
 * you're going to update, via \c sub_mid , and which publisher stream should
 * now start to feed it via \c feed and \c mid.
 *
 * If successful, the specified subscriptions will be updated, meaning they'll
 * be unsubscribed from the previous publisher stream, and subscribed to the
 * new publisher stream instead, all without a renegotiation (so no new SDP
 * offer/answer exchange to take care of). The event to confirm the switch
 * was successful will look like this:
 *
\verbatim
{
	"videoroom" : "event",
	"switched" : "ok",
	"room" : <room ID>,
	"changes" : <number of successful changes (may be smaller than the size of the streams array provided in the request)>,
	"streams" : [
		// Current configuration of the subscription, same format as when subscribing
		// Will contain info on all streams, not only those that have been updated
	]
}
\endverbatim
 *
 * Notice that, while a \c switch request usually doesn't require a renegotiation,
 * it \b MIGHT trigger one nevertheless: in fact, if a "switch" request assigns
 * a new publisher stream to a previously inactive subscriber stream, then
 * a renegotiation to re-activate that stream will be needed as well, as
 * otherwise the packets from the new source will not be relayed.
 *
 * Finally, to close a subscription and tear down the related PeerConnection,
 * you can use the \c leave request. Since context is implicit, no other
 * argument is required:
 *
\verbatim
{
	"request" : "leave"
}
\endverbatim
 *
 * If successful, the plugin will attempt to tear down the PeerConnection,
 * and will send back a \c left event:
 *
\verbatim
{
	"videoroom" : "event",
	"left" : "ok",
}
\endverbatim
 */

#include "plugin.h"

#include <jansson.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../rtp.h"
#include "../rtpsrtp.h"
#include "../rtcp.h"
#include "../record.h"
#include "../sdp-utils.h"
#include "../utils.h"
#include <sys/types.h>
#include <sys/socket.h>


/* Plugin information */
#define JANUS_VIDEOROOM_VERSION			10
#define JANUS_VIDEOROOM_VERSION_STRING	"0.0.10"
#define JANUS_VIDEOROOM_DESCRIPTION		"This is a plugin implementing a videoconferencing SFU (Selective Forwarding Unit) for Janus, that is an audio/video router."
#define JANUS_VIDEOROOM_NAME			"JANUS VideoRoom plugin"
#define JANUS_VIDEOROOM_AUTHOR			"Meetecho s.r.l."
#define JANUS_VIDEOROOM_PACKAGE			"janus.plugin.videoroom"

/* Plugin methods */
janus_plugin *create(void);
int janus_videoroom_init(janus_callbacks *callback, const char *config_path);
void janus_videoroom_destroy(void);
int janus_videoroom_get_api_compatibility(void);
int janus_videoroom_get_version(void);
const char *janus_videoroom_get_version_string(void);
const char *janus_videoroom_get_description(void);
const char *janus_videoroom_get_name(void);
const char *janus_videoroom_get_author(void);
const char *janus_videoroom_get_package(void);
void janus_videoroom_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_videoroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
json_t *janus_videoroom_handle_admin_message(json_t *message);
void janus_videoroom_setup_media(janus_plugin_session *handle);
void janus_videoroom_incoming_rtp(janus_plugin_session *handle, int mindex, gboolean video, char *buf, int len);
void janus_videoroom_incoming_rtcp(janus_plugin_session *handle, int mindex, gboolean video, char *buf, int len);
void janus_videoroom_incoming_data(janus_plugin_session *handle, char *label, char *buf, int len);
void janus_videoroom_slow_link(janus_plugin_session *handle, int mindex, gboolean video, gboolean uplink);
void janus_videoroom_hangup_media(janus_plugin_session *handle);
void janus_videoroom_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_videoroom_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_videoroom_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_videoroom_init,
		.destroy = janus_videoroom_destroy,

		.get_api_compatibility = janus_videoroom_get_api_compatibility,
		.get_version = janus_videoroom_get_version,
		.get_version_string = janus_videoroom_get_version_string,
		.get_description = janus_videoroom_get_description,
		.get_name = janus_videoroom_get_name,
		.get_author = janus_videoroom_get_author,
		.get_package = janus_videoroom_get_package,

		.create_session = janus_videoroom_create_session,
		.handle_message = janus_videoroom_handle_message,
		.handle_admin_message = janus_videoroom_handle_admin_message,
		.setup_media = janus_videoroom_setup_media,
		.incoming_rtp = janus_videoroom_incoming_rtp,
		.incoming_rtcp = janus_videoroom_incoming_rtcp,
		.incoming_data = janus_videoroom_incoming_data,
		.slow_link = janus_videoroom_slow_link,
		.hangup_media = janus_videoroom_hangup_media,
		.destroy_session = janus_videoroom_destroy_session,
		.query_session = janus_videoroom_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_VIDEOROOM_NAME);
	return &janus_videoroom_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter adminkey_parameters[] = {
	{"admin_key", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter create_parameters[] = {
	{"room", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"description", JANUS_JSON_STRING, 0},
	{"is_private", JANUS_JSON_BOOL, 0},
	{"allowed", JANUS_JSON_ARRAY, 0},
	{"secret", JANUS_JSON_STRING, 0},
	{"pin", JANUS_JSON_STRING, 0},
	{"require_pvtid", JANUS_JSON_BOOL, 0},
	{"bitrate", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"bitrate_cap", JANUS_JSON_BOOL, 0},
	{"pli_freq", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"fir_freq", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},	/* Deprecated! */
	{"publishers", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audiocodec", JANUS_JSON_STRING, 0},
	{"videocodec", JANUS_JSON_STRING, 0},
	{"opus_fec", JANUS_JSON_BOOL, 0},
	{"video_svc", JANUS_JSON_BOOL, 0},
	{"audiolevel_ext", JANUS_JSON_BOOL, 0},
	{"audiolevel_event", JANUS_JSON_BOOL, 0},
	{"audio_active_packets", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_level_average", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"videoorient_ext", JANUS_JSON_BOOL, 0},
	{"playoutdelay_ext", JANUS_JSON_BOOL, 0},
	{"transport_wide_cc_ext", JANUS_JSON_BOOL, 0},
	{"record", JANUS_JSON_BOOL, 0},
	{"rec_dir", JANUS_JSON_STRING, 0},
	{"permanent", JANUS_JSON_BOOL, 0},
	{"notify_joining", JANUS_JSON_BOOL, 0},
};
static struct janus_json_parameter edit_parameters[] = {
	{"room", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"secret", JANUS_JSON_STRING, 0},
	{"new_description", JANUS_JSON_STRING, 0},
	{"new_is_private", JANUS_JSON_BOOL, 0},
	{"new_secret", JANUS_JSON_STRING, 0},
	{"new_pin", JANUS_JSON_STRING, 0},
	{"new_require_pvtid", JANUS_JSON_BOOL, 0},
	{"new_bitrate", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"new_pli_freq", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"new_fir_freq", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},	/* Deprecated! */
	{"new_publishers", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter room_parameters[] = {
	{"room", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter destroy_parameters[] = {
	{"room", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter allowed_parameters[] = {
	{"room", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"secret", JANUS_JSON_STRING, 0},
	{"action", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"allowed", JANUS_JSON_ARRAY, 0}
};
static struct janus_json_parameter kick_parameters[] = {
	{"room", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"secret", JANUS_JSON_STRING, 0},
	{"id", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter join_parameters[] = {
	{"room", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"ptype", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"descriptions", JANUS_JSON_ARRAY, 0},
	{"audio", JANUS_JSON_BOOL, 0},	/* Deprecated! */
	{"video", JANUS_JSON_BOOL, 0},	/* Deprecated! */
	{"data", JANUS_JSON_BOOL, 0},	/* Deprecated! */
	{"bitrate", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"record", JANUS_JSON_BOOL, 0},
	{"filename", JANUS_JSON_STRING, 0},
	{"token", JANUS_JSON_STRING, 0}
};
static struct janus_json_parameter publish_parameters[] = {
	{"descriptions", JANUS_JSON_ARRAY, 0},
	{"audiocodec", JANUS_JSON_STRING, 0},
	{"videocodec", JANUS_JSON_STRING, 0},
	{"bitrate", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"keyframe", JANUS_JSON_BOOL, 0},
	{"record", JANUS_JSON_BOOL, 0},
	{"filename", JANUS_JSON_STRING, 0},
	{"display", JANUS_JSON_STRING, 0},
	/* Only needed when configuring, to make a stream active/inactive */
	{"mid", JANUS_JSON_STRING, 0},
	{"send", JANUS_JSON_BOOL, 0},
	/* Deprecated, use mid+send instead */
	{"audio", JANUS_JSON_BOOL, 0},	/* Deprecated! */
	{"video", JANUS_JSON_BOOL, 0},	/* Deprecated! */
	{"data", JANUS_JSON_BOOL, 0},	/* Deprecated! */
	/* The following are just to force a renegotiation and/or an ICE restart */
	{"update", JANUS_JSON_BOOL, 0},
	{"restart", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter publish_desc_parameters[] = {
	{"mid", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"description", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter rtp_forward_parameters[] = {
	{"room", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"publisher_id", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"host", JANUS_JSON_STRING, 0},
	{"simulcast", JANUS_JSON_BOOL, 0},
	{"srtp_suite", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"srtp_crypto", JANUS_JSON_STRING, 0},
	{"streams", JANUS_JSON_ARRAY, 0},
	/* Deprecated parameters, use the streams array instead */
	{"video_port", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video_rtcp_port", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video_ssrc", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video_pt", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video_port_2", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video_ssrc_2", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video_pt_2", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video_port_3", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video_ssrc_3", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video_pt_3", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_port", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_rtcp_port", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_ssrc", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_pt", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"data_port", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
};
static struct janus_json_parameter rtp_forward_stream_parameters[] = {
	{"host", JANUS_JSON_STRING, 0},
	{"port", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"rtcp_port", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"ssrc", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"pt", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"simulcast", JANUS_JSON_BOOL, 0},
	{"port_2", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"ssrc_2", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"pt_2", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"port_3", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"ssrc_3", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"pt_3", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter stop_rtp_forward_parameters[] = {
	{"room", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"publisher_id", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"stream_id", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter publisher_parameters[] = {
	{"id", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"display", JANUS_JSON_STRING, 0}
};
static struct janus_json_parameter configure_parameters[] = {
	{"mid", JANUS_JSON_STRING, 0},
	{"send", JANUS_JSON_BOOL, 0},
	/* For VP8 (or H.264) simulcast */
	{"substream", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"temporal", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	/* For VP9 SVC */
	{"spatial_layer", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"temporal_layer", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	/* The following is to handle a renegotiation */
	{"update", JANUS_JSON_BOOL, 0},
	/* Deprecated properties, use mid+send instead */
	{"audio", JANUS_JSON_BOOL, 0},	/* Deprecated */
	{"video", JANUS_JSON_BOOL, 0},	/* Deprecated */
	{"data", JANUS_JSON_BOOL, 0}	/* Deprecated */
};
static struct janus_json_parameter subscriber_parameters[] = {
	{"streams", JANUS_JSON_ARRAY, 0},
	{"feed", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},	/* Deprecated! Use feed in streams instead */
	{"private_id", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"close_pc", JANUS_JSON_BOOL, 0},
	/* All the following parameters are deprecated: use streams instead */
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"data", JANUS_JSON_BOOL, 0},
	{"offer_audio", JANUS_JSON_BOOL, 0},
	{"offer_video", JANUS_JSON_BOOL, 0},
	{"offer_data", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter subscriber_stream_parameters[] = {
	{"feed", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"mid", JANUS_JSON_STRING, 0},
	/* For VP8 (or H.264) simulcast */
	{"substream", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"temporal", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	/* For VP9 SVC */
	{"spatial_layer", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"temporal_layer", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter subscriber_update_parameters[] = {
	{"streams", JANUS_JSON_ARRAY, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter subscriber_remove_parameters[] = {
	{"feed", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"mid", JANUS_JSON_STRING, 0},
	{"sub_mid", JANUS_JSON_STRING, 0}
};
static struct janus_json_parameter switch_parameters[] = {
	{"streams", JANUS_JSON_ARRAY, 0}
};
static struct janus_json_parameter switch_update_parameters[] = {
	{"feed", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"mid", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"sub_mid", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};

/* Static configuration instance */
static janus_config *config = NULL;
static const char *config_folder = NULL;
static janus_mutex config_mutex = JANUS_MUTEX_INITIALIZER;

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_videoroom_handler(void *data);
static void janus_videoroom_relay_rtp_packet(gpointer data, gpointer user_data);
static void janus_videoroom_relay_data_packet(gpointer data, gpointer user_data);
static void janus_videoroom_hangup_media_internal(janus_plugin_session *handle);

typedef enum janus_videoroom_p_type {
	janus_videoroom_p_type_none = 0,
	janus_videoroom_p_type_subscriber,			/* Generic subscriber */
	janus_videoroom_p_type_publisher,			/* Participant (for receiving events) and optionally publisher */
} janus_videoroom_p_type;

typedef enum janus_videoroom_media {
	JANUS_VIDEOROOM_MEDIA_NONE = 0,
	JANUS_VIDEOROOM_MEDIA_AUDIO,
	JANUS_VIDEOROOM_MEDIA_VIDEO,
	JANUS_VIDEOROOM_MEDIA_DATA
} janus_videoroom_media;
static const char *janus_videoroom_media_str(janus_videoroom_media type) {
	switch(type) {
		case JANUS_VIDEOROOM_MEDIA_AUDIO: return "audio";
		case JANUS_VIDEOROOM_MEDIA_VIDEO: return "video";
		case JANUS_VIDEOROOM_MEDIA_DATA: return "data";
		case JANUS_VIDEOROOM_MEDIA_NONE:
		default:
			break;
	}
	return NULL;
}
static janus_sdp_mtype janus_videoroom_media_sdptype(janus_videoroom_media type) {
	switch(type) {
		case JANUS_VIDEOROOM_MEDIA_AUDIO: return JANUS_SDP_AUDIO;
		case JANUS_VIDEOROOM_MEDIA_VIDEO: return JANUS_SDP_VIDEO;
		case JANUS_VIDEOROOM_MEDIA_DATA: return JANUS_SDP_APPLICATION;
		case JANUS_VIDEOROOM_MEDIA_NONE:
		default:
			break;
	}
	return JANUS_SDP_OTHER;
}

typedef struct janus_videoroom_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_videoroom_message;
static GAsyncQueue *messages = NULL;
static janus_videoroom_message exit_message;


typedef struct janus_videoroom {
	guint64 room_id;			/* Unique room ID */
	gchar *room_name;			/* Room description */
	gchar *room_secret;			/* Secret needed to manipulate (e.g., destroy) this room */
	gchar *room_pin;			/* Password needed to join this room, if any */
	gboolean is_private;		/* Whether this room is 'private' (as in hidden) or not */
	gboolean require_pvtid;		/* Whether subscriptions in this room require a private_id */
	int max_publishers;			/* Maximum number of concurrent publishers */
	uint32_t bitrate;			/* Global bitrate limit */
	gboolean bitrate_cap;		/* Whether the above limit is insormountable */
	uint16_t pli_freq;			/* Regular PLI frequency (0=disabled) */
	janus_audiocodec acodec[3];	/* Audio codec(s) to force on publishers */
	janus_videocodec vcodec[3];	/* Video codec(s) to force on publishers */
	gboolean do_opusfec;		/* Whether inband FEC must be negotiated (note: only available for Opus) */
	gboolean do_svc;			/* Whether SVC must be done for video (note: only available for VP9 right now) */
	gboolean audiolevel_ext;	/* Whether the ssrc-audio-level extension must be negotiated or not for new publishers */
	gboolean audiolevel_event;	/* Whether to emit event to other users about audiolevel */
	int audio_active_packets;	/* Amount of packets with audio level for checkup */
	int audio_level_average;	/* Average audio level */
	gboolean videoorient_ext;	/* Whether the video-orientation extension must be negotiated or not for new publishers */
	gboolean playoutdelay_ext;	/* Whether the playout-delay extension must be negotiated or not for new publishers */
	gboolean transport_wide_cc_ext;	/* Whether the transport wide cc extension must be negotiated or not for new publishers */
	gboolean record;			/* Whether the feeds from publishers in this room should be recorded */
	char *rec_dir;				/* Where to save the recordings of this room, if enabled */
	GHashTable *participants;	/* Map of potential publishers (we get subscribers from them) */
	GHashTable *private_ids;	/* Map of existing private IDs */
	volatile gint destroyed;	/* Whether this room has been destroyed */
	gboolean check_allowed;		/* Whether to check tokens when participants join (see below) */
	GHashTable *allowed;		/* Map of participants (as tokens) allowed to join */
	gboolean notify_joining;	/* Whether an event is sent to notify all participants if a new participant joins the room */
	janus_mutex mutex;			/* Mutex to lock this room instance */
	janus_refcount ref;			/* Reference counter for this room */
} janus_videoroom;
static GHashTable *rooms;
static janus_mutex rooms_mutex = JANUS_MUTEX_INITIALIZER;
static char *admin_key = NULL;
static gboolean lock_rtpfwd = FALSE;

typedef struct janus_videoroom_session {
	janus_plugin_session *handle;
	gint64 sdp_sessid;
	gint64 sdp_version;
	janus_videoroom_p_type participant_type;
	gpointer participant;
	gboolean started;
	gboolean stopping;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_mutex mutex;
	janus_refcount ref;
} janus_videoroom_session;
static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

/* A host whose ports gets streamed RTP packets of the corresponding type */
typedef struct janus_videoroom_srtp_context janus_videoroom_srtp_context;
typedef struct janus_videoroom_rtp_forwarder {
	void *source;
	guint32 stream_id;
	gboolean is_video;
	gboolean is_data;
	uint32_t ssrc;
	int payload_type;
	int substream;
	struct sockaddr_in serv_addr;
	/* Only needed for RTCP */
	int rtcp_fd;
	uint16_t local_rtcp_port, remote_rtcp_port;
	GSource *rtcp_recv;
	/* Only needed when forwarding simulcasted streams to a single endpoint */
	gboolean simulcast;
	janus_rtp_switching_context context;
	janus_rtp_simulcasting_context sim_context;
	/* Only needed for SRTP forwarders */
	gboolean is_srtp;
	janus_videoroom_srtp_context *srtp_ctx;
	/* Reference */
	volatile gint destroyed;
	janus_refcount ref;
} janus_videoroom_rtp_forwarder;
static void janus_videoroom_rtp_forwarder_destroy(janus_videoroom_rtp_forwarder *forward);
static void janus_videoroom_rtp_forwarder_free(const janus_refcount *f_ref);
/* SRTP encryption may be needed, and potentially shared */
struct janus_videoroom_srtp_context {
	GHashTable *contexts;
	char *id;
	srtp_t ctx;
	srtp_policy_t policy;
	char sbuf[1500];
	int slen;
	/* Keep track of how many forwarders are using this context */
	uint8_t count;
};
static void janus_videoroom_srtp_context_free(gpointer data);
/* RTCP support in RTP forwarders */
typedef struct janus_videoroom_rtcp_receiver {
	GSource parent;
	janus_videoroom_rtp_forwarder *forward;
	GDestroyNotify destroy;
} janus_videoroom_rtcp_receiver;
static void janus_videoroom_rtp_forwarder_rtcp_receive(janus_videoroom_rtp_forwarder *forward);
static gboolean janus_videoroom_rtp_forwarder_rtcp_prepare(GSource *source, gint *timeout) {
	*timeout = -1;
	return FALSE;
}
static gboolean janus_videoroom_rtp_forwarder_rtcp_dispatch(GSource *source, GSourceFunc callback, gpointer user_data) {
	janus_videoroom_rtcp_receiver *r = (janus_videoroom_rtcp_receiver *)source;
	/* Receive the packet */
	if(r)
		janus_videoroom_rtp_forwarder_rtcp_receive(r->forward);
	return G_SOURCE_CONTINUE;
}
static void janus_videoroom_rtp_forwarder_rtcp_finalize(GSource *source) {
	janus_videoroom_rtcp_receiver *r = (janus_videoroom_rtcp_receiver *)source;
	/* Remove the reference to the forwarder */
	if(r && r->forward)
		janus_refcount_decrease(&r->forward->ref);
}
static GSourceFuncs janus_videoroom_rtp_forwarder_rtcp_funcs = {
	janus_videoroom_rtp_forwarder_rtcp_prepare,
	NULL,
	janus_videoroom_rtp_forwarder_rtcp_dispatch,
	janus_videoroom_rtp_forwarder_rtcp_finalize,
	NULL, NULL
};
static GMainContext *rtcpfwd_ctx = NULL;
static GMainLoop *rtcpfwd_loop = NULL;
static GThread *rtcpfwd_thread = NULL;
static void *janus_videoroom_rtp_forwarder_rtcp_thread(void *data);

typedef struct janus_videoroom_publisher {
	janus_videoroom_session *session;
	janus_videoroom *room;		/* Room */
	guint64 room_id;			/* Unique room ID */
	guint64 user_id;			/* Unique ID in the room */
	guint32 pvt_id;				/* This is sent to the publisher for mapping purposes, but shouldn't be shared with others */
	gchar *display;				/* Display name (just for fun) */
	gboolean firefox;			/* Firefox and Chrome use different b= attributes (TIAS vs AS) */
	GList *streams;				/* List of media streams sent by this publisher (audio, video and/or data) */
	GHashTable *streams_byid;	/* As above, indexed by mindex */
	GHashTable *streams_bymid;	/* As above, indexed by mid */
	int data_mindex;			/* We keep track of the mindex for data, as there can only be one */
	janus_mutex streams_mutex;
	uint32_t bitrate;
	gint64 remb_startup;		/* Incremental changes on REMB to reach the target at startup */
	gint64 remb_latest;			/* Time of latest sent REMB (to avoid flooding) */
	gboolean recording_active;	/* Whether this publisher has to be recorded or not */
	gchar *recording_base;		/* Base name for the recording (e.g., /path/to/filename, will generate /path/to/filename-audio.mjr and/or /path/to/filename-video.mjr */
	janus_mutex rec_mutex;		/* Mutex to protect the recorders from race conditions */
	GSList *subscriptions;		/* Subscriptions this publisher has created (who this publisher is watching) */
	janus_mutex subscribers_mutex;
	GHashTable *srtp_contexts;	/* SRTP contexts that we can share among RTP forwarders */
	/* Index of RTP (or data) forwarders for this stream, if any */
	GHashTable *rtp_forwarders;
	janus_mutex rtp_forwarders_mutex;
	int udp_sock; 				/* The udp socket on which to forward rtp packets */
	gboolean kicked;			/* Whether this participant has been kicked */
	volatile gint destroyed;
	janus_refcount ref;
} janus_videoroom_publisher;
/* Each VideoRoom publisher can share multiple streams, so each stream is its own structure */
typedef struct janus_videoroom_publisher_stream {
	janus_videoroom_publisher *publisher;	/* Publisher instance this stream belongs to */
	janus_videoroom_media type;				/* Type of this stream (audio, video or data) */
	int mindex;								/* mindex of this stream */
	char *mid;								/* mid of this stream */
	char *description;						/* Description of this stream (user provided) */
	gboolean active;						/* Whether this stream is active or not */
	janus_audiocodec acodec;				/* Audio codec this publisher is using (if audio) */
	janus_videocodec vcodec;				/* Video codec this publisher is using (if video) */
	int pt;									/* Payload type of this stream (if audio or video) */
	guint32 ssrc;							/* Internal SSRC of this stream */
	gint64 pli_latest;						/* Time of latest sent PLI (to avoid flooding) */
	gboolean opusfec;						/* Whether this stream is sending inband Opus FEC */
	gboolean simulcast, svc;				/* Whether this stream uses simulcast or VP9 SVC */
	uint32_t vssrc[3];						/* Only needed in case VP8 (or H.264) simulcasting is involved */
	char *rid[3];							/* Only needed if simulcasting is rid-based */
	int rid_extmap_id;						/* rid extmap ID */
	int framemarking_ext_id;				/* Frame marking extmap ID */
	/* RTP extensions, if negotiated */
	guint8 audio_level_extmap_id;			/* Audio level extmap ID */
	guint8 video_orient_extmap_id;			/* Video orientation extmap ID */
	guint8 playout_delay_extmap_id;			/* Playout delay extmap ID */
	janus_sdp_mdirection audio_level_mdir, video_orient_mdir, playout_delay_mdir;
	/* Audio level processing, if enabled */
	int audio_dBov_level;					/* Value in dBov of the audio level (last value from extension) */
	int audio_active_packets;				/* Participant's number of audio packets to accumulate */
	int audio_dBov_sum;						/* Participant's accumulated dBov value for audio level */
	gboolean talking;						/* Whether this participant is currently talking (uses audio levels extension) */
	/* Recording related stuff, if enabled */
	janus_recorder *rc;
	janus_rtp_switching_context rec_ctx;
	janus_rtp_simulcasting_context rec_simctx;
	/* RTP (or data) forwarders for this stream, if any */
	GHashTable *rtp_forwarders;
	janus_mutex rtp_forwarders_mutex;
	/* Subscriptions to this publisher stream (who's receiving it)  */
	GSList *subscribers;
	janus_mutex subscribers_mutex;
	volatile gint destroyed;
	janus_refcount ref;
} janus_videoroom_publisher_stream;
static janus_videoroom_rtp_forwarder *janus_videoroom_rtp_forwarder_add_helper(janus_videoroom_publisher *p,
	janus_videoroom_publisher_stream *stream,
	const gchar *host, int port, int rtcp_port, int pt, uint32_t ssrc,
	gboolean simulcast, int srtp_suite, const char *srtp_crypto,
	int substream, gboolean is_video, gboolean is_data);
static json_t *janus_videoroom_rtp_forwarder_summary(janus_videoroom_rtp_forwarder *f);

typedef struct janus_videoroom_subscriber {
	janus_videoroom_session *session;
	janus_videoroom *room;		/* Room */
	guint64 room_id;			/* Unique room ID */
	GList *streams;				/* List of media stream subscriptions originated by this subscriber (audio, video and/or data) */
	GHashTable *streams_byid;	/* As above, indexed by mindex */
	GHashTable *streams_bymid;	/* As above, indexed by mid */
	janus_mutex streams_mutex;
	gboolean close_pc;			/* Whether we should automatically close the PeerConnection when the last stream goes away */
	guint32 pvt_id;				/* Private ID of the participant that is subscribing (if available/provided) */
	gboolean paused;
	gboolean kicked;			/* Whether this subscription belongs to a participant that has been kicked */
	volatile gint answered, pending_offer, pending_restart;
	volatile gint destroyed;
	janus_refcount ref;
} janus_videoroom_subscriber;
/* Each VideoRoom subscriber can be subscribed to multiple streams, belonging to
 * the same or different publishers: as such, each stream is its own structure */
typedef struct janus_videoroom_subscriber_stream {
	janus_videoroom_subscriber *subscriber;			/* Subscriber instance this stream belongs to */
	GSList *publisher_streams;						/* Complete list of publisher streams (e.g., when this is data) */
	int mindex;				/* The media index of this stream (may not be the same as the publisher stream) */
	char *mid;				/* The mid of this stream (may not be the same as the publisher stream) */
	gboolean send;			/* Whether this stream media must be sent to this subscriber */
	/* The following properties are copied from the source, in case this stream becomes inactive */
	janus_videoroom_media type;			/* Type of this stream (audio, video or data) */
	janus_audiocodec acodec;			/* Audio codec this publisher is using (if audio) */
	janus_videocodec vcodec;			/* Video codec this publisher is using (if video) */
	int pt;								/* Payload type of this stream (if audio or video) */
	gboolean opusfec;					/* Whether this stream is using inband Opus FEC */
	guint8 audio_level_extmap_id;		/* Audio level extmap ID */
	guint8 video_orient_extmap_id;		/* Video orientation extmap ID */
	guint8 playout_delay_extmap_id;		/* Playout delay extmap ID */
	/* RTP and simulcasting contexts */
	janus_rtp_switching_context context;
	janus_rtp_simulcasting_context sim_context;
	janus_vp8_simulcast_context vp8_context;
	/* The following are only relevant if we're doing VP9 SVC, and are not to be confused with plain
	 * simulcast, which has similar info (substream/templayer) but in a completely different context */
	int spatial_layer, target_spatial_layer;
	int temporal_layer, target_temporal_layer;
	volatile gint ready, destroyed;
	janus_refcount ref;
} janus_videoroom_subscriber_stream;

typedef struct janus_videoroom_rtp_relay_packet {
	janus_videoroom_publisher_stream *source;
	janus_rtp_header *data;
	gint length;
	gboolean is_video;
	uint32_t ssrc[3];
	uint32_t timestamp;
	uint16_t seq_number;
	/* The following are only relevant if we're doing VP9 SVC*/
	gboolean svc;
	int spatial_layer;
	int temporal_layer;
	uint8_t pbit, dbit, ubit, bbit, ebit;
} janus_videoroom_rtp_relay_packet;

typedef struct janus_videoroom_data_relay_packet {
	janus_videoroom_publisher_stream *source;
	char *text;
} janus_videoroom_data_relay_packet;


/* Freeing stuff */
static void janus_videoroom_subscriber_stream_destroy(janus_videoroom_subscriber_stream *s) {
	if(s && g_atomic_int_compare_and_exchange(&s->destroyed, 0, 1))
		janus_refcount_decrease(&s->ref);
	/* TODO Should unref the subscriber instance? */
}

static void janus_videoroom_subscriber_stream_unref(janus_videoroom_subscriber_stream *s) {
	/* Decrease the counter */
	if(s)
		janus_refcount_decrease(&s->ref);
}

static void janus_videoroom_subscriber_stream_free(const janus_refcount *s_ref) {
	janus_videoroom_subscriber_stream *s = janus_refcount_containerof(s_ref, janus_videoroom_subscriber_stream, ref);
	/* This subscriber stream can be destroyed, free all the resources */
		/* TODO Anything else we should free? */
	g_free(s->mid);
	g_free(s);
}

static void janus_videoroom_subscriber_destroy(janus_videoroom_subscriber *s) {
	if(s && g_atomic_int_compare_and_exchange(&s->destroyed, 0, 1))
		janus_refcount_decrease(&s->ref);
}

static void janus_videoroom_subscriber_free(const janus_refcount *s_ref) {
	janus_videoroom_subscriber *s = janus_refcount_containerof(s_ref, janus_videoroom_subscriber, ref);
	/* This subscriber can be destroyed, free all the resources */
	/* TODO Get rid of all the streams */
	g_list_free_full(s->streams, (GDestroyNotify)(janus_videoroom_subscriber_stream_destroy));
	g_hash_table_unref(s->streams_byid);
	g_hash_table_unref(s->streams_bymid);
		/* TODO Unref the publisher stream? */

	g_free(s);
}

static void janus_videoroom_publisher_stream_destroy(janus_videoroom_publisher_stream *ps) {
	if(ps && g_atomic_int_compare_and_exchange(&ps->destroyed, 0, 1)) {
		if(ps->publisher)
			janus_refcount_decrease(&ps->publisher->ref);
		ps->publisher = NULL;
		janus_refcount_decrease(&ps->ref);
	}
	/* TODO Should unref the publisher instance? */
}

static void janus_videoroom_publisher_stream_unref(janus_videoroom_publisher_stream *ps) {
	/* Decrease the counter */
	if(ps)
		janus_refcount_decrease(&ps->ref);
}

static void janus_videoroom_publisher_stream_free(const janus_refcount *ps_ref) {
	janus_videoroom_publisher_stream *ps = janus_refcount_containerof(ps_ref, janus_videoroom_publisher_stream, ref);
	/* This publisher stream can be destroyed, free all the resources */
		/* TODO Anything else we should free? */
	g_free(ps->mid);
	g_free(ps->description);
	janus_recorder_destroy(ps->rc);
	g_hash_table_destroy(ps->rtp_forwarders);
	ps->rtp_forwarders = NULL;
	janus_mutex_destroy(&ps->rtp_forwarders_mutex);
	g_slist_free(ps->subscribers);
	janus_mutex_destroy(&ps->subscribers_mutex);
	int i=0;
	for(i=0; i<3; i++) {
		g_free(ps->rid[i]);
		ps->rid[i] = NULL;
	}
	g_free(ps);
}

static void janus_videoroom_publisher_dereference(janus_videoroom_publisher *p) {
	/* This is used by g_pointer_clear and g_hash_table_new_full so that NULL is only possible if that was inserted into the hash table. */
	janus_refcount_decrease(&p->ref);
}

static void janus_videoroom_publisher_dereference_nodebug(janus_videoroom_publisher *p) {
	janus_refcount_decrease_nodebug(&p->ref);
}

static void janus_videoroom_publisher_destroy(janus_videoroom_publisher *p) {
	if(p && g_atomic_int_compare_and_exchange(&p->destroyed, 0, 1))
		janus_refcount_decrease(&p->ref);
}

static void janus_videoroom_publisher_free(const janus_refcount *p_ref) {
	janus_videoroom_publisher *p = janus_refcount_containerof(p_ref, janus_videoroom_publisher, ref);
	g_free(p->display);
	p->display = NULL;
	g_free(p->recording_base);
	p->recording_base = NULL;
	/* Get rid of all the streams */
	g_list_free_full(p->streams, (GDestroyNotify)(janus_videoroom_publisher_stream_destroy));
	g_hash_table_unref(p->streams_byid);
	g_hash_table_unref(p->streams_bymid);

	if(p->udp_sock > 0)
		close(p->udp_sock);
	g_hash_table_destroy(p->rtp_forwarders);
	janus_mutex_destroy(&p->rtp_forwarders_mutex);
	g_hash_table_destroy(p->srtp_contexts);
	p->srtp_contexts = NULL;

	g_slist_free(p->subscriptions);
	janus_mutex_destroy(&p->subscribers_mutex);
	g_free(p);
}

static void janus_videoroom_session_destroy(janus_videoroom_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void janus_videoroom_session_free(const janus_refcount *session_ref) {
	janus_videoroom_session *session = janus_refcount_containerof(session_ref, janus_videoroom_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	janus_mutex_destroy(&session->mutex);
	g_free(session);
}

static void janus_videoroom_room_dereference(janus_videoroom *room) {
	janus_refcount_decrease(&room->ref);
}

static void janus_videoroom_room_destroy(janus_videoroom *room) {
	if(room && g_atomic_int_compare_and_exchange(&room->destroyed, 0, 1))
		janus_refcount_decrease(&room->ref);
}

static void janus_videoroom_room_free(const janus_refcount *room_ref) {
	janus_videoroom *room = janus_refcount_containerof(room_ref, janus_videoroom, ref);
	/* This room can be destroyed, free all the resources */
	g_free(room->room_name);
	g_free(room->room_secret);
	g_free(room->room_pin);
	g_free(room->rec_dir);
	g_hash_table_destroy(room->participants);
	g_hash_table_destroy(room->private_ids);
	g_hash_table_destroy(room->allowed);
	g_free(room);
}

static void janus_videoroom_message_free(janus_videoroom_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_videoroom_session *session = (janus_videoroom_session *)msg->handle->plugin_handle;
		janus_refcount_decrease(&session->ref);
	}
	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if(msg->message)
		json_decref(msg->message);
	msg->message = NULL;
	if(msg->jsep)
		json_decref(msg->jsep);
	msg->jsep = NULL;

	g_free(msg);
}

static void janus_videoroom_codecstr(janus_videoroom *videoroom, char *audio_codecs, char *video_codecs, int str_len, const char *split) {
	if (audio_codecs) {
		audio_codecs[0] = 0;
		g_snprintf(audio_codecs, str_len, "%s", janus_audiocodec_name(videoroom->acodec[0]));
		if (videoroom->acodec[1] != JANUS_AUDIOCODEC_NONE) {
			g_strlcat(audio_codecs, split, str_len);
			g_strlcat(audio_codecs, janus_audiocodec_name(videoroom->acodec[1]), str_len);
		}
		if (videoroom->acodec[2] != JANUS_AUDIOCODEC_NONE) {
			g_strlcat(audio_codecs, split, str_len);
			g_strlcat(audio_codecs, janus_audiocodec_name(videoroom->acodec[2]), str_len);
		}
	}
	if (video_codecs) {
		video_codecs[0] = 0;
		g_snprintf(video_codecs, str_len, "%s", janus_videocodec_name(videoroom->vcodec[0]));
		if (videoroom->vcodec[1] != JANUS_VIDEOCODEC_NONE) {
			g_strlcat(video_codecs, split, str_len);
			g_strlcat(video_codecs, janus_videocodec_name(videoroom->vcodec[1]), str_len);
		}
		if (videoroom->vcodec[2] != JANUS_VIDEOCODEC_NONE) {
			g_strlcat(video_codecs, split, str_len);
			g_strlcat(video_codecs, janus_videocodec_name(videoroom->vcodec[2]), str_len);
		}
	}
}

static void janus_videoroom_reqpli(janus_videoroom_publisher_stream *ps, const char *reason) {
	/* Send a PLI */
	char buf[12];
	janus_rtcp_pli((char *)&buf, 12);
	JANUS_LOG(LOG_VERB, "%s sending PLI to %"SCNu64" (%s)\n", reason,
		ps->publisher->user_id, ps->publisher->display ? ps->publisher->display : "??");
	gateway->relay_rtcp(ps->publisher->session->handle, ps->mindex, TRUE, buf, 12);
	/* Update the time of when we last sent a keyframe request */
	ps->pli_latest = janus_get_monotonic_time();
}

/* Error codes */
#define JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR		499
#define JANUS_VIDEOROOM_ERROR_NO_MESSAGE		421
#define JANUS_VIDEOROOM_ERROR_INVALID_JSON		422
#define JANUS_VIDEOROOM_ERROR_INVALID_REQUEST	423
#define JANUS_VIDEOROOM_ERROR_JOIN_FIRST		424
#define JANUS_VIDEOROOM_ERROR_ALREADY_JOINED	425
#define JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM		426
#define JANUS_VIDEOROOM_ERROR_ROOM_EXISTS		427
#define JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED		428
#define JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT	429
#define JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT	430
#define JANUS_VIDEOROOM_ERROR_INVALID_SDP_TYPE	431
#define JANUS_VIDEOROOM_ERROR_PUBLISHERS_FULL	432
#define JANUS_VIDEOROOM_ERROR_UNAUTHORIZED		433
#define JANUS_VIDEOROOM_ERROR_ALREADY_PUBLISHED	434
#define JANUS_VIDEOROOM_ERROR_NOT_PUBLISHED		435
#define JANUS_VIDEOROOM_ERROR_ID_EXISTS			436
#define JANUS_VIDEOROOM_ERROR_INVALID_SDP		437


/* RTP forwarder helpers */
static janus_videoroom_rtp_forwarder *janus_videoroom_rtp_forwarder_add_helper(janus_videoroom_publisher *p,
		janus_videoroom_publisher_stream *stream,
		const gchar *host, int port, int rtcp_port, int pt, uint32_t ssrc,
		gboolean simulcast, int srtp_suite, const char *srtp_crypto,
		int substream, gboolean is_video, gboolean is_data) {
	if(!p || !stream || !host) {
		return NULL;
	}
	janus_mutex_lock(&stream->rtp_forwarders_mutex);
	/* Do we need to bind to a port for RTCP? */
	int fd = -1;
	uint16_t local_rtcp_port = 0;
	if(!is_data && rtcp_port > -1) {
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(fd < 0) {
			JANUS_LOG(LOG_ERR, "Error creating RTCP socket for new RTP forwarder... %d (%s)\n",
				errno, strerror(errno));
			return NULL;
		}
		struct sockaddr_in address;
		socklen_t len = sizeof(address);
		memset(&address, 0, sizeof(address));
		address.sin_family = AF_INET;
		address.sin_port = htons(0);	/* The RTCP port we received is the remote one */
		address.sin_addr.s_addr = INADDR_ANY;
		if(bind(fd, (struct sockaddr *)&address, sizeof(struct sockaddr)) < 0 ||
				getsockname(fd, (struct sockaddr *)&address, &len) < 0) {
			JANUS_LOG(LOG_ERR, "Error binding RTCP socket for new RTP forwarder... %d (%s)\n",
				errno, strerror(errno));
			close(fd);
			return NULL;
		}
		local_rtcp_port = ntohs(address.sin_port);
		JANUS_LOG(LOG_VERB, "Bound local %s RTCP port: %"SCNu16"\n",
			is_video ? "video" : "audio", local_rtcp_port);
	}
	janus_videoroom_rtp_forwarder *forward = g_malloc0(sizeof(janus_videoroom_rtp_forwarder));
	forward->source = stream;
	forward->rtcp_fd = fd;
	forward->local_rtcp_port = local_rtcp_port;
	forward->remote_rtcp_port = rtcp_port;
	/* First of all, let's check if we need to setup an SRTP forwarder */
	if(!is_data && srtp_suite > 0 && srtp_crypto != NULL) {
		/* First of all, let's check if there's already an RTP forwarder with
		 * the same SRTP context: make sure SSRC and pt are the same too */
		char media[10] = {0};
		if(!is_video) {
			g_sprintf(media, "audio");
		} else if(is_video) {
			g_sprintf(media, "video%d", substream);
		}
		char srtp_id[256] = {0};
		g_snprintf(srtp_id, 255, "%s-%s-%"SCNu32"-%d", srtp_crypto, media, ssrc, pt);
		JANUS_LOG(LOG_VERB, "SRTP context ID: %s\n", srtp_id);
		janus_videoroom_srtp_context *srtp_ctx = g_hash_table_lookup(p->srtp_contexts, srtp_id);
		if(srtp_ctx != NULL) {
			JANUS_LOG(LOG_VERB, "  -- Reusing existing SRTP context\n");
			srtp_ctx->count++;
			forward->srtp_ctx = srtp_ctx;
		} else {
			/* Nope, base64 decode the crypto string and set it as a new SRTP context */
			JANUS_LOG(LOG_VERB, "  -- Creating new SRTP context\n");
			srtp_ctx = g_malloc0(sizeof(janus_videoroom_srtp_context));
			gsize len = 0;
			guchar *decoded = g_base64_decode(srtp_crypto, &len);
			if(len < SRTP_MASTER_LENGTH) {
				janus_mutex_unlock(&stream->rtp_forwarders_mutex);
				JANUS_LOG(LOG_ERR, "Invalid SRTP crypto (%s)\n", srtp_crypto);
				g_free(decoded);
				g_free(srtp_ctx);
				if(forward->rtcp_fd > -1)
					close(forward->rtcp_fd);
				g_free(forward);
				return NULL;
			}
			/* Set SRTP policy */
			srtp_policy_t *policy = &srtp_ctx->policy;
			srtp_crypto_policy_set_rtp_default(&(policy->rtp));
			if(srtp_suite == 32) {
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(policy->rtp));
			} else if(srtp_suite == 80) {
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtp));
			}
			policy->ssrc.type = ssrc_any_inbound;
			policy->key = decoded;
			policy->next = NULL;
			/* Create SRTP context */
			srtp_err_status_t res = srtp_create(&srtp_ctx->ctx, policy);
			if(res != srtp_err_status_ok) {
				/* Something went wrong... */
				janus_mutex_unlock(&stream->rtp_forwarders_mutex);
				JANUS_LOG(LOG_ERR, "Error creating forwarder SRTP session: %d (%s)\n", res, janus_srtp_error_str(res));
				g_free(decoded);
				policy->key = NULL;
				g_free(srtp_ctx);
				if(forward->rtcp_fd > -1)
					close(forward->rtcp_fd);
				g_free(forward);
				return NULL;
			}
			srtp_ctx->contexts = p->srtp_contexts;
			srtp_ctx->id = g_strdup(srtp_id);
			srtp_ctx->count = 1;
			g_hash_table_insert(p->srtp_contexts, srtp_ctx->id, srtp_ctx);
			forward->srtp_ctx = srtp_ctx;
		}
		forward->is_srtp = TRUE;
	}
	forward->is_video = is_video;
	forward->payload_type = pt;
	forward->ssrc = ssrc;
	forward->substream = substream;
	forward->is_data = is_data;
	forward->serv_addr.sin_family = AF_INET;
	inet_pton(AF_INET, host, &(forward->serv_addr.sin_addr));
	forward->serv_addr.sin_port = htons(port);
	if(is_video && simulcast) {
		forward->simulcast = TRUE;
		janus_rtp_switching_context_reset(&forward->context);
		janus_rtp_simulcasting_context_reset(&forward->sim_context);
		forward->sim_context.rid_ext_id = stream->rid_extmap_id;
		forward->sim_context.substream_target = 2;
		forward->sim_context.templayer_target = 2;
	}
	janus_refcount_init(&forward->ref, janus_videoroom_rtp_forwarder_free);
	guint32 stream_id = janus_random_uint32();
	while(g_hash_table_lookup(stream->publisher->rtp_forwarders, GUINT_TO_POINTER(stream_id)) != NULL &&
			g_hash_table_lookup(stream->rtp_forwarders, GUINT_TO_POINTER(stream_id)) != NULL) {
		stream_id = janus_random_uint32();
	}
	forward->stream_id = stream_id;
	g_hash_table_insert(stream->rtp_forwarders, GUINT_TO_POINTER(stream_id), forward);
	g_hash_table_insert(stream->publisher->rtp_forwarders, GUINT_TO_POINTER(stream_id), GUINT_TO_POINTER(stream_id));
	if(fd > -1) {
		/* We need RTCP: track this file descriptor, and ref the forwarder */
		janus_refcount_increase(&forward->ref);
		forward->rtcp_recv = g_source_new(&janus_videoroom_rtp_forwarder_rtcp_funcs, sizeof(janus_videoroom_rtcp_receiver));
		janus_videoroom_rtcp_receiver *rr = (janus_videoroom_rtcp_receiver *)forward->rtcp_recv;
		rr->forward = forward;
		g_source_set_priority(forward->rtcp_recv, G_PRIORITY_DEFAULT);
		g_source_add_unix_fd(forward->rtcp_recv, fd, G_IO_IN | G_IO_ERR);
		g_source_attach((GSource *)forward->rtcp_recv, rtcpfwd_ctx);
		/* Send a couple of empty RTP packets to the remote port to do latching */
		struct sockaddr_in address;
		socklen_t addrlen = sizeof(address);
		memset(&address, 0, addrlen);
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = forward->serv_addr.sin_addr.s_addr;
		address.sin_port = htons(forward->remote_rtcp_port);
		janus_rtp_header rtp;
		memset(&rtp, 0, sizeof(rtp));
		rtp.version = 2;
		(void)sendto(fd, &rtp, 12, 0, (struct sockaddr *)&address, addrlen);
		(void)sendto(fd, &rtp, 12, 0, (struct sockaddr *)&address, addrlen);
	}
	janus_mutex_unlock(&stream->rtp_forwarders_mutex);
	JANUS_LOG(LOG_VERB, "Added %s/%d rtp_forward to participant %"SCNu64" host: %s:%d stream_id: %"SCNu32"\n",
		is_data ? "data" : (is_video ? "video" : "audio"), substream, p->user_id, host, port, stream_id);
	return forward;
}

static json_t *janus_videoroom_rtp_forwarder_summary(janus_videoroom_rtp_forwarder *f) {
	if(f == NULL)
		return NULL;
	json_t *json = json_object();
	json_object_set_new(json, "stream_id", json_integer(f->stream_id));
	json_object_set_new(json, "ip", json_string(inet_ntoa(f->serv_addr.sin_addr)));
	json_object_set_new(json, "port", json_integer(ntohs(f->serv_addr.sin_port)));
	if(f->is_data) {
		json_object_set_new(json, "type", json_string("data"));
	} else if(f->is_video) {
		json_object_set_new(json, "type", json_string("video"));
		if(f->local_rtcp_port > 0)
			json_object_set_new(json, "local_rtcp_port", json_integer(f->local_rtcp_port));
		if(f->remote_rtcp_port > 0)
			json_object_set_new(json, "remote_rtcp_port", json_integer(f->remote_rtcp_port));
		if(f->payload_type)
			json_object_set_new(json, "pt", json_integer(f->payload_type));
		if(f->ssrc)
			json_object_set_new(json, "ssrc", json_integer(f->ssrc));
		if(f->substream)
			json_object_set_new(json, "substream", json_integer(f->substream));
	} else {
		json_object_set_new(json, "type", json_string("audio"));
		if(f->local_rtcp_port > 0)
			json_object_set_new(json, "local_rtcp_port", json_integer(f->local_rtcp_port));
		if(f->remote_rtcp_port > 0)
			json_object_set_new(json, "remote_rtcp_port", json_integer(f->remote_rtcp_port));
		if(f->payload_type)
			json_object_set_new(json, "pt", json_integer(f->payload_type));
		if(f->ssrc)
			json_object_set_new(json, "ssrc", json_integer(f->ssrc));
	}
	if(f->is_srtp)
		json_object_set_new(json, "srtp", json_true());
	return json;
}

static void janus_videoroom_rtp_forwarder_destroy(janus_videoroom_rtp_forwarder *forward) {
	if(forward && g_atomic_int_compare_and_exchange(&forward->destroyed, 0, 1)) {
		if(forward->rtcp_fd > -1) {
			g_source_destroy(forward->rtcp_recv);
			g_source_unref(forward->rtcp_recv);
		}
		janus_refcount_decrease(&forward->ref);
	}
}
static void janus_videoroom_rtp_forwarder_free(const janus_refcount *f_ref) {
	janus_videoroom_rtp_forwarder *forward = janus_refcount_containerof(f_ref, janus_videoroom_rtp_forwarder, ref);
	if(forward->rtcp_fd > -1)
		close(forward->rtcp_fd);
	if(forward->is_srtp && forward->srtp_ctx) {
		forward->srtp_ctx->count--;
		if(forward->srtp_ctx->count == 0 && forward->srtp_ctx->contexts != NULL)
			g_hash_table_remove(forward->srtp_ctx->contexts, forward->srtp_ctx->id);
	}
	g_free(forward);
	forward = NULL;
}

static void janus_videoroom_srtp_context_free(gpointer data) {
	if(data) {
		janus_videoroom_srtp_context *srtp_ctx = (janus_videoroom_srtp_context *)data;
		if(srtp_ctx) {
			g_free(srtp_ctx->id);
			srtp_dealloc(srtp_ctx->ctx);
			g_free(srtp_ctx->policy.key);
			g_free(srtp_ctx);
			srtp_ctx = NULL;
		}
	}
}


/* Helpers for subscription streams */
static janus_videoroom_subscriber_stream *janus_videoroom_subscriber_stream_add(janus_videoroom_subscriber *subscriber,
		janus_videoroom_publisher_stream *ps,
		gboolean legacy, gboolean do_audio, gboolean do_video, gboolean do_data) {
	/* If this is a legacy subscription ("feed"), use the deprecated properties */
	if(legacy && ((ps->type == JANUS_VIDEOROOM_MEDIA_AUDIO && !do_audio) ||
			(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO && !do_video) ||
			(ps->type == JANUS_VIDEOROOM_MEDIA_DATA && !do_data))) {
		/* Skip this */
		JANUS_LOG(LOG_WARN, "Skipping %s stream (legacy subscription)\n", janus_videoroom_media_str(ps->type));
		return NULL;
	}
	/* Allocate a new subscriber stream instance */
	janus_videoroom_subscriber_stream *stream = g_malloc0(sizeof(janus_videoroom_subscriber_stream));
	stream->mindex = g_list_length(subscriber->streams);
	stream->subscriber = subscriber;
	stream->publisher_streams = g_slist_append(stream->publisher_streams, ps);
	/* Copy properties from the source */
	stream->type = ps->type;
	stream->acodec = ps->acodec;
	stream->vcodec = ps->vcodec;
	stream->pt = ps->pt;
	stream->opusfec = ps->opusfec;
	char mid[5];
	g_snprintf(mid, sizeof(mid), "%d", stream->mindex);
	stream->mid = g_strdup(mid);
	subscriber->streams = g_list_append(subscriber->streams, stream);
	g_hash_table_insert(subscriber->streams_byid, GINT_TO_POINTER(stream->mindex), stream);
	g_hash_table_insert(subscriber->streams_bymid, g_strdup(stream->mid), stream);
	/* Initialize the stream */
	janus_rtp_switching_context_reset(&stream->context);
	stream->send = TRUE;
	g_atomic_int_set(&stream->destroyed, 0);
	janus_refcount_init(&stream->ref, janus_videoroom_subscriber_stream_free);
	janus_refcount_increase(&stream->ref);	/* This is for the mid-indexed hashtable */
	janus_rtp_simulcasting_context_reset(&stream->sim_context);
	stream->sim_context.rid_ext_id = ps->rid_extmap_id;
	stream->sim_context.substream_target = 2;
	stream->sim_context.templayer_target = 2;
	janus_vp8_simulcast_context_reset(&stream->vp8_context);
	/* This stream may belong to a room where VP9 SVC has been enabled,
	 * let's assume we're interested in all layers for the time being */
	stream->spatial_layer = -1;
	stream->target_spatial_layer = 1;		/* FIXME Chrome sends 0 and 1 */
	stream->temporal_layer = -1;
	stream->target_temporal_layer = 2;	/* FIXME Chrome sends 0, 1 and 2 */
	janus_mutex_lock(&ps->subscribers_mutex);
	ps->subscribers = g_slist_append(ps->subscribers, stream);
	/* The two streams reference each other */
	janus_refcount_increase(&stream->ref);
	janus_refcount_increase(&ps->ref);
	janus_mutex_unlock(&ps->subscribers_mutex);
	return stream;
}

static janus_videoroom_subscriber_stream *janus_videoroom_subscriber_stream_add_or_replace(janus_videoroom_subscriber *subscriber,
		janus_videoroom_publisher_stream *ps) {
	if(subscriber == NULL || ps == NULL)
		return NULL;
	/* First of all, let's check if there's an m-line we can reuse */
	gboolean found = FALSE;
	janus_videoroom_subscriber_stream *stream = NULL;
	GList *temp = subscriber->streams;
	while(temp) {
		stream = (janus_videoroom_subscriber_stream *)temp->data;
		janus_videoroom_publisher_stream *stream_ps = stream->publisher_streams ? stream->publisher_streams->data : NULL;
		if(stream_ps != NULL && stream_ps->type == ps->type && stream->type == JANUS_VIDEOROOM_MEDIA_DATA) {
			/* We already have a datachannel m-line, no need for others: just update the subscribers list */
			janus_mutex_lock(&ps->subscribers_mutex);
			if(g_slist_find(ps->subscribers, stream) == NULL && g_slist_find(stream->publisher_streams, ps) == NULL) {
				ps->subscribers = g_slist_append(ps->subscribers, stream);
				stream->publisher_streams = g_slist_append(stream->publisher_streams, ps);
				/* The two streams reference each other */
				janus_refcount_increase(&stream->ref);
				janus_refcount_increase(&ps->ref);
			}
			janus_mutex_unlock(&ps->subscribers_mutex);
			return NULL;
		}
		if(stream_ps == NULL && stream->type == ps->type) {
			/* There's an empty m-line of the right type, check if codecs match */
			if(stream->type == JANUS_VIDEOROOM_MEDIA_DATA ||
					(stream->type == JANUS_VIDEOROOM_MEDIA_AUDIO && stream->acodec == ps->acodec) ||
					(stream->type == JANUS_VIDEOROOM_MEDIA_VIDEO && stream->vcodec == ps->vcodec)) {
				found = TRUE;
				JANUS_LOG(LOG_VERB, "Reusing m-line %d for this subscription\n", stream->mindex);
				stream->opusfec = ps->opusfec;
				janus_rtp_simulcasting_context_reset(&stream->sim_context);
				if(ps->simulcast) {
					stream->sim_context.rid_ext_id = ps->rid_extmap_id;
					stream->sim_context.substream_target = 2;
					stream->sim_context.templayer_target = 2;
				}
				janus_vp8_simulcast_context_reset(&stream->vp8_context);
				if(ps->svc) {
					/* This stream belongs to a room where VP9 SVC has been enabled,
					 * let's assume we're interested in all layers for the time being */
					stream->spatial_layer = -1;
					stream->target_spatial_layer = 1;		/* FIXME Chrome sends 0 and 1 */
					stream->temporal_layer = -1;
					stream->target_temporal_layer = 2;	/* FIXME Chrome sends 0, 1 and 2 */
				}
				janus_mutex_lock(&ps->subscribers_mutex);
				if(g_slist_find(ps->subscribers, stream) == NULL && g_slist_find(stream->publisher_streams, ps) == NULL) {
					ps->subscribers = g_slist_append(ps->subscribers, stream);
					stream->publisher_streams = g_slist_append(stream->publisher_streams, ps);
					/* The two streams reference each other */
					janus_refcount_increase(&stream->ref);
					janus_refcount_increase(&ps->ref);
				}
				janus_mutex_unlock(&ps->subscribers_mutex);
				break;
			}
		}
		temp = temp->next;
	}
	if(found)
		return stream;
	/* We couldn't find any, add a new one */
	return janus_videoroom_subscriber_stream_add(subscriber, ps, FALSE, FALSE, FALSE, FALSE);
}

static void janus_videoroom_subscriber_stream_remove(janus_videoroom_subscriber_stream *s,
		janus_videoroom_publisher_stream *ps, gboolean lock_ps) {
	janus_videoroom_subscriber *subscriber = s->subscriber;
	if(subscriber && subscriber->pvt_id > 0 && subscriber->room != NULL) {
		janus_mutex_lock(&subscriber->room->mutex);
		janus_videoroom_publisher *owner = g_hash_table_lookup(subscriber->room->private_ids, GUINT_TO_POINTER(subscriber->pvt_id));
		if(owner != NULL) {
			janus_mutex_lock(&owner->subscribers_mutex);
			/* Note: we should refcount these subscription-publisher mappings as well */
			owner->subscriptions = g_slist_remove(owner->subscriptions, s);
			janus_mutex_unlock(&owner->subscribers_mutex);
		}
		janus_mutex_unlock(&subscriber->room->mutex);
		//~ if(subscriber->room)
			//~ g_clear_pointer(&subscriber->room, janus_videoroom_room_dereference);
		//~ /* If the subscriber itself has no more active active subscriptions, should we close it? */
		//~ if(subscriber->streams == NULL && subscriber->session && subscriber->close_pc)
			//~ gateway->close_pc(subscriber->session->handle);
	}
	g_atomic_int_set(&s->ready, 0);
	if(ps != NULL) {
		/* Unsubscribe from this stream in particular (datachannels can have multiple sources) */
		if(g_slist_find(s->publisher_streams, ps) != NULL) {
			/* Remove the subscription from the list of recipients */
			s->publisher_streams = g_slist_remove(s->publisher_streams, ps);
			if(s->publisher_streams == NULL)
				g_atomic_int_set(&s->ready, 0);
			s->opusfec = FALSE;
			if(lock_ps)
				janus_mutex_lock(&ps->subscribers_mutex);
			ps->subscribers = g_slist_remove(ps->subscribers, s);
			if(lock_ps)
				janus_mutex_unlock(&ps->subscribers_mutex);
			/* Unref the two streams, as they're not related anymore */
			janus_refcount_decrease(&ps->ref);
			janus_refcount_decrease(&s->ref);
		}
	} else {
		/* Unsubscribe from all sources (which will be one for audio/video, potentially more for datachannels) */
		while(s->publisher_streams) {
			ps = s->publisher_streams->data;
			s->publisher_streams = g_slist_remove(s->publisher_streams, ps);
			if(ps) {
				/* Remove the subscription from the list of recipients */
				if(s->publisher_streams == NULL)
					g_atomic_int_set(&s->ready, 0);
				s->opusfec = FALSE;
				if(lock_ps)
					janus_mutex_lock(&ps->subscribers_mutex);
				ps->subscribers = g_slist_remove(ps->subscribers, s);
				if(lock_ps)
					janus_mutex_unlock(&ps->subscribers_mutex);
				/* Unref the two streams, as they're not related anymore */
				janus_refcount_decrease(&ps->ref);
				janus_refcount_decrease(&s->ref);
			}
		}
	}
}

static json_t *janus_videoroom_subscriber_streams_summary(janus_videoroom_subscriber *subscriber, gboolean legacy, json_t *event) {
	json_t *media = json_array();
	GList *temp = subscriber->streams;
	while(temp) {
		janus_videoroom_subscriber_stream *stream = (janus_videoroom_subscriber_stream *)temp->data;
		janus_refcount_increase(&stream->ref);
		janus_videoroom_publisher_stream *ps = stream->publisher_streams ? stream->publisher_streams->data : NULL;
		if(ps)
			janus_refcount_increase(&ps->ref);
		json_t *m = json_object();
		json_object_set_new(m, "type", json_string(janus_videoroom_media_str(stream->type)));
		json_object_set_new(m, "active", (ps || stream->type == JANUS_VIDEOROOM_MEDIA_DATA) ? json_true() : json_false());
		json_object_set_new(m, "mindex", json_integer(stream->mindex));
		json_object_set_new(m, "mid", json_string(stream->mid));
		json_object_set_new(m, "ready", g_atomic_int_get(&stream->ready) ? json_true() : json_false());
		json_object_set_new(m, "send", stream->send ? json_true() : json_false());
		if(ps && stream->type == JANUS_VIDEOROOM_MEDIA_DATA) {
			json_object_set_new(m, "sources", json_integer(g_slist_length(stream->publisher_streams)));
		} else if(ps && stream->type != JANUS_VIDEOROOM_MEDIA_DATA) {
			if(ps->publisher) {
				json_object_set_new(m, "feed_id", json_integer(ps->publisher->user_id));
				if(ps->publisher->display)
					json_object_set_new(m, "feed_display", json_string(ps->publisher->display));
				/* If this is a legacy subscription, put the info in the generic part too */
				if(legacy && event) {
					json_object_set_new(event, "id", json_integer(ps->publisher->user_id));
					if(ps->publisher->display)
						json_object_set_new(event, "display", json_string(ps->publisher->display));
				}
			}
			if(ps->mid)
				json_object_set_new(m, "feed_mid", json_string(ps->mid));
			if(ps->description)
				json_object_set_new(m, "feed_description", json_string(ps->description));
			if(ps->simulcast) {
				json_t *simulcast = json_object();
				json_object_set_new(simulcast, "substream", json_integer(stream->sim_context.substream));
				json_object_set_new(simulcast, "substream-target", json_integer(stream->sim_context.substream_target));
				json_object_set_new(simulcast, "temporal-layer", json_integer(stream->sim_context.templayer));
				json_object_set_new(simulcast, "temporal-layer-target", json_integer(stream->sim_context.templayer_target));
				json_object_set_new(m, "simulcast", simulcast);
			}
			if(ps->svc) {
				json_t *svc = json_object();
				json_object_set_new(svc, "spatial-layer", json_integer(stream->spatial_layer));
				json_object_set_new(svc, "target-spatial-layer", json_integer(stream->target_spatial_layer));
				json_object_set_new(svc, "temporal-layer", json_integer(stream->temporal_layer));
				json_object_set_new(svc, "target-temporal-layer", json_integer(stream->target_temporal_layer));
				json_object_set_new(m, "svc", svc);
			}
		}
		if(ps)
			janus_refcount_decrease(&ps->ref);
		janus_refcount_decrease(&stream->ref);
		json_array_append_new(media, m);
		temp = temp->next;
	}
	return media;
}

/* Helper to generate a new offer with the subscriber streams */
static json_t *janus_videoroom_subscriber_offer(janus_videoroom_subscriber *subscriber) {
	g_atomic_int_set(&subscriber->answered, 0);
	char s_name[100];
	g_snprintf(s_name, sizeof(s_name), "VideoRoom %"SCNu64, subscriber->room->room_id);
	janus_sdp *offer = janus_sdp_generate_offer(s_name, "0.0.0.0",
		JANUS_SDP_OA_DONE);
	GList *temp = subscriber->streams;
	while(temp) {
		janus_videoroom_subscriber_stream *stream = (janus_videoroom_subscriber_stream *)temp->data;
		janus_videoroom_publisher_stream *ps = stream->publisher_streams ? stream->publisher_streams->data : NULL;
		int pt = -1;
		const char *codec = NULL;
		if(stream->type != JANUS_VIDEOROOM_MEDIA_DATA) {
			pt = stream->pt;
			codec = (stream->type == JANUS_VIDEOROOM_MEDIA_AUDIO ?
				janus_audiocodec_name(stream->acodec) : janus_videocodec_name(stream->vcodec));
		}
		janus_sdp_generate_offer_mline(offer,
			JANUS_SDP_OA_MLINE, janus_videoroom_media_sdptype(stream->type),
			JANUS_SDP_OA_MID, stream->mid,
			JANUS_SDP_OA_PT, pt,
			JANUS_SDP_OA_CODEC, codec,
			JANUS_SDP_OA_FMTP, (stream->type == JANUS_VIDEOROOM_MEDIA_AUDIO && stream->opusfec ? "useinbandfec=1" : NULL),
			JANUS_SDP_OA_DIRECTION, (ps || stream->type == JANUS_VIDEOROOM_MEDIA_DATA) ? JANUS_SDP_SENDONLY : JANUS_SDP_INACTIVE,
			/* TODO Add other properties from original SDP */
			JANUS_SDP_OA_DONE);
		/* Add the extmap attributes, if needed */
		if(ps) {
			janus_sdp_mline *m = janus_sdp_mline_find_by_index(offer, stream->mindex);
			if(ps->type == JANUS_VIDEOROOM_MEDIA_AUDIO && ps->audio_level_extmap_id > 0) {
				if(m != NULL) {
					janus_sdp_attribute *a = janus_sdp_attribute_create("extmap",
						"%d %s\r\n", ps->audio_level_extmap_id, JANUS_RTP_EXTMAP_AUDIO_LEVEL);
					janus_sdp_attribute_add_to_mline(m, a);
				}
			}
			if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO && ps->video_orient_extmap_id > 0) {
				if(m != NULL) {
					janus_sdp_attribute *a = janus_sdp_attribute_create("extmap",
						"%d %s\r\n", ps->video_orient_extmap_id, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION);
					janus_sdp_attribute_add_to_mline(m, a);
				}
			}
			if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO && ps->playout_delay_extmap_id > 0) {
				if(m != NULL) {
					janus_sdp_attribute *a = janus_sdp_attribute_create("extmap",
						"%d %s\r\n", ps->playout_delay_extmap_id, JANUS_RTP_EXTMAP_PLAYOUT_DELAY);
					janus_sdp_attribute_add_to_mline(m, a);
				}
			}
		}
		temp = temp->next;
	}
	/* Update (or set) the SDP version */
	subscriber->session->sdp_version++;
	offer->o_version = subscriber->session->sdp_version;
	char *sdp = janus_sdp_write(offer);
	janus_sdp_destroy(offer);
	json_t *jsep = json_pack("{ssss}", "type", "offer", "sdp", sdp);
	g_free(sdp);
	/* Done */
	return jsep;
}


/* Plugin implementation */
int janus_videoroom_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_VIDEOROOM_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_VIDEOROOM_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_VIDEOROOM_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	config_folder = config_path;
	if(config != NULL)
		janus_config_print(config);

	rooms = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify) janus_videoroom_room_destroy);
	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_videoroom_session_destroy);

	messages = g_async_queue_new_full((GDestroyNotify) janus_videoroom_message_free);

	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	/* Parse configuration to populate the rooms list */
	if(config != NULL) {
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		/* Any admin key to limit who can "create"? */
		janus_config_item *key = janus_config_get(config, config_general, janus_config_type_item, "admin_key");
		if(key != NULL && key->value != NULL)
			admin_key = g_strdup(key->value);
		janus_config_item *lrf = janus_config_get(config, config_general, janus_config_type_item, "lock_rtp_forward");
		if(admin_key && lrf != NULL && lrf->value != NULL)
			lock_rtpfwd = janus_is_true(lrf->value);
		janus_config_item *events = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(events != NULL && events->value != NULL)
			notify_events = janus_is_true(events->value);
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_VIDEOROOM_NAME);
		}
		/* Iterate on all rooms */
		GList *clist = janus_config_get_categories(config, NULL), *cl = clist;
		while(cl != NULL) {
			janus_config_category *cat = (janus_config_category *)cl->data;
			if(cat->name == NULL || !strcasecmp(cat->name, "general")) {
				cl = cl->next;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Adding video room '%s'\n", cat->name);
			janus_config_item *desc = janus_config_get(config, cat, janus_config_type_item, "description");
			janus_config_item *priv = janus_config_get(config, cat, janus_config_type_item, "is_private");
			janus_config_item *secret = janus_config_get(config, cat, janus_config_type_item, "secret");
			janus_config_item *pin = janus_config_get(config, cat, janus_config_type_item, "pin");
			janus_config_item *req_pvtid = janus_config_get(config, cat, janus_config_type_item, "require_pvtid");
			janus_config_item *bitrate = janus_config_get(config, cat, janus_config_type_item, "bitrate");
			janus_config_item *bitrate_cap = janus_config_get(config, cat, janus_config_type_item, "bitrate_cap");
			janus_config_item *maxp = janus_config_get(config, cat, janus_config_type_item, "publishers");
			janus_config_item *plifreq = janus_config_get(config, cat, janus_config_type_item, "pli_freq");
			if(plifreq == NULL)	/* For backwards compatibility, we accept fir_freq as well */
				plifreq = janus_config_get(config, cat, janus_config_type_item, "fir_freq");
			janus_config_item *audiocodec = janus_config_get(config, cat, janus_config_type_item, "audiocodec");
			janus_config_item *videocodec = janus_config_get(config, cat, janus_config_type_item, "videocodec");
			janus_config_item *fec = janus_config_get(config, cat, janus_config_type_item, "opus_fec");
			janus_config_item *svc = janus_config_get(config, cat, janus_config_type_item, "video_svc");
			janus_config_item *audiolevel_ext = janus_config_get(config, cat, janus_config_type_item, "audiolevel_ext");
			janus_config_item *audiolevel_event = janus_config_get(config, cat, janus_config_type_item, "audiolevel_event");
			janus_config_item *audio_active_packets = janus_config_get(config, cat, janus_config_type_item, "audio_active_packets");
			janus_config_item *audio_level_average = janus_config_get(config, cat, janus_config_type_item, "audio_level_average");
			janus_config_item *videoorient_ext = janus_config_get(config, cat, janus_config_type_item, "videoorient_ext");
			janus_config_item *playoutdelay_ext = janus_config_get(config, cat, janus_config_type_item, "playoutdelay_ext");
			janus_config_item *transport_wide_cc_ext = janus_config_get(config, cat, janus_config_type_item, "transport_wide_cc_ext");
			janus_config_item *notify_joining = janus_config_get(config, cat, janus_config_type_item, "notify_joining");
			janus_config_item *record = janus_config_get(config, cat, janus_config_type_item, "record");
			janus_config_item *rec_dir = janus_config_get(config, cat, janus_config_type_item, "rec_dir");
			/* Create the video room */
			janus_videoroom *videoroom = g_malloc0(sizeof(janus_videoroom));
			const char *room_num = cat->name;
			if(strstr(room_num, "room-") == room_num)
				room_num += 5;
			videoroom->room_id = g_ascii_strtoull(room_num, NULL, 0);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL && strlen(desc->value) > 0)
				description = g_strdup(desc->value);
			else
				description = g_strdup(cat->name);
			videoroom->room_name = description;
			if(secret != NULL && secret->value != NULL) {
				videoroom->room_secret = g_strdup(secret->value);
			}
			if(pin != NULL && pin->value != NULL) {
				videoroom->room_pin = g_strdup(pin->value);
			}
			videoroom->is_private = priv && priv->value && janus_is_true(priv->value);
			videoroom->require_pvtid = req_pvtid && req_pvtid->value && janus_is_true(req_pvtid->value);
			videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
			if(maxp != NULL && maxp->value != NULL)
				videoroom->max_publishers = atol(maxp->value);
			if(videoroom->max_publishers < 0)
				videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
			videoroom->bitrate = 0;
			if(bitrate != NULL && bitrate->value != NULL)
				videoroom->bitrate = atol(bitrate->value);
			if(videoroom->bitrate > 0 && videoroom->bitrate < 64000)
				videoroom->bitrate = 64000;	/* Don't go below 64k */
			videoroom->bitrate_cap = bitrate_cap && bitrate_cap->value && janus_is_true(bitrate_cap->value);
			videoroom->pli_freq = 0;
			if(plifreq != NULL && plifreq->value != NULL)
				videoroom->pli_freq = atol(plifreq->value);
			/* By default, we force Opus as the only audio codec */
			videoroom->acodec[0] = JANUS_AUDIOCODEC_OPUS;
			videoroom->acodec[1] = JANUS_AUDIOCODEC_NONE;
			videoroom->acodec[2] = JANUS_AUDIOCODEC_NONE;
			/* Check if we're forcing a different single codec, or allowing more than one */
			if(audiocodec && audiocodec->value) {
				gchar **list = g_strsplit(audiocodec->value, ",", 4);
				gchar *codec = list[0];
				if(codec != NULL) {
					int i=0;
					while(codec != NULL) {
						if(i == 3) {
							JANUS_LOG(LOG_WARN, "Ignoring extra audio codecs: %s\n", codec);
							break;
						}
						if(strlen(codec) > 0)
							videoroom->acodec[i] = janus_audiocodec_from_name(codec);
						i++;
						codec = list[i];
					}
				}
				g_clear_pointer(&list, g_strfreev);
			}
			/* By default, we force VP8 as the only video codec */
			videoroom->vcodec[0] = JANUS_VIDEOCODEC_VP8;
			videoroom->vcodec[1] = JANUS_VIDEOCODEC_NONE;
			videoroom->vcodec[2] = JANUS_VIDEOCODEC_NONE;
			/* Check if we're forcing a different single codec, or allowing more than one */
			if(videocodec && videocodec->value) {
				gchar **list = g_strsplit(videocodec->value, ",", 4);
				gchar *codec = list[0];
				if(codec != NULL) {
					int i=0;
					while(codec != NULL) {
						if(i == 3) {
							JANUS_LOG(LOG_WARN, "Ignoring extra video codecs: %s\n", codec);
							break;
						}
						if(strlen(codec) > 0)
							videoroom->vcodec[i] = janus_videocodec_from_name(codec);
						i++;
						codec = list[i];
					}
				}
				g_clear_pointer(&list, g_strfreev);
			}
			if(fec && fec->value) {
				videoroom->do_opusfec = janus_is_true(fec->value);
				if(videoroom->acodec[0] != JANUS_AUDIOCODEC_OPUS &&
						videoroom->acodec[1] != JANUS_AUDIOCODEC_OPUS &&
						videoroom->acodec[2] != JANUS_AUDIOCODEC_OPUS) {
					videoroom->do_opusfec = FALSE;
					JANUS_LOG(LOG_WARN, "Inband FEC is only supported for rooms that allow Opus: disabling it...\n");
				}
			}
			if(svc && svc->value && janus_is_true(svc->value)) {
				if(videoroom->vcodec[0] == JANUS_VIDEOCODEC_VP9 &&
						videoroom->vcodec[1] == JANUS_VIDEOCODEC_NONE &&
						videoroom->vcodec[2] == JANUS_VIDEOCODEC_NONE) {
					videoroom->do_svc = TRUE;
				} else {
					JANUS_LOG(LOG_WARN, "SVC is only supported, in an experimental way, for VP9 only rooms: disabling it...\n");
				}
			}
			videoroom->audiolevel_ext = TRUE;
			if(audiolevel_ext != NULL && audiolevel_ext->value != NULL)
				videoroom->audiolevel_ext = janus_is_true(audiolevel_ext->value);
			videoroom->audiolevel_event = FALSE;
			if(audiolevel_event != NULL && audiolevel_event->value != NULL)
				videoroom->audiolevel_event = janus_is_true(audiolevel_event->value);
			if(videoroom->audiolevel_event) {
				videoroom->audio_active_packets = 100;
				if(audio_active_packets != NULL && audio_active_packets->value != NULL){
					if(atoi(audio_active_packets->value) > 0) {
						videoroom->audio_active_packets = atoi(audio_active_packets->value);
					} else {
						JANUS_LOG(LOG_WARN, "Invalid audio_active_packets value, using default: %d\n", videoroom->audio_active_packets);
					}
				}
				videoroom->audio_level_average = 25;
				if(audio_level_average != NULL && audio_level_average->value != NULL) {
					if(atoi(audio_level_average->value) > 0) {
						videoroom->audio_level_average = atoi(audio_level_average->value);
					} else {
						JANUS_LOG(LOG_WARN, "Invalid audio_level_average value provided, using default: %d\n", videoroom->audio_level_average);
					}
				}
			}
			videoroom->videoorient_ext = TRUE;
			if(videoorient_ext != NULL && videoorient_ext->value != NULL)
				videoroom->videoorient_ext = janus_is_true(videoorient_ext->value);
			videoroom->playoutdelay_ext = TRUE;
			if(playoutdelay_ext != NULL && playoutdelay_ext->value != NULL)
				videoroom->playoutdelay_ext = janus_is_true(playoutdelay_ext->value);
			videoroom->transport_wide_cc_ext = TRUE;
			if(transport_wide_cc_ext != NULL && transport_wide_cc_ext->value != NULL)
				videoroom->transport_wide_cc_ext = janus_is_true(transport_wide_cc_ext->value);
			if(record && record->value) {
				videoroom->record = janus_is_true(record->value);
			}
			if(rec_dir && rec_dir->value) {
				videoroom->rec_dir = g_strdup(rec_dir->value);
			}
			/* By default, the videoroom plugin does not notify about participants simply joining the room.
			   It only notifies when the participant actually starts publishing media. */
			videoroom->notify_joining = FALSE;
			if(notify_joining != NULL && notify_joining->value != NULL)
				videoroom->notify_joining = janus_is_true(notify_joining->value);
			g_atomic_int_set(&videoroom->destroyed, 0);
			janus_mutex_init(&videoroom->mutex);
			janus_refcount_init(&videoroom->ref, janus_videoroom_room_free);
			videoroom->participants = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, (GDestroyNotify)janus_videoroom_publisher_dereference);
			videoroom->private_ids = g_hash_table_new(NULL, NULL);
			videoroom->check_allowed = FALSE;	/* Static rooms can't have an "allowed" list yet, no hooks to the configuration file */
			videoroom->allowed = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
			janus_mutex_lock(&rooms_mutex);
			g_hash_table_insert(rooms, janus_uint64_dup(videoroom->room_id), videoroom);
			janus_mutex_unlock(&rooms_mutex);
			/* Compute a list of the supported codecs for the summary */
			char audio_codecs[100], video_codecs[100];
			janus_videoroom_codecstr(videoroom, audio_codecs, video_codecs, sizeof(audio_codecs), "|");
			JANUS_LOG(LOG_VERB, "Created videoroom: %"SCNu64" (%s, %s, %s/%s codecs, secret: %s, pin: %s, pvtid: %s)\n",
				videoroom->room_id, videoroom->room_name,
				videoroom->is_private ? "private" : "public",
				audio_codecs, video_codecs,
				videoroom->room_secret ? videoroom->room_secret : "no secret",
				videoroom->room_pin ? videoroom->room_pin : "no pin",
				videoroom->require_pvtid ? "required" : "optional");
			if(videoroom->record) {
				JANUS_LOG(LOG_VERB, "  -- Room is going to be recorded in %s\n", videoroom->rec_dir ? videoroom->rec_dir : "the current folder");
			}
			cl = cl->next;
		}
		/* Done: we keep the configuration file open in case we get a "create" or "destroy" with permanent=true */
	}

	/* Show available rooms */
	janus_mutex_lock(&rooms_mutex);
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, rooms);
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_videoroom *vr = value;
		/* Compute a list of the supported codecs for the summary */
		char audio_codecs[100], video_codecs[100];
		janus_videoroom_codecstr(vr, audio_codecs, video_codecs, sizeof(audio_codecs), "|");
		JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s] %"SCNu32", max %d publishers, PLI frequency of %d seconds, %s audio codec(s), %s video codec(s)\n",
			vr->room_id, vr->room_name, vr->bitrate, vr->max_publishers, vr->pli_freq,
			audio_codecs, video_codecs);
	}
	janus_mutex_unlock(&rooms_mutex);

	/* Thread for handling incoming RTCP packets from RTP forwarders, if any */
	rtcpfwd_ctx = g_main_context_new();
	rtcpfwd_loop = g_main_loop_new(rtcpfwd_ctx, FALSE);
	GError *error = NULL;
	rtcpfwd_thread = g_thread_try_new("videoroom rtcpfwd", janus_videoroom_rtp_forwarder_rtcp_thread, NULL, &error);
	if(error != NULL) {
		/* We show the error but it's not fatal */
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the VideoRoom RTCP thread for RTP forwarders...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
	}

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	error = NULL;
	handler_thread = g_thread_try_new("videoroom handler", janus_videoroom_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the VideoRoom handler thread...\n",
			error->code, error->message ? error->message : "??");
		janus_config_destroy(config);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_VIDEOROOM_NAME);
	return 0;
}

void janus_videoroom_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	if(rtcpfwd_thread != NULL) {
		if(g_main_loop_is_running(rtcpfwd_loop)) {
			g_main_loop_quit(rtcpfwd_loop);
			g_main_context_wakeup(rtcpfwd_ctx);
		}
		g_thread_join(rtcpfwd_thread);
		rtcpfwd_thread = NULL;
	}

	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	sessions = NULL;
	janus_mutex_unlock(&sessions_mutex);

	janus_mutex_lock(&rooms_mutex);
	g_hash_table_destroy(rooms);
	rooms = NULL;
	janus_mutex_unlock(&rooms_mutex);

	g_async_queue_unref(messages);
	messages = NULL;

	janus_config_destroy(config);
	g_free(admin_key);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_VIDEOROOM_NAME);
}

int janus_videoroom_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_videoroom_get_version(void) {
	return JANUS_VIDEOROOM_VERSION;
}

const char *janus_videoroom_get_version_string(void) {
	return JANUS_VIDEOROOM_VERSION_STRING;
}

const char *janus_videoroom_get_description(void) {
	return JANUS_VIDEOROOM_DESCRIPTION;
}

const char *janus_videoroom_get_name(void) {
	return JANUS_VIDEOROOM_NAME;
}

const char *janus_videoroom_get_author(void) {
	return JANUS_VIDEOROOM_AUTHOR;
}

const char *janus_videoroom_get_package(void) {
	return JANUS_VIDEOROOM_PACKAGE;
}

static janus_videoroom_session *janus_videoroom_lookup_session(janus_plugin_session *handle) {
	janus_videoroom_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_videoroom_session *)handle->plugin_handle;
	}
	return session;
}

void janus_videoroom_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_videoroom_session *session = g_malloc0(sizeof(janus_videoroom_session));
	session->handle = handle;
	session->participant_type = janus_videoroom_p_type_none;
	session->participant = NULL;
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	handle->plugin_handle = session;
	janus_mutex_init(&session->mutex);
	janus_refcount_init(&session->ref, janus_videoroom_session_free);

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

static janus_videoroom_publisher *janus_videoroom_session_get_publisher(janus_videoroom_session *session) {
	janus_mutex_lock(&session->mutex);
	janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)session->participant;
	if(publisher)
		janus_refcount_increase(&publisher->ref);
	janus_mutex_unlock(&session->mutex);
	return publisher;
}

static janus_videoroom_publisher *janus_videoroom_session_get_publisher_nodebug(janus_videoroom_session *session) {
	janus_mutex_lock(&session->mutex);
	janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)session->participant;
	if(publisher)
		janus_refcount_increase_nodebug(&publisher->ref);
	janus_mutex_unlock(&session->mutex);
	return publisher;
}

static void janus_videoroom_notify_participants(janus_videoroom_publisher *participant, json_t *msg) {
	/* participant->room->mutex has to be locked. */
	if(participant->room == NULL)
		return;
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, participant->room->participants);
	while (participant->room && !g_atomic_int_get(&participant->room->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_videoroom_publisher *p = value;
		if(p && p->session && p != participant) {
			JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, msg, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
	}
}

static void janus_videoroom_participant_joining(janus_videoroom_publisher *p) {
	/* we need to check if the room still exists, may have been destroyed already */
	if(p->room == NULL)
		return;
	if(!g_atomic_int_get(&p->room->destroyed) && p->room->notify_joining) {
		json_t *event = json_object();
		json_t *user = json_object();
		json_object_set_new(user, "id", json_integer(p->user_id));
		if (p->display) {
			json_object_set_new(user, "display", json_string(p->display));
		}
		json_object_set_new(event, "videoroom", json_string("event"));
		json_object_set_new(event, "room", json_integer(p->room_id));
		json_object_set_new(event, "joining", user);
		janus_videoroom_notify_participants(p, event);
		/* user gets deref-ed by the owner event */
		json_decref(event);
	}
}

static void janus_videoroom_leave_or_unpublish(janus_videoroom_publisher *participant, gboolean is_leaving, gboolean kicked) {
	/* we need to check if the room still exists, may have been destroyed already */
	if(participant->room == NULL)
		return;
	janus_mutex_lock(&rooms_mutex);
	if (!g_hash_table_lookup(rooms, &participant->room_id)) {
		JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", participant->room_id);
		janus_mutex_unlock(&rooms_mutex);
		return;
	}
	janus_mutex_unlock(&rooms_mutex);
	if(!participant->room || g_atomic_int_get(&participant->room->destroyed))
		return;
	json_t *event = json_object();
	json_object_set_new(event, "videoroom", json_string("event"));
	json_object_set_new(event, "room", json_integer(participant->room_id));
	json_object_set_new(event, is_leaving ? (kicked ? "kicked" : "leaving") : "unpublished",
		json_integer(participant->user_id));
	janus_mutex_lock(&participant->room->mutex);
	janus_videoroom_notify_participants(participant, event);
	/* Also notify event handlers */
	if(notify_events && gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string(is_leaving ? (kicked ? "kicked" : "leaving") : "unpublished"));
		json_object_set_new(info, "room", json_integer(participant->room_id));
		json_object_set_new(info, "id", json_integer(participant->user_id));
		gateway->notify_event(&janus_videoroom_plugin, NULL, info);
	}
	if(is_leaving) {
		g_hash_table_remove(participant->room->participants, &participant->user_id);
		g_hash_table_remove(participant->room->private_ids, GUINT_TO_POINTER(participant->pvt_id));
	}
	janus_mutex_unlock(&participant->room->mutex);
	json_decref(event);
}

void janus_videoroom_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_videoroom_session *session = janus_videoroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No VideoRoom session associated with this handle...\n");
		*error = -2;
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_WARN, "VideoRoom session already marked as destroyed...\n");
		return;
	}
	/* Cleaning up and removing the session is done in a lazy way */
	if(!g_atomic_int_get(&session->destroyed)) {
		/* Any related WebRTC PeerConnection is not available anymore either */
		janus_videoroom_hangup_media_internal(handle);
		if(session->participant_type == janus_videoroom_p_type_publisher) {
			/* Get rid of publisher */
			janus_mutex_lock(&session->mutex);
			janus_videoroom_publisher *p = (janus_videoroom_publisher *)session->participant;
			if(p)
				janus_refcount_increase(&p->ref);
			session->participant = NULL;
			janus_mutex_unlock(&session->mutex);
			if(p && p->room) {
				janus_videoroom_leave_or_unpublish(p, TRUE, FALSE);
				/* Don't clear p->room.  Another thread calls janus_videoroom_leave_or_unpublish,
					 too, and there is no mutex to protect this change. */
				g_clear_pointer(&p->room, janus_videoroom_room_dereference);
			}
			janus_videoroom_publisher_destroy(p);
			if(p)
				janus_refcount_decrease(&p->ref);
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			janus_videoroom_subscriber *s = (janus_videoroom_subscriber *)session->participant;
			session->participant = NULL;
			if(s->room) {
				janus_refcount_decrease(&s->room->ref);
			}
			janus_videoroom_subscriber_destroy(s);
		}
		g_hash_table_remove(sessions, handle);
	}
	janus_mutex_unlock(&sessions_mutex);
	return;
}

json_t *janus_videoroom_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_videoroom_session *session = janus_videoroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* Show the participant/room info, if any */
	json_t *info = json_object();
	if(session->participant) {
		if(session->participant_type == janus_videoroom_p_type_none) {
			json_object_set_new(info, "type", json_string("none"));
		} else if(session->participant_type == janus_videoroom_p_type_publisher) {
			json_object_set_new(info, "type", json_string("publisher"));
			janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher(session);
			if(participant && participant->room) {
				janus_videoroom *room = participant->room;
				json_object_set_new(info, "room", room ? json_integer(room->room_id) : NULL);
				json_object_set_new(info, "id", json_integer(participant->user_id));
				json_object_set_new(info, "private_id", json_integer(participant->pvt_id));
				if(participant->display)
					json_object_set_new(info, "display", json_string(participant->display));
				/* TODO Fix the summary of viewers, since everything is stream based now */
				//~ if(participant->subscribers)
					//~ json_object_set_new(info, "viewers", json_integer(g_slist_length(participant->subscribers)));
				json_object_set_new(info, "bitrate", json_integer(participant->bitrate));
				json_t *media = json_array();
				GList *temp = participant->streams;
				while(temp) {
					janus_videoroom_publisher_stream *stream = (janus_videoroom_publisher_stream *)temp->data;
					janus_refcount_increase(&stream->ref);
					json_t *m = json_object();
					json_object_set_new(m, "type", json_string(janus_videoroom_media_str(stream->type)));
					json_object_set_new(m, "mindex", json_integer(stream->mindex));
					json_object_set_new(m, "mid", json_string(stream->mid));
					if(stream->description)
						json_object_set_new(m, "description", json_string(stream->description));
					if(stream->type == JANUS_VIDEOROOM_MEDIA_AUDIO)
						json_object_set_new(m, "codec", json_string(janus_audiocodec_name(stream->acodec)));
					else if(stream->type == JANUS_VIDEOROOM_MEDIA_VIDEO)
						json_object_set_new(m, "codec", json_string(janus_videocodec_name(stream->vcodec)));
					if(stream->simulcast)
						json_object_set_new(m, "simulcast", json_true());
					if(stream->svc)
						json_object_set_new(m, "vp9-svc", json_true());
					if(stream->rc && stream->rc->filename)
						json_object_set_new(m, "recording", json_string(stream->rc->filename));
					if(stream->audio_level_extmap_id > 0) {
						json_object_set_new(m, "audio-level-dBov", json_integer(stream->audio_dBov_level));
						json_object_set_new(m, "talking", stream->talking ? json_true() : json_false());
					}
					janus_mutex_lock(&stream->subscribers_mutex);
					json_object_set_new(m, "subscribers", json_integer(g_slist_length(stream->subscribers)));
					janus_mutex_unlock(&stream->subscribers_mutex);
					janus_refcount_decrease(&stream->ref);
					json_array_append_new(media, m);
					temp = temp->next;
				}
				json_object_set_new(info, "streams", media);
				janus_refcount_decrease(&participant->ref);
			}
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			json_object_set_new(info, "type", json_string("subscriber"));
			janus_videoroom_subscriber *participant = (janus_videoroom_subscriber *)session->participant;
			if(participant && participant->room) {
				janus_videoroom *room = participant->room;
				json_object_set_new(info, "room", room ? json_integer(room->room_id) : NULL);
				json_object_set_new(info, "answered", g_atomic_int_get(&participant->answered) ? json_true() : json_false());
				json_object_set_new(info, "pending_offer", g_atomic_int_get(&participant->pending_offer) ? json_true() : json_false());
				json_object_set_new(info, "pending_restart", g_atomic_int_get(&participant->pending_restart) ? json_true() : json_false());
				json_object_set_new(info, "paused", participant->paused ? json_true() : json_false());
				json_t *media = janus_videoroom_subscriber_streams_summary(participant, FALSE, NULL);
				json_object_set_new(info, "streams", media);
			}
		}
	}
	json_object_set_new(info, "hangingup", g_atomic_int_get(&session->hangingup) ? json_true() : json_false());
	json_object_set_new(info, "destroyed", g_atomic_int_get(&session->destroyed) ? json_true() : json_false());
	janus_refcount_decrease(&session->ref);
	return info;
}

static int janus_videoroom_access_room(json_t *root, gboolean check_modify, gboolean check_join, janus_videoroom **videoroom, char *error_cause, int error_cause_size) {
	/* rooms_mutex has to be locked */
	int error_code = 0;
	json_t *room = json_object_get(root, "room");
	guint64 room_id = json_integer_value(room);
	*videoroom = g_hash_table_lookup(rooms, &room_id);
	if(*videoroom == NULL) {
		JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
		error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
		if(error_cause)
			g_snprintf(error_cause, error_cause_size, "No such room (%"SCNu64")", room_id);
		return error_code;
	}
	if((*videoroom)->destroyed) {
		JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
		error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
		if(error_cause)
			g_snprintf(error_cause, error_cause_size, "No such room (%"SCNu64")", room_id);
		return error_code;
	}
	if(check_modify) {
		char error_cause2[100];
		JANUS_CHECK_SECRET((*videoroom)->room_secret, root, "secret", error_code, error_cause2,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			g_strlcpy(error_cause, error_cause2, error_cause_size);
			return error_code;
		}
	}
	if(check_join) {
		char error_cause2[100];
		/* signed tokens bypass pin validation */
		json_t *token = json_object_get(root, "token");
		if(token) {
			char room_descriptor[26];
			g_snprintf(room_descriptor, sizeof(room_descriptor), "room=%"SCNu64, room_id);
			if(gateway->auth_signature_contains(&janus_videoroom_plugin, json_string_value(token), room_descriptor))
				return 0;
		}
		JANUS_CHECK_SECRET((*videoroom)->room_pin, root, "pin", error_code, error_cause2,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			g_strlcpy(error_cause, error_cause2, error_cause_size);
			return error_code;
		}
	}
	return 0;
}

/* Helper method to process synchronous requests */
static json_t *janus_videoroom_process_synchronous_request(janus_videoroom_session *session, json_t *message) {
	json_t *request = json_object_get(message, "request");
	const char *request_text = json_string_value(request);

	/* Parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	if(!strcasecmp(request_text, "create")) {
		/* Create a new videoroom */
		JANUS_LOG(LOG_VERB, "Creating a new videoroom\n");
		JANUS_VALIDATE_JSON_OBJECT(root, create_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		if(admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto prepare_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto prepare_response;
		}
		json_t *desc = json_object_get(root, "description");
		json_t *is_private = json_object_get(root, "is_private");
		json_t *req_pvtid = json_object_get(root, "require_pvtid");
		json_t *secret = json_object_get(root, "secret");
		json_t *pin = json_object_get(root, "pin");
		json_t *bitrate = json_object_get(root, "bitrate");
		json_t *bitrate_cap = json_object_get(root, "bitrate_cap");
		json_t *pli_freq = json_object_get(root, "pli_freq");
		if(pli_freq == NULL)	/* For backwards compatibility, we accept fir_freq as well */
			pli_freq = json_object_get(root, "fir_freq");
		json_t *publishers = json_object_get(root, "publishers");
		json_t *allowed = json_object_get(root, "allowed");
		json_t *audiocodec = json_object_get(root, "audiocodec");
		if(audiocodec) {
			const char *audiocodec_value = json_string_value(audiocodec);
			gchar **list = g_strsplit(audiocodec_value, ",", 4);
			gchar *codec = list[0];
			if(codec != NULL) {
				int i=0;
				while(codec != NULL) {
					if(i == 3) {
						break;
					}
					if(strlen(codec) == 0 || JANUS_AUDIOCODEC_NONE == janus_audiocodec_from_name(codec)) {
						JANUS_LOG(LOG_ERR, "Invalid element (audiocodec can only be or contain opus, isac32, isac16, pcmu, pcma or g722)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid element (audiocodec can only be or contain opus, isac32, isac16, pcmu, pcma or g722)");
						goto prepare_response;
					}
					i++;
					codec = list[i];
				}
			}
			g_clear_pointer(&list, g_strfreev);
		}
		json_t *videocodec = json_object_get(root, "videocodec");
		if(videocodec) {
			const char *videocodec_value = json_string_value(videocodec);
			gchar **list = g_strsplit(videocodec_value, ",", 4);
			gchar *codec = list[0];
			if(codec != NULL) {
				int i=0;
				while(codec != NULL) {
					if(i == 3) {
						break;
					}
					if(strlen(codec) == 0 || JANUS_VIDEOCODEC_NONE == janus_videocodec_from_name(codec)) {
						JANUS_LOG(LOG_ERR, "Invalid element (videocodec can only be or contain vp8, vp9 or h264)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid element (videocodec can only be or contain vp8, vp9 or h264)");
						goto prepare_response;
					}
					i++;
					codec = list[i];
				}
			}
			g_clear_pointer(&list, g_strfreev);
		}
		json_t *fec = json_object_get(root, "opus_fec");
		json_t *svc = json_object_get(root, "video_svc");
		json_t *audiolevel_ext = json_object_get(root, "audiolevel_ext");
		json_t *audiolevel_event = json_object_get(root, "audiolevel_event");
		json_t *audio_active_packets = json_object_get(root, "audio_active_packets");
		json_t *audio_level_average = json_object_get(root, "audio_level_average");
		json_t *videoorient_ext = json_object_get(root, "videoorient_ext");
		json_t *playoutdelay_ext = json_object_get(root, "playoutdelay_ext");
		json_t *transport_wide_cc_ext = json_object_get(root, "transport_wide_cc_ext");
		json_t *notify_joining = json_object_get(root, "notify_joining");
		json_t *record = json_object_get(root, "record");
		json_t *rec_dir = json_object_get(root, "rec_dir");
		json_t *permanent = json_object_get(root, "permanent");
		if(allowed) {
			/* Make sure the "allowed" array only contains strings */
			gboolean ok = TRUE;
			if(json_array_size(allowed) > 0) {
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					json_t *a = json_array_get(allowed, i);
					if(!a || !json_is_string(a)) {
						ok = FALSE;
						break;
					}
				}
			}
			if(!ok) {
				JANUS_LOG(LOG_ERR, "Invalid element in the allowed array (not a string)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element in the allowed array (not a string)");
				goto prepare_response;
			}
		}
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't create permanent room\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't create permanent room");
			goto prepare_response;
		}
		guint64 room_id = 0;
		json_t *room = json_object_get(root, "room");
		if(room) {
			room_id = json_integer_value(room);
			if(room_id == 0) {
				JANUS_LOG(LOG_WARN, "Desired room ID is 0, which is not allowed... picking random ID instead\n");
			}
		}
		janus_mutex_lock(&rooms_mutex);
		if(room_id > 0) {
			/* Let's make sure the room doesn't exist already */
			if(g_hash_table_lookup(rooms, &room_id) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Room %"SCNu64" already exists!\n", room_id);
				error_code = JANUS_VIDEOROOM_ERROR_ROOM_EXISTS;
				g_snprintf(error_cause, 512, "Room %"SCNu64" already exists", room_id);
				goto prepare_response;
			}
		}
		/* Create the room */
		janus_videoroom *videoroom = g_malloc0(sizeof(janus_videoroom));
		/* Generate a random ID */
		if(room_id == 0) {
			while(room_id == 0) {
				room_id = janus_random_uint64();
				if(g_hash_table_lookup(rooms, &room_id) != NULL) {
					/* Room ID already taken, try another one */
					room_id = 0;
				}
			}
		}
		videoroom->room_id = room_id;
		char *description = NULL;
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			description = g_strdup(json_string_value(desc));
		} else {
			char roomname[255];
			g_snprintf(roomname, 255, "Room %"SCNu64"", videoroom->room_id);
			description = g_strdup(roomname);
		}
		videoroom->room_name = description;
		videoroom->is_private = is_private ? json_is_true(is_private) : FALSE;
		videoroom->require_pvtid = req_pvtid ? json_is_true(req_pvtid) : FALSE;
		if(secret)
			videoroom->room_secret = g_strdup(json_string_value(secret));
		if(pin)
			videoroom->room_pin = g_strdup(json_string_value(pin));
		videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
		if(publishers)
			videoroom->max_publishers = json_integer_value(publishers);
		if(videoroom->max_publishers < 0)
			videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
		videoroom->bitrate = 0;
		if(bitrate)
			videoroom->bitrate = json_integer_value(bitrate);
		if(videoroom->bitrate > 0 && videoroom->bitrate < 64000)
			videoroom->bitrate = 64000;	/* Don't go below 64k */
		videoroom->bitrate_cap = bitrate_cap ? json_is_true(bitrate_cap) : FALSE;
		videoroom->pli_freq = 0;
		if(pli_freq)
			videoroom->pli_freq = json_integer_value(pli_freq);
		/* By default, we force Opus as the only audio codec */
		videoroom->acodec[0] = JANUS_AUDIOCODEC_OPUS;
		videoroom->acodec[1] = JANUS_AUDIOCODEC_NONE;
		videoroom->acodec[2] = JANUS_AUDIOCODEC_NONE;
		/* Check if we're forcing a different single codec, or allowing more than one */
		if(audiocodec) {
			const char *audiocodec_value = json_string_value(audiocodec);
			gchar **list = g_strsplit(audiocodec_value, ",", 4);
			gchar *codec = list[0];
			if(codec != NULL) {
				int i=0;
				while(codec != NULL) {
					if(i == 3) {
						JANUS_LOG(LOG_WARN, "Ignoring extra audio codecs: %s\n", codec);
						break;
					}
					if(strlen(codec) > 0)
						videoroom->acodec[i] = janus_audiocodec_from_name(codec);
					i++;
					codec = list[i];
				}
			}
			g_clear_pointer(&list, g_strfreev);
		}
		/* By default, we force VP8 as the only video codec */
		videoroom->vcodec[0] = JANUS_VIDEOCODEC_VP8;
		videoroom->vcodec[1] = JANUS_VIDEOCODEC_NONE;
		videoroom->vcodec[2] = JANUS_VIDEOCODEC_NONE;
		/* Check if we're forcing a different single codec, or allowing more than one */
		if(videocodec) {
			const char *videocodec_value = json_string_value(videocodec);
			gchar **list = g_strsplit(videocodec_value, ",", 4);
			gchar *codec = list[0];
			if(codec != NULL) {
				int i=0;
				while(codec != NULL) {
					if(i == 3) {
						JANUS_LOG(LOG_WARN, "Ignoring extra video codecs: %s\n", codec);
						break;
					}
					if(strlen(codec) > 0)
						videoroom->vcodec[i] = janus_videocodec_from_name(codec);
					i++;
					codec = list[i];
				}
			}
			g_clear_pointer(&list, g_strfreev);
		}
		if(fec) {
			videoroom->do_opusfec = json_is_true(fec);
			if(videoroom->acodec[0] != JANUS_AUDIOCODEC_OPUS &&
					videoroom->acodec[1] != JANUS_AUDIOCODEC_OPUS &&
					videoroom->acodec[2] != JANUS_AUDIOCODEC_OPUS) {
				videoroom->do_opusfec = FALSE;
				JANUS_LOG(LOG_WARN, "Inband FEC is only supported for rooms that allow Opus: disabling it...\n");
			}
		}
		if(svc && json_is_true(svc)) {
			if(videoroom->vcodec[0] == JANUS_VIDEOCODEC_VP9 &&
					videoroom->vcodec[1] == JANUS_VIDEOCODEC_NONE &&
					videoroom->vcodec[2] == JANUS_VIDEOCODEC_NONE) {
				videoroom->do_svc = TRUE;
			} else {
				JANUS_LOG(LOG_WARN, "SVC is only supported, in an experimental way, for VP9 only rooms: disabling it...\n");
			}
		}
		videoroom->audiolevel_ext = audiolevel_ext ? json_is_true(audiolevel_ext) : TRUE;
		videoroom->audiolevel_event = audiolevel_event ? json_is_true(audiolevel_event) : FALSE;
		if(videoroom->audiolevel_event) {
			videoroom->audio_active_packets = 100;
			if(json_integer_value(audio_active_packets) > 0) {
				videoroom->audio_active_packets = json_integer_value(audio_active_packets);
			} else {
				JANUS_LOG(LOG_WARN, "Invalid audio_active_packets value provided, using default: %d\n", videoroom->audio_active_packets);
			}
			videoroom->audio_level_average = 25;
			if(json_integer_value(audio_level_average) > 0) {
				videoroom->audio_level_average = json_integer_value(audio_level_average);
			} else {
				JANUS_LOG(LOG_WARN, "Invalid audio_level_average value provided, using default: %d\n", videoroom->audio_level_average);
			}
		}
		videoroom->videoorient_ext = videoorient_ext ? json_is_true(videoorient_ext) : TRUE;
		videoroom->playoutdelay_ext = playoutdelay_ext ? json_is_true(playoutdelay_ext) : TRUE;
		videoroom->transport_wide_cc_ext = transport_wide_cc_ext ? json_is_true(transport_wide_cc_ext) : TRUE;
		/* By default, the videoroom plugin does not notify about participants simply joining the room.
		   It only notifies when the participant actually starts publishing media. */
		videoroom->notify_joining = notify_joining ? json_is_true(notify_joining) : FALSE;
		if(record) {
			videoroom->record = json_is_true(record);
		}
		if(rec_dir) {
			videoroom->rec_dir = g_strdup(json_string_value(rec_dir));
		}
		g_atomic_int_set(&videoroom->destroyed, 0);
		janus_mutex_init(&videoroom->mutex);
		janus_refcount_init(&videoroom->ref, janus_videoroom_room_free);
		videoroom->participants = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, (GDestroyNotify)janus_videoroom_publisher_dereference);
		videoroom->private_ids = g_hash_table_new(NULL, NULL);
		videoroom->allowed = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
		if(allowed != NULL) {
			/* Populate the "allowed" list as an ACL for people trying to join */
			if(json_array_size(allowed) > 0) {
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					const char *token = json_string_value(json_array_get(allowed, i));
					if(!g_hash_table_lookup(videoroom->allowed, token))
						g_hash_table_insert(videoroom->allowed, g_strdup(token), GINT_TO_POINTER(TRUE));
				}
			}
			videoroom->check_allowed = TRUE;
		}
		/* Compute a list of the supported codecs for the summary */
		char audio_codecs[100], video_codecs[100];
		janus_videoroom_codecstr(videoroom, audio_codecs, video_codecs, sizeof(audio_codecs), "|");
		JANUS_LOG(LOG_VERB, "Created videoroom: %"SCNu64" (%s, %s, %s/%s codecs, secret: %s, pin: %s, pvtid: %s)\n",
			videoroom->room_id, videoroom->room_name,
			videoroom->is_private ? "private" : "public",
			audio_codecs, video_codecs,
			videoroom->room_secret ? videoroom->room_secret : "no secret",
			videoroom->room_pin ? videoroom->room_pin : "no pin",
			videoroom->require_pvtid ? "required" : "optional");
		if(videoroom->record) {
			JANUS_LOG(LOG_VERB, "  -- Room is going to be recorded in %s\n", videoroom->rec_dir ? videoroom->rec_dir : "the current folder");
		}
		if(save) {
			/* This room is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Saving room %"SCNu64" permanently in config file\n", videoroom->room_id);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ], value[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%"SCNu64, videoroom->room_id);
			janus_config_category *c = janus_config_get_create(config, NULL, janus_config_type_category, cat);
			/* Now for the values */
			janus_config_add(config, c, janus_config_item_create("description", videoroom->room_name));
			if(videoroom->is_private)
				janus_config_add(config, c, janus_config_item_create("is_private", "yes"));
			if(videoroom->require_pvtid)
				janus_config_add(config, c, janus_config_item_create("require_pvtid", "yes"));
			g_snprintf(value, BUFSIZ, "%"SCNu32, videoroom->bitrate);
			janus_config_add(config, c, janus_config_item_create("bitrate", value));
			if(videoroom->bitrate_cap)
				janus_config_add(config, c, janus_config_item_create("bitrate_cap", "yes"));
			g_snprintf(value, BUFSIZ, "%d", videoroom->max_publishers);
			janus_config_add(config, c, janus_config_item_create("publishers", value));
			if(videoroom->pli_freq) {
				g_snprintf(value, BUFSIZ, "%"SCNu16, videoroom->pli_freq);
				janus_config_add(config, c, janus_config_item_create("pli_freq", value));
			}
			char video_codecs[100];
			char audio_codecs[100];
			janus_videoroom_codecstr(videoroom, audio_codecs, video_codecs, sizeof(audio_codecs), ",");
			janus_config_add(config, c, janus_config_item_create("audiocodec", audio_codecs));
			janus_config_add(config, c, janus_config_item_create("videocodec", video_codecs));
			if(videoroom->do_opusfec)
				janus_config_add(config, c, janus_config_item_create("opus_fec", "yes"));
			if(videoroom->do_svc)
				janus_config_add(config, c, janus_config_item_create("video_svc", "yes"));
			if(videoroom->room_secret)
				janus_config_add(config, c, janus_config_item_create("secret", videoroom->room_secret));
			if(videoroom->room_pin)
				janus_config_add(config, c, janus_config_item_create("pin", videoroom->room_pin));
			if(videoroom->audiolevel_ext) {
				janus_config_add(config, c, janus_config_item_create("audiolevel_ext", "yes"));
				if(videoroom->audiolevel_event)
					janus_config_add(config, c, janus_config_item_create("audiolevel_event", "yes"));
				if(videoroom->audio_active_packets > 0) {
					g_snprintf(value, BUFSIZ, "%d", videoroom->audio_active_packets);
					janus_config_add(config, c, janus_config_item_create("audio_active_packets", value));
				}
				if(videoroom->audio_level_average > 0) {
					g_snprintf(value, BUFSIZ, "%d", videoroom->audio_level_average);
					janus_config_add(config, c, janus_config_item_create("audio_level_average", value));
				}
			} else {
				janus_config_add(config, c, janus_config_item_create("audiolevel_ext", "no"));
			}
			janus_config_add(config, c, janus_config_item_create("videoorient_ext", videoroom->videoorient_ext ? "yes" : "no"));
			janus_config_add(config, c, janus_config_item_create("playoutdelay_ext", videoroom->playoutdelay_ext ? "yes" : "no"));
			janus_config_add(config, c, janus_config_item_create("transport_wide_cc_ext", videoroom->transport_wide_cc_ext ? "yes" : "no"));
			if(videoroom->notify_joining)
				janus_config_add(config, c, janus_config_item_create("notify_joining", "yes"));
			if(videoroom->record)
				janus_config_add(config, c, janus_config_item_create("record", "yes"));
			if(videoroom->rec_dir)
				janus_config_add(config, c, janus_config_item_create("rec_dir", videoroom->rec_dir));
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_VIDEOROOM_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room is not permanent */
			janus_mutex_unlock(&config_mutex);
		}

		g_hash_table_insert(rooms, janus_uint64_dup(videoroom->room_id), videoroom);
		/* Show updated rooms list */
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom *vr = value;
			JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s] %"SCNu32", max %d publishers, PLI frequency of %d seconds\n", vr->room_id, vr->room_name, vr->bitrate, vr->max_publishers, vr->pli_freq);
		}
		janus_mutex_unlock(&rooms_mutex);
		/* Send info back */
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("created"));
		json_object_set_new(response, "room", json_integer(videoroom->room_id));
		json_object_set_new(response, "permanent", save ? json_true() : json_false());
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("created"));
			json_object_set_new(info, "room", json_integer(videoroom->room_id));
			gateway->notify_event(&janus_videoroom_plugin, session ? session->handle : NULL, info);
		}
		goto prepare_response;
	} else if(!strcasecmp(request_text, "edit")) {
		/* Edit the properties for an existing videoroom */
		JANUS_LOG(LOG_VERB, "Attempt to edit the properties of an existing videoroom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, edit_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		/* We only allow for a limited set of properties to be edited */
		json_t *desc = json_object_get(root, "new_description");
		json_t *is_private = json_object_get(root, "new_is_private");
		json_t *req_pvtid = json_object_get(root, "new_require_pvtid");
		json_t *secret = json_object_get(root, "new_secret");
		json_t *pin = json_object_get(root, "new_pin");
		json_t *bitrate = json_object_get(root, "new_bitrate");
		json_t *pli_freq = json_object_get(root, "new_pli_freq");
		if(pli_freq == NULL)	/* For backwards compatibility, we accept new_fir_freq as well */
			pli_freq = json_object_get(root, "new_fir_freq");
		json_t *publishers = json_object_get(root, "new_publishers");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't edit room permanently\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't edit room permanently");
			goto prepare_response;
		}
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, TRUE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		/* Edit the room properties that were provided */
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			char *old_description = videoroom->room_name;
			char *new_description = g_strdup(json_string_value(desc));
			videoroom->room_name = new_description;
			g_free(old_description);
		}
		if(is_private)
			videoroom->is_private = json_is_true(is_private);
		if(req_pvtid)
			videoroom->require_pvtid = json_is_true(req_pvtid);
		if(publishers)
			videoroom->max_publishers = json_integer_value(publishers);
		if(bitrate) {
			videoroom->bitrate = json_integer_value(bitrate);
			if(videoroom->bitrate > 0 && videoroom->bitrate < 64000)
				videoroom->bitrate = 64000;	/* Don't go below 64k */
		}
		if(pli_freq)
			videoroom->pli_freq = json_integer_value(pli_freq);
		if(secret && strlen(json_string_value(secret)) > 0) {
			char *old_secret = videoroom->room_secret;
			char *new_secret = g_strdup(json_string_value(secret));
			videoroom->room_secret = new_secret;
			g_free(old_secret);
		}
		if(pin && strlen(json_string_value(pin)) > 0) {
			char *old_pin = videoroom->room_pin;
			char *new_pin = g_strdup(json_string_value(pin));
			videoroom->room_pin = new_pin;
			g_free(old_pin);
		}
		if(save) {
			/* This room is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Modifying room %"SCNu64" permanently in config file\n", videoroom->room_id);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ], value[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%"SCNu64, videoroom->room_id);
			/* Remove the old category first */
			janus_config_remove(config, NULL, cat);
			/* Now write the room details again */
			janus_config_category *c = janus_config_get_create(config, NULL, janus_config_type_category, cat);
			janus_config_add(config, c, janus_config_item_create("description", videoroom->room_name));
			if(videoroom->is_private)
				janus_config_add(config, c, janus_config_item_create("is_private", "yes"));
			if(videoroom->require_pvtid)
				janus_config_add(config, c, janus_config_item_create("require_pvtid", "yes"));
			g_snprintf(value, BUFSIZ, "%"SCNu32, videoroom->bitrate);
			janus_config_add(config, c, janus_config_item_create("bitrate", value));
			if(videoroom->bitrate_cap)
				janus_config_add(config, c, janus_config_item_create("bitrate_cap", "yes"));
			g_snprintf(value, BUFSIZ, "%d", videoroom->max_publishers);
			janus_config_add(config, c, janus_config_item_create("publishers", value));
			if(videoroom->pli_freq) {
				g_snprintf(value, BUFSIZ, "%"SCNu16, videoroom->pli_freq);
				janus_config_add(config, c, janus_config_item_create("pli_freq", value));
			}
			char audio_codecs[100];
			char video_codecs[100];
			janus_videoroom_codecstr(videoroom, audio_codecs, video_codecs, sizeof(audio_codecs), ",");
			janus_config_add(config, c, janus_config_item_create("audiocodec", audio_codecs));
			janus_config_add(config, c, janus_config_item_create("videocodec", video_codecs));
			if(videoroom->do_opusfec)
				janus_config_add(config, c, janus_config_item_create("opus_fec", "yes"));
			if(videoroom->do_svc)
				janus_config_add(config, c, janus_config_item_create("video_svc", "yes"));
			if(videoroom->room_secret)
				janus_config_add(config, c, janus_config_item_create("secret", videoroom->room_secret));
			if(videoroom->room_pin)
				janus_config_add(config, c, janus_config_item_create("pin", videoroom->room_pin));
			if(videoroom->audiolevel_ext) {
				janus_config_add(config, c, janus_config_item_create("audiolevel_ext", "yes"));
				if(videoroom->audiolevel_event)
					janus_config_add(config, c, janus_config_item_create("audiolevel_event", "yes"));
				if(videoroom->audio_active_packets > 0) {
					g_snprintf(value, BUFSIZ, "%d", videoroom->audio_active_packets);
					janus_config_add(config, c, janus_config_item_create("audio_active_packets", value));
				}
				if(videoroom->audio_level_average > 0) {
					g_snprintf(value, BUFSIZ, "%d", videoroom->audio_level_average);
					janus_config_add(config, c, janus_config_item_create("audio_level_average", value));
				}
			} else {
				janus_config_add(config, c, janus_config_item_create("audiolevel_ext", "no"));
			}
			janus_config_add(config, c, janus_config_item_create("videoorient_ext", videoroom->videoorient_ext ? "yes" : "no"));
			janus_config_add(config, c, janus_config_item_create("playoutdelay_ext", videoroom->playoutdelay_ext ? "yes" : "no"));
			janus_config_add(config, c, janus_config_item_create("transport_wide_cc_ext", videoroom->transport_wide_cc_ext ? "yes" : "no"));
			if(videoroom->notify_joining)
				janus_config_add(config, c, janus_config_item_create("notify_joining", "yes"));
			if(videoroom->record)
				janus_config_add(config, c, janus_config_item_create("record", "yes"));
			if(videoroom->rec_dir)
				janus_config_add(config, c, janus_config_item_create("rec_dir", videoroom->rec_dir));
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_VIDEOROOM_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room changes are not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		janus_mutex_unlock(&rooms_mutex);
		/* Send info back */
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("edited"));
		json_object_set_new(response, "room", json_integer(videoroom->room_id));
		json_object_set_new(response, "permanent", save ? json_true() : json_false());
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("edited"));
			json_object_set_new(info, "room", json_integer(videoroom->room_id));
			gateway->notify_event(&janus_videoroom_plugin, session ? session->handle : NULL, info);
		}
		goto prepare_response;
	} else if(!strcasecmp(request_text, "destroy")) {
		JANUS_LOG(LOG_VERB, "Attempt to destroy an existing videoroom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, destroy_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't destroy room permanently\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't destroy room permanently");
			goto prepare_response;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, TRUE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		/* Remove room, but add a reference until we're done */
		janus_refcount_increase(&videoroom->ref);
		g_hash_table_remove(rooms, &room_id);
		/* Notify all participants that the fun is over, and that they'll be kicked */
		JANUS_LOG(LOG_VERB, "Notifying all participants\n");
		json_t *destroyed = json_object();
		json_object_set_new(destroyed, "videoroom", json_string("destroyed"));
		json_object_set_new(destroyed, "room", json_integer(room_id));
		GHashTableIter iter;
		gpointer value;
		janus_mutex_lock(&videoroom->mutex);
		g_hash_table_iter_init(&iter, videoroom->participants);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom_publisher *p = value;
			if(p && p->session) {
				g_clear_pointer(&p->room, janus_videoroom_room_dereference);
				/* Notify the user we're going to destroy the room... */
				int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, destroyed, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				/* ... and then ask the core to close the PeerConnection */
				gateway->close_pc(p->session->handle);
			}
		}
		json_decref(destroyed);
		janus_mutex_unlock(&videoroom->mutex);
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("destroyed"));
			json_object_set_new(info, "room", json_integer(room_id));
			gateway->notify_event(&janus_videoroom_plugin, session ? session->handle : NULL, info);
		}
		janus_mutex_unlock(&rooms_mutex);
		if(save) {
			/* This change is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Destroying room %"SCNu64" permanently in config file\n", room_id);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%"SCNu64, room_id);
			janus_config_remove(config, NULL, cat);
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_VIDEOROOM_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room destruction is not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		janus_refcount_decrease(&videoroom->ref);
		/* Done */
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("destroyed"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "permanent", save ? json_true() : json_false());
		goto prepare_response;
	} else if(!strcasecmp(request_text, "list")) {
		/* List all rooms (but private ones) and their details (except for the secret, of course...) */
		json_t *list = json_array();
		JANUS_LOG(LOG_VERB, "Getting the list of video rooms\n");
		janus_mutex_lock(&rooms_mutex);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom *room = value;
			if(!room)
				continue;
			janus_refcount_increase(&room->ref);
			if(room->is_private) {
				/* Skip private room */
				JANUS_LOG(LOG_VERB, "Skipping private room '%s'\n", room->room_name);
				janus_refcount_decrease(&room->ref);
				continue;
			}
			if(!g_atomic_int_get(&room->destroyed)) {
				json_t *rl = json_object();
				json_object_set_new(rl, "room", json_integer(room->room_id));
				json_object_set_new(rl, "description", json_string(room->room_name));
				json_object_set_new(rl, "pin_required", room->room_pin ? json_true() : json_false());
				json_object_set_new(rl, "max_publishers", json_integer(room->max_publishers));
				json_object_set_new(rl, "bitrate", json_integer(room->bitrate));
				if(room->bitrate_cap)
					json_object_set_new(rl, "bitrate_cap", json_true());
				json_object_set_new(rl, "pli_freq", json_integer(room->pli_freq));
				json_object_set_new(rl, "require_pvtid", room->require_pvtid ? json_true() : json_false());
				json_object_set_new(rl, "notify_joining", room->notify_joining ? json_true() : json_false());
				char audio_codecs[100];
				char video_codecs[100];
				janus_videoroom_codecstr(room, audio_codecs, video_codecs, sizeof(audio_codecs), ",");
				json_object_set_new(rl, "audiocodec", json_string(audio_codecs));
				json_object_set_new(rl, "videocodec", json_string(video_codecs));
				if(room->do_opusfec)
					json_object_set_new(rl, "opus_fec", json_true());
				if(room->do_svc)
					json_object_set_new(rl, "video_svc", json_true());
				json_object_set_new(rl, "record", room->record ? json_true() : json_false());
				json_object_set_new(rl, "rec_dir", json_string(room->rec_dir));
				/* TODO: Should we list participants as well? or should there be a separate API call on a specific room for this? */
				json_object_set_new(rl, "num_participants", json_integer(g_hash_table_size(room->participants)));
				json_array_append_new(list, rl);
			}
			janus_refcount_decrease(&room->ref);
		}
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("success"));
		json_object_set_new(response, "list", list);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "rtp_forward")) {
		JANUS_VALIDATE_JSON_OBJECT(root, rtp_forward_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		if(lock_rtpfwd && admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto prepare_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto prepare_response;
		}
		json_t *room = json_object_get(root, "room");
		json_t *pub_id = json_object_get(root, "publisher_id");
		json_t *json_host = json_object_get(root, "host");
		const char *host = json_string_value(json_host);

		json_t *streams = json_object_get(root, "streams");
		if(streams == NULL || json_array_size(streams) == 0) {
			/* No streams array, we'll use the legacy approach: make sure the host attribute was set */
			if(host == NULL) {
				error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, sizeof(error_cause), "Missing mandatory element host (deprecated API)");
				goto prepare_response;
			}
		} else {
			/* Iterate on the streams objects and validate them all */
			size_t i = 0;
			for(i=0; i<json_array_size(streams); i++) {
				json_t *s = json_array_get(streams, i);
				JANUS_VALIDATE_JSON_OBJECT(s, rtp_forward_stream_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto prepare_response;
				/* Make sure we have a host attribute, either global or stream-specific */
				json_t *stream_host = json_object_get(s, "host");
				const char *s_host = json_string_value(stream_host);
				if(host == NULL && s_host == NULL) {
					error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
					g_snprintf(error_cause, sizeof(error_cause), "Missing mandatory element host (global or local)");
					goto prepare_response;
				}
			}
		}
		/* We may need to SRTP-encrypt this stream */
		int srtp_suite = 0;
		const char *srtp_crypto = NULL;
		json_t *s_suite = json_object_get(root, "srtp_suite");
		json_t *s_crypto = json_object_get(root, "srtp_crypto");
		if(s_suite && s_crypto) {
			srtp_suite = json_integer_value(s_suite);
			if(srtp_suite != 32 && srtp_suite != 80) {
				JANUS_LOG(LOG_ERR, "Invalid SRTP suite (%d)\n", srtp_suite);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid SRTP suite (%d)", srtp_suite);
				goto prepare_response;
			}
			srtp_crypto = json_string_value(s_crypto);
		}
		/* Look for room and publisher */
		guint64 room_id = json_integer_value(room);
		guint64 publisher_id = json_integer_value(pub_id);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, TRUE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		janus_mutex_unlock(&rooms_mutex);
		if(error_code != 0)
			goto prepare_response;
		janus_refcount_increase(&videoroom->ref);
		janus_mutex_lock(&videoroom->mutex);
		janus_videoroom_publisher *publisher = g_hash_table_lookup(videoroom->participants, &publisher_id);
		if(publisher == NULL) {
			janus_mutex_unlock(&videoroom->mutex);
			janus_refcount_decrease(&videoroom->ref);
			JANUS_LOG(LOG_ERR, "No such publisher (%"SCNu64")\n", publisher_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", publisher_id);
			goto prepare_response;
		}
		janus_refcount_increase(&publisher->ref);	/* This is just to handle the request for now */
		janus_mutex_lock(&publisher->rtp_forwarders_mutex);
		if(publisher->udp_sock <= 0) {
			publisher->udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(publisher->udp_sock <= 0) {
				janus_mutex_unlock(&publisher->rtp_forwarders_mutex);
				janus_refcount_decrease(&publisher->ref);
				janus_mutex_unlock(&videoroom->mutex);
				janus_refcount_decrease(&videoroom->ref);
				JANUS_LOG(LOG_ERR, "Could not open UDP socket for rtp stream for publisher (%"SCNu64")\n", publisher_id);
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Could not open UDP socket for rtp stream");
				goto prepare_response;
			}
		}
		/* Are we using the new approach, or the old deprecated one? */
		response = json_object();
		json_t *rtp_stream = json_object();
		janus_videoroom_publisher_stream *stream = NULL;
		json_t *new_forwarders = NULL;
		if(streams != NULL) {
			/* New approach: iterate on all objects, and create the related forwarder(s) */
			new_forwarders = json_array();
			size_t i = 0;
			for(i=0; i<json_array_size(streams); i++) {
				json_t *s = json_array_get(streams, i);
				json_t *stream_mid = json_object_get(s, "mid");
				const char *mid = json_string_value(stream_mid);
				janus_mutex_lock(&publisher->streams_mutex);
				stream = g_hash_table_lookup(publisher->streams_bymid, mid);
				janus_mutex_unlock(&publisher->streams_mutex);
				if(stream == NULL) {
					/* FIXME Should we return an error instead? */
					JANUS_LOG(LOG_WARN, "No such stream with mid '%s', skipping forwarder...\n", mid);
					continue;
				}
				janus_videoroom_rtp_forwarder *f = NULL;
				json_t *stream_host = json_object_get(s, "host");
				host = json_string_value(stream_host) ? json_string_value(stream_host) : json_string_value(json_host);
				json_t *stream_port = json_object_get(s, "port");
				if(stream->type == JANUS_VIDEOROOM_MEDIA_DATA) {
					/* We have all we need */
					f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
						host, json_integer_value(stream_port), 0, 0, 0, FALSE, 0, NULL, 0, FALSE, TRUE);
					if(f) {
						json_t *rtpf = janus_videoroom_rtp_forwarder_summary(f);
						json_array_append_new(new_forwarders, rtpf);
						/* Also notify event handlers */
						if(notify_events && gateway->events_is_enabled()) {
							json_t *info = janus_videoroom_rtp_forwarder_summary(f);
							json_object_set_new(info, "event", json_string("rtp_forward"));
							json_object_set_new(info, "room", json_integer(room_id));
							json_object_set_new(info, "publisher_id", json_integer(publisher_id));
							gateway->notify_event(&janus_videoroom_plugin, NULL, info);
						}
					}
					continue;
				}
				/* If we got here, it's RTP media, check the other properties too */
				json_t *stream_pt = json_object_get(root, "pt");
				json_t *stream_ssrc = json_object_get(root, "ssrc");
				json_t *stream_rtcp_port = json_object_get(s, "rtcp_port");
				if(stream->type == JANUS_VIDEOROOM_MEDIA_AUDIO) {
					f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
						host, json_integer_value(stream_port), stream_rtcp_port ? json_integer_value(stream_rtcp_port) : -1,
						json_integer_value(stream_pt), json_integer_value(stream_ssrc),
						FALSE, srtp_suite, srtp_crypto, 0, FALSE, FALSE);
					if(f) {
						json_t *rtpf = janus_videoroom_rtp_forwarder_summary(f);
						json_array_append_new(new_forwarders, rtpf);
						/* Also notify event handlers */
						if(notify_events && gateway->events_is_enabled()) {
							json_t *info = janus_videoroom_rtp_forwarder_summary(f);
							json_object_set_new(info, "event", json_string("rtp_forward"));
							json_object_set_new(info, "room", json_integer(room_id));
							json_object_set_new(info, "publisher_id", json_integer(publisher_id));
							gateway->notify_event(&janus_videoroom_plugin, NULL, info);
						}
					}
				} else {
					json_t *stream_simulcast = json_object_get(root, "simulcast");
					f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
						host, json_integer_value(stream_port), stream_rtcp_port ? json_integer_value(stream_rtcp_port) : -1,
						json_integer_value(stream_pt), json_integer_value(stream_ssrc),
						json_is_true(stream_simulcast), srtp_suite, srtp_crypto, 0, TRUE, FALSE);
					if(f) {
						json_t *rtpf = janus_videoroom_rtp_forwarder_summary(f);
						json_array_append_new(new_forwarders, rtpf);
						/* Also notify event handlers */
						if(notify_events && gateway->events_is_enabled()) {
							json_t *info = janus_videoroom_rtp_forwarder_summary(f);
							json_object_set_new(info, "event", json_string("rtp_forward"));
							json_object_set_new(info, "room", json_integer(room_id));
							json_object_set_new(info, "publisher_id", json_integer(publisher_id));
							gateway->notify_event(&janus_videoroom_plugin, NULL, info);
						}
					}
					if(!json_is_true(stream_simulcast)) {
						/* Check if there's simulcast substreams we need to relay */
						stream_port = json_object_get(s, "port_2");
						stream_pt = json_object_get(root, "pt_2");
						stream_ssrc = json_object_get(root, "ssrc_2");
						if(json_integer_value(stream_port) > 0) {
							f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
								host, json_integer_value(stream_port), 0,
								json_integer_value(stream_pt), json_integer_value(stream_ssrc),
								FALSE, srtp_suite, srtp_crypto, 1, TRUE, FALSE);
							if(f) {
								json_t *rtpf = janus_videoroom_rtp_forwarder_summary(f);
								json_array_append_new(new_forwarders, rtpf);
								/* Also notify event handlers */
								if(notify_events && gateway->events_is_enabled()) {
									json_t *info = janus_videoroom_rtp_forwarder_summary(f);
									json_object_set_new(info, "event", json_string("rtp_forward"));
									json_object_set_new(info, "room", json_integer(room_id));
									json_object_set_new(info, "publisher_id", json_integer(publisher_id));
									gateway->notify_event(&janus_videoroom_plugin, NULL, info);
								}
							}
						}
						stream_port = json_object_get(s, "port_3");
						stream_pt = json_object_get(root, "pt_3");
						stream_ssrc = json_object_get(root, "ssrc_3");
						if(json_integer_value(stream_port) > 0) {
							f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
								host, json_integer_value(stream_port), 0,
								json_integer_value(stream_pt), json_integer_value(stream_ssrc),
								FALSE, srtp_suite, srtp_crypto, 2, TRUE, FALSE);
							if(f) {
								json_t *rtpf = janus_videoroom_rtp_forwarder_summary(f);
								json_array_append_new(new_forwarders, rtpf);
								/* Also notify event handlers */
								if(notify_events && gateway->events_is_enabled()) {
									json_t *info = janus_videoroom_rtp_forwarder_summary(f);
									json_object_set_new(info, "event", json_string("rtp_forward"));
									json_object_set_new(info, "room", json_integer(room_id));
									json_object_set_new(info, "publisher_id", json_integer(publisher_id));
									gateway->notify_event(&janus_videoroom_plugin, NULL, info);
								}
							}
						}
					}
				}
			}
		} else {
			/* Old deprecated approach: return the legacy info as well */
			int video_port[3] = {-1, -1, -1}, video_rtcp_port = -1, video_pt[3] = {0, 0, 0};
			uint32_t video_ssrc[3] = {0, 0, 0};
			int audio_port = -1, audio_rtcp_port = -1, audio_pt = 0;
			uint32_t audio_ssrc = 0;
			int data_port = -1;
			/* There may be multiple target video ports (e.g., publisher simulcasting) */
			json_t *vid_port = json_object_get(root, "video_port");
			if(vid_port) {
				video_port[0] = json_integer_value(vid_port);
				json_t *pt = json_object_get(root, "video_pt");
				if(pt)
					video_pt[0] = json_integer_value(pt);
				json_t *ssrc = json_object_get(root, "video_ssrc");
				if(ssrc)
					video_ssrc[0] = json_integer_value(ssrc);
			}
			vid_port = json_object_get(root, "video_port_2");
			if(vid_port) {
				video_port[1] = json_integer_value(vid_port);
				json_t *pt = json_object_get(root, "video_pt_2");
				if(pt)
					video_pt[1] = json_integer_value(pt);
				json_t *ssrc = json_object_get(root, "video_ssrc_2");
				if(ssrc)
					video_ssrc[1] = json_integer_value(ssrc);
			}
			vid_port = json_object_get(root, "video_port_3");
			if(vid_port) {
				video_port[2] = json_integer_value(vid_port);
				json_t *pt = json_object_get(root, "video_pt_3");
				if(pt)
					video_pt[2] = json_integer_value(pt);
				json_t *ssrc = json_object_get(root, "video_ssrc_3");
				if(ssrc)
					video_ssrc[2] = json_integer_value(ssrc);
			}
			json_t *vid_rtcp_port = json_object_get(root, "video_rtcp_port");
			if(vid_rtcp_port)
				video_rtcp_port = json_integer_value(vid_rtcp_port);
			/* Audio target */
			json_t *au_port = json_object_get(root, "audio_port");
			if(au_port) {
				audio_port = json_integer_value(au_port);
				json_t *pt = json_object_get(root, "audio_pt");
				if(pt)
					audio_pt = json_integer_value(pt);
				json_t *ssrc = json_object_get(root, "audio_ssrc");
				if(ssrc)
					audio_ssrc = json_integer_value(ssrc);
			}
			json_t *au_rtcp_port = json_object_get(root, "audio_rtcp_port");
			if(au_rtcp_port)
				audio_rtcp_port = json_integer_value(au_rtcp_port);
			/* Data target */
			json_t *d_port = json_object_get(root, "data_port");
			if(d_port) {
				data_port = json_integer_value(d_port);
			}
			/* Do we need to forward multiple simulcast streams to a single endpoint? */
			gboolean simulcast = FALSE;
			if(json_object_get(root, "simulcast") != NULL)
				simulcast = json_is_true(json_object_get(root, "simulcast"));
			if(simulcast) {
				/* We do, disable the other video ports if they were requested */
				video_port[1] = -1;
				video_port[2] = -1;
			}
			/* Create all the forwarders we need */
			janus_videoroom_rtp_forwarder *f = NULL;
			guint32 audio_handle = 0;
			guint32 video_handle[3] = {0, 0, 0};
			guint32 data_handle = 0;
			janus_mutex_lock(&publisher->streams_mutex);
			if(audio_port > 0) {
				/* FIXME Find the audio stream */
				GList *temp = publisher->streams;
				while(temp) {
					stream = (janus_videoroom_publisher_stream *)temp->data;
					if(stream && stream->type == JANUS_VIDEOROOM_MEDIA_AUDIO) {
						/* FIXME Found */
						break;
					}
					stream = NULL;
					temp = temp->next;
				}
				if(stream == NULL) {
					JANUS_LOG(LOG_WARN, "Couldn't find any audio stream to forward, skipping...\n");
				} else {
					f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
						host, audio_port, audio_rtcp_port, audio_pt, audio_ssrc,
						FALSE, srtp_suite, srtp_crypto, 0, FALSE, FALSE);
					audio_handle = f ? f->stream_id : 0;
					/* Also notify event handlers */
					if(f != NULL && notify_events && gateway->events_is_enabled()) {
						json_t *info = janus_videoroom_rtp_forwarder_summary(f);
						json_object_set_new(info, "event", json_string("rtp_forward"));
						json_object_set_new(info, "room", json_integer(room_id));
						json_object_set_new(info, "publisher_id", json_integer(publisher_id));
						gateway->notify_event(&janus_videoroom_plugin, NULL, info);
					}
				}
			}
			if(video_port[0] > 0 || video_port[1] > 0 || video_port[2] > 0) {
				/* FIXME Find the video stream */
				GList *temp = publisher->streams;
				while(temp) {
					stream = (janus_videoroom_publisher_stream *)temp->data;
					if(stream && stream->type == JANUS_VIDEOROOM_MEDIA_VIDEO) {
						/* FIXME Found */
						break;
					}
					stream = NULL;
					temp = temp->next;
				}
				if(stream == NULL) {
					JANUS_LOG(LOG_WARN, "Couldn't find any video stream to forward, skipping...\n");
				} else {
					if(video_port[0] > 0) {
						f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
							host, video_port[0], video_rtcp_port, video_pt[0], video_ssrc[0],
							simulcast, srtp_suite, srtp_crypto, 0, TRUE, FALSE);
						video_handle[0] = f ? f->stream_id : 0;
						/* Also notify event handlers */
						if(f != NULL && notify_events && gateway->events_is_enabled()) {
							json_t *info = janus_videoroom_rtp_forwarder_summary(f);
							json_object_set_new(info, "event", json_string("rtp_forward"));
							json_object_set_new(info, "room", json_integer(room_id));
							json_object_set_new(info, "publisher_id", json_integer(publisher_id));
							gateway->notify_event(&janus_videoroom_plugin, NULL, info);
						}
					}
					if(video_port[1] > 0) {
						f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
							host, video_port[1], 0, video_pt[1], video_ssrc[1],
							FALSE, srtp_suite, srtp_crypto, 1, TRUE, FALSE);
						video_handle[1] = f ? f->stream_id : 0;
						/* Also notify event handlers */
						if(f != NULL && notify_events && gateway->events_is_enabled()) {
							json_t *info = janus_videoroom_rtp_forwarder_summary(f);
							json_object_set_new(info, "event", json_string("rtp_forward"));
							json_object_set_new(info, "room", json_integer(room_id));
							json_object_set_new(info, "publisher_id", json_integer(publisher_id));
							gateway->notify_event(&janus_videoroom_plugin, NULL, info);
						}
					}
					if(video_port[2] > 0) {
						f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
							host, video_port[2], 0, video_pt[2], video_ssrc[2],
							FALSE, srtp_suite, srtp_crypto, 2, TRUE, FALSE);
						video_handle[2] = f ? f->stream_id : 0;
						/* Also notify event handlers */
						if(f != NULL && notify_events && gateway->events_is_enabled()) {
							json_t *info = janus_videoroom_rtp_forwarder_summary(f);
							json_object_set_new(info, "event", json_string("rtp_forward"));
							json_object_set_new(info, "room", json_integer(room_id));
							json_object_set_new(info, "publisher_id", json_integer(publisher_id));
							gateway->notify_event(&janus_videoroom_plugin, NULL, info);
						}
					}
					janus_videoroom_reqpli(stream, "New RTP forward publisher");
				}
			}
			if(data_port > 0) {
				/* FIXME Find the data stream */
				GList *temp = publisher->streams;
				while(temp) {
					stream = (janus_videoroom_publisher_stream *)temp->data;
					if(stream && stream->type == JANUS_VIDEOROOM_MEDIA_DATA) {
						/* FIXME Found */
						break;
					}
					stream = NULL;
					temp = temp->next;
				}
				if(stream == NULL) {
					JANUS_LOG(LOG_WARN, "Couldn't find any data stream to forward, skipping...\n");
				} else {
					f = janus_videoroom_rtp_forwarder_add_helper(publisher, stream,
						host, data_port, 0, 0, 0, FALSE, 0, NULL, 0, FALSE, TRUE);
					data_handle = f ? f->stream_id : 0;
					/* Also notify event handlers */
					if(f != NULL && notify_events && gateway->events_is_enabled()) {
						json_t *info = janus_videoroom_rtp_forwarder_summary(f);
						json_object_set_new(info, "event", json_string("rtp_forward"));
						json_object_set_new(info, "room", json_integer(room_id));
						json_object_set_new(info, "publisher_id", json_integer(publisher_id));
						gateway->notify_event(&janus_videoroom_plugin, NULL, info);
					}
				}
			}
			janus_mutex_unlock(&publisher->streams_mutex);
			if(audio_handle > 0) {
				json_object_set_new(rtp_stream, "audio_stream_id", json_integer(audio_handle));
				json_object_set_new(rtp_stream, "audio", json_integer(audio_port));
			}
			if(video_handle[0] > 0 || video_handle[1] > 0 || video_handle[2] > 0) {
				/* Done */
				if(video_handle[0] > 0) {
					json_object_set_new(rtp_stream, "video_stream_id", json_integer(video_handle[0]));
					json_object_set_new(rtp_stream, "video", json_integer(video_port[0]));
				}
				if(video_handle[1] > 0) {
					json_object_set_new(rtp_stream, "video_stream_id_2", json_integer(video_handle[1]));
					json_object_set_new(rtp_stream, "video_2", json_integer(video_port[1]));
				}
				if(video_handle[2] > 0) {
					json_object_set_new(rtp_stream, "video_stream_id_3", json_integer(video_handle[2]));
					json_object_set_new(rtp_stream, "video_3", json_integer(video_port[2]));
				}
			}
			if(data_handle > 0) {
				json_object_set_new(rtp_stream, "data_stream_id", json_integer(data_handle));
				json_object_set_new(rtp_stream, "data", json_integer(data_port));
			}
		}
		janus_mutex_unlock(&publisher->rtp_forwarders_mutex);
		janus_mutex_unlock(&videoroom->mutex);
		/* These two unrefs are related to the message handling */
		janus_refcount_decrease(&publisher->ref);
		janus_refcount_decrease(&videoroom->ref);
		json_object_set_new(rtp_stream, "host", json_string(host));
		if(new_forwarders != NULL)
			json_object_set_new(rtp_stream, "forwarders", new_forwarders);
		json_object_set_new(response, "publisher_id", json_integer(publisher_id));
		json_object_set_new(response, "rtp_stream", rtp_stream);
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "videoroom", json_string("rtp_forward"));
		goto prepare_response;
	} else if(!strcasecmp(request_text, "stop_rtp_forward")) {
		JANUS_VALIDATE_JSON_OBJECT(root, stop_rtp_forward_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		if(lock_rtpfwd && admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto prepare_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto prepare_response;
		}
		json_t *room = json_object_get(root, "room");
		json_t *pub_id = json_object_get(root, "publisher_id");
		json_t *id = json_object_get(root, "stream_id");

		guint64 room_id = json_integer_value(room);
		guint64 publisher_id = json_integer_value(pub_id);
		guint32 stream_id = json_integer_value(id);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, TRUE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		janus_mutex_unlock(&rooms_mutex);
		if(error_code != 0)
			goto prepare_response;
		janus_mutex_lock(&videoroom->mutex);
		janus_refcount_increase(&videoroom->ref);
		janus_videoroom_publisher *publisher = g_hash_table_lookup(videoroom->participants, &publisher_id);
		if(publisher == NULL) {
			janus_mutex_unlock(&videoroom->mutex);
			janus_refcount_decrease(&videoroom->ref);
			JANUS_LOG(LOG_ERR, "No such publisher (%"SCNu64")\n", publisher_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", publisher_id);
			goto prepare_response;
		}
		janus_refcount_increase(&publisher->ref);	/* Just to handle the message now */
		janus_mutex_lock(&publisher->rtp_forwarders_mutex);
		/* FIXME Find the forwarder by iterating on all the streams */
		gboolean found = FALSE;
		GList *temp = publisher->streams;
		while(temp) {
			janus_videoroom_publisher_stream *stream = (janus_videoroom_publisher_stream *)temp->data;
			janus_mutex_lock(&stream->rtp_forwarders_mutex);
			if(g_hash_table_remove(stream->rtp_forwarders, GUINT_TO_POINTER(stream_id))) {
				janus_mutex_unlock(&stream->rtp_forwarders_mutex);
				/* Found, remove from global index too */
				g_hash_table_remove(publisher->rtp_forwarders, GUINT_TO_POINTER(stream_id));
				found = TRUE;
				break;
			}
			janus_mutex_unlock(&stream->rtp_forwarders_mutex);
			temp = temp->next;
		}
		janus_mutex_unlock(&publisher->rtp_forwarders_mutex);
		janus_refcount_decrease(&publisher->ref);
		janus_mutex_unlock(&videoroom->mutex);
		janus_refcount_decrease(&videoroom->ref);
		if(!found) {
			JANUS_LOG(LOG_ERR, "No such stream (%"SCNu32")\n", stream_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such stream (%"SCNu32")", stream_id);
			goto prepare_response;
		}
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("stop_rtp_forward"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "publisher_id", json_integer(publisher_id));
		json_object_set_new(response, "stream_id", json_integer(stream_id));
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("stop_rtp_forward"));
			json_object_set_new(info, "room", json_integer(room_id));
			json_object_set_new(info, "publisher_id", json_integer(publisher_id));
			json_object_set_new(info, "stream_id", json_integer(stream_id));
			gateway->notify_event(&janus_videoroom_plugin, NULL, info);
		}
		goto prepare_response;
	} else if(!strcasecmp(request_text, "exists")) {
		/* Check whether a given room exists or not, returns true/false */
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		gboolean room_exists = g_hash_table_contains(rooms, &room_id);
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("success"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "exists", room_exists ? json_true() : json_false());
		goto prepare_response;
	} else if(!strcasecmp(request_text, "allowed")) {
		JANUS_LOG(LOG_VERB, "Attempt to edit the list of allowed participants in an existing videoroom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, allowed_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *action = json_object_get(root, "action");
		json_t *room = json_object_get(root, "room");
		json_t *allowed = json_object_get(root, "allowed");
		const char *action_text = json_string_value(action);
		if(strcasecmp(action_text, "enable") && strcasecmp(action_text, "disable") &&
				strcasecmp(action_text, "add") && strcasecmp(action_text, "remove")) {
			JANUS_LOG(LOG_ERR, "Unsupported action '%s' (allowed)\n", action_text);
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Unsupported action '%s' (allowed)", action_text);
			goto prepare_response;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, TRUE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		janus_refcount_increase(&videoroom->ref);
		janus_mutex_unlock(&rooms_mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(videoroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_refcount_decrease(&videoroom->ref);
			goto prepare_response;
		}
		if(!strcasecmp(action_text, "enable")) {
			JANUS_LOG(LOG_VERB, "Enabling the check on allowed authorization tokens for room %"SCNu64"\n", room_id);
			videoroom->check_allowed = TRUE;
		} else if(!strcasecmp(action_text, "disable")) {
			JANUS_LOG(LOG_VERB, "Disabling the check on allowed authorization tokens for room %"SCNu64" (free entry)\n", room_id);
			videoroom->check_allowed = FALSE;
		} else {
			gboolean add = !strcasecmp(action_text, "add");
			if(allowed) {
				/* Make sure the "allowed" array only contains strings */
				gboolean ok = TRUE;
				if(json_array_size(allowed) > 0) {
					size_t i = 0;
					for(i=0; i<json_array_size(allowed); i++) {
						json_t *a = json_array_get(allowed, i);
						if(!a || !json_is_string(a)) {
							ok = FALSE;
							break;
						}
					}
				}
				if(!ok) {
					JANUS_LOG(LOG_ERR, "Invalid element in the allowed array (not a string)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element in the allowed array (not a string)");
					janus_refcount_decrease(&videoroom->ref);
					goto prepare_response;
				}
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					const char *token = json_string_value(json_array_get(allowed, i));
					if(add) {
						if(!g_hash_table_lookup(videoroom->allowed, token))
							g_hash_table_insert(videoroom->allowed, g_strdup(token), GINT_TO_POINTER(TRUE));
					} else {
						g_hash_table_remove(videoroom->allowed, token);
					}
				}
			}
		}
		/* Prepare response */
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("success"));
		json_object_set_new(response, "room", json_integer(videoroom->room_id));
		json_t *list = json_array();
		if(strcasecmp(action_text, "disable")) {
			if(g_hash_table_size(videoroom->allowed) > 0) {
				GHashTableIter iter;
				gpointer key;
				g_hash_table_iter_init(&iter, videoroom->allowed);
				while(g_hash_table_iter_next(&iter, &key, NULL)) {
					char *token = key;
					json_array_append_new(list, json_string(token));
				}
			}
			json_object_set_new(response, "allowed", list);
		}
		/* Done */
		janus_refcount_decrease(&videoroom->ref);
		JANUS_LOG(LOG_VERB, "VideoRoom room allowed list updated\n");
		goto prepare_response;
	} else if(!strcasecmp(request_text, "kick")) {
		JANUS_LOG(LOG_VERB, "Attempt to kick a participant from an existing videoroom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, kick_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		json_t *id = json_object_get(root, "id");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, TRUE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		janus_refcount_increase(&videoroom->ref);
		janus_mutex_lock(&videoroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(videoroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&videoroom->mutex);
			janus_refcount_decrease(&videoroom->ref);
			goto prepare_response;
		}
		guint64 user_id = json_integer_value(id);
		janus_videoroom_publisher *participant = g_hash_table_lookup(videoroom->participants, &user_id);
		if(participant == NULL) {
			janus_mutex_unlock(&videoroom->mutex);
			janus_refcount_decrease(&videoroom->ref);
			JANUS_LOG(LOG_ERR, "No such user %"SCNu64" in room %"SCNu64"\n", user_id, room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such user %"SCNu64" in room %"SCNu64, user_id, room_id);
			goto prepare_response;
		}
		if(participant->kicked) {
			/* Already kicked */
			janus_mutex_unlock(&videoroom->mutex);
			janus_refcount_decrease(&videoroom->ref);
			response = json_object();
			json_object_set_new(response, "videoroom", json_string("success"));
			/* Done */
			goto prepare_response;
		}
		participant->kicked = TRUE;
		participant->session->started = FALSE;
		/* Prepare an event for this */
		json_t *kicked = json_object();
		json_object_set_new(kicked, "videoroom", json_string("event"));
		json_object_set_new(kicked, "room", json_integer(participant->room_id));
		json_object_set_new(kicked, "leaving", json_string("ok"));
		json_object_set_new(kicked, "reason", json_string("kicked"));
		int ret = gateway->push_event(participant->session->handle, &janus_videoroom_plugin, NULL, kicked, NULL);
		JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		json_decref(kicked);
		janus_mutex_unlock(&videoroom->mutex);
		/* If this room requires valid private_id values, we can kick subscriptions too */
		if(videoroom->require_pvtid && participant->subscriptions != NULL) {
			/* Iterate on the subscriptions we know this user has */
			janus_mutex_lock(&participant->subscribers_mutex);
			GSList *s = participant->subscriptions;
			while(s) {
				janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)s->data;
				if(subscriber) {
					subscriber->kicked = TRUE;
					/* FIXME We should also close the PeerConnection, but we risk race conditions if we do it here,
					 * so for now we mark the subscriber as kicked and prevent it from getting any media after this */
				}
				s = s->next;
			}
			janus_mutex_unlock(&participant->subscribers_mutex);
		}
		/* This publisher is leaving, tell everybody */
		janus_videoroom_leave_or_unpublish(participant, TRUE, TRUE);
		/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
		if(participant && participant->session)
			gateway->close_pc(participant->session->handle);
		JANUS_LOG(LOG_INFO, "Kicked user %"SCNu64" from room %"SCNu64"\n", user_id, room_id);
		/* Prepare response */
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("success"));
		/* Done */
		janus_refcount_decrease(&videoroom->ref);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "listparticipants")) {
		/* List all participants in a room, specifying whether they're publishers or just attendees */
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, FALSE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		janus_mutex_unlock(&rooms_mutex);
		if(error_code != 0)
			goto prepare_response;
		janus_refcount_increase(&videoroom->ref);
		/* Return a list of all participants (whether they're publishing or not) */
		json_t *list = json_array();
		GHashTableIter iter;
		gpointer value;
		janus_mutex_lock(&videoroom->mutex);
		g_hash_table_iter_init(&iter, videoroom->participants);
		while (!g_atomic_int_get(&videoroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom_publisher *p = value;
			json_t *pl = json_object();
			json_object_set_new(pl, "id", json_integer(p->user_id));
			if(p->display)
				json_object_set_new(pl, "display", json_string(p->display));
			json_object_set_new(pl, "publisher", p->session->started ? json_true() : json_false());
			/* FIXME To see if the participant is talking, we need to find the audio stream(s) */
			if(p->session->started) {
				gboolean found = FALSE, talking = FALSE;
				GList *temp = p->streams;
				while(temp) {
					janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
					if(ps && ps->type == JANUS_VIDEOROOM_MEDIA_AUDIO &&
							ps->audio_level_extmap_id > 0) {
						found = TRUE;
						talking |= ps->talking;
					}
					temp = temp->next;
				}
				if(found)
					json_object_set_new(pl, "talking", talking ? json_true() : json_false());
			}
			json_array_append_new(list, pl);
		}
		janus_mutex_unlock(&videoroom->mutex);
		janus_refcount_decrease(&videoroom->ref);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("participants"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "participants", list);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "listforwarders")) {
		/* List all forwarders in a room */
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = g_hash_table_lookup(rooms, &room_id);
		if(videoroom == NULL) {
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		if(g_atomic_int_get(&videoroom->destroyed)) {
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(videoroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		/* Return a list of all forwarders */
		json_t *list = json_array();
		GHashTableIter iter;
		gpointer value;
		janus_mutex_lock(&videoroom->mutex);
		g_hash_table_iter_init(&iter, videoroom->participants);
		while (!g_atomic_int_get(&videoroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom_publisher *p = value;
			janus_videoroom_publisher_stream *ps = NULL;
			json_t *pl = json_object();
			json_object_set_new(pl, "publisher_id", json_integer(p->user_id));
			if(p->display)
				json_object_set_new(pl, "display", json_string(p->display));
			json_t *flist = json_array();
			/* FIXME We need to iterate on all media streams */
			GList *temp = p->streams;
			while(temp) {
				ps = (janus_videoroom_publisher_stream *)temp->data;
				janus_mutex_lock(&ps->rtp_forwarders_mutex);
				if(g_hash_table_size(ps->rtp_forwarders) == 0) {
					janus_mutex_unlock(&ps->rtp_forwarders_mutex);
					temp = temp->next;
					continue;
				}
				GHashTableIter iter_f;
				gpointer key_f, value_f;
				g_hash_table_iter_init(&iter_f, ps->rtp_forwarders);
				while(g_hash_table_iter_next(&iter_f, &key_f, &value_f)) {
					janus_videoroom_rtp_forwarder *rpv = value_f;
					/* Return a different, media-agnostic, format */
					json_t *fl = janus_videoroom_rtp_forwarder_summary(rpv);
					json_array_append_new(flist, fl);
				}
				janus_mutex_unlock(&ps->rtp_forwarders_mutex);
				json_object_set_new(pl, "forwarders", flist);
				temp = temp->next;
			}
			json_array_append_new(list, pl);
		}
		janus_mutex_unlock(&videoroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("forwarders"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "publishers", list);
		goto prepare_response;
	} else {
		/* Not a request we recognize, don't do anything */
		return NULL;
	}

prepare_response:
		{
			if(error_code == 0 && !response) {
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid response");
			}
			if(error_code != 0) {
				/* Prepare JSON error event */
				response = json_object();
				json_object_set_new(response, "videoroom", json_string("event"));
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}

}

struct janus_plugin_result *janus_videoroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);

	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	janus_mutex_lock(&sessions_mutex);
	janus_videoroom_session *session = janus_videoroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "No session associated with this handle...");
		goto plugin_response;
	}
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_ERR, "Session has already been marked as destroyed...\n");
		error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been marked as destroyed...");
		goto plugin_response;
	}

	if(message == NULL) {
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = JANUS_VIDEOROOM_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");
		goto plugin_response;
	}
	if(!json_is_object(root)) {
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = JANUS_VIDEOROOM_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");
		goto plugin_response;
	}
	/* Get the request first */
	JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	json_t *request = json_object_get(root, "request");
	/* Some requests ('create', 'destroy', 'exists', 'list') can be handled synchronously */
	const char *request_text = json_string_value(request);
	/* We have a separate method to process synchronous requests, as those may
	 * arrive from the Admin API as well, and so we handle them the same way */
	response = janus_videoroom_process_synchronous_request(session, root);
	if(response != NULL) {
		/* We got a response, send it back */
		goto plugin_response;
	} else if(!strcasecmp(request_text, "join") || !strcasecmp(request_text, "joinandconfigure")
			|| !strcasecmp(request_text, "configure") || !strcasecmp(request_text, "publish") || !strcasecmp(request_text, "unpublish")
			|| !strcasecmp(request_text, "start") || !strcasecmp(request_text, "pause") || !strcasecmp(request_text, "switch")
			|| !strcasecmp(request_text, "subscribe") || !strcasecmp(request_text, "unsubscribe") || !strcasecmp(request_text, "leave")) {
		/* These messages are handled asynchronously */

		janus_videoroom_message *msg = g_malloc(sizeof(janus_videoroom_message));
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->jsep = jsep;
		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if(error_code == 0 && !response) {
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid response");
			}
			if(error_code != 0) {
				/* Prepare JSON error event */
				json_t *event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "error_code", json_integer(error_code));
				json_object_set_new(event, "error", json_string(error_cause));
				response = event;
			}
			if(root != NULL)
				json_decref(root);
			if(jsep != NULL)
				json_decref(jsep);
			g_free(transaction);

			if(session != NULL)
				janus_refcount_decrease(&session->ref);
			return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
		}

}

json_t *janus_videoroom_handle_admin_message(json_t *message) {
	/* Some requests (e.g., 'create' and 'destroy') can be handled via Admin API */
	int error_code = 0;
	char error_cause[512];
	json_t *response = NULL;

	JANUS_VALIDATE_JSON_OBJECT(message, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto admin_response;
	json_t *request = json_object_get(message, "request");
	const char *request_text = json_string_value(request);
	if((response = janus_videoroom_process_synchronous_request(NULL, message)) != NULL) {
		/* We got a response, send it back */
		goto admin_response;
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

admin_response:
		{
			if(!response) {
				/* Prepare JSON error event */
				response = json_object();
				json_object_set_new(response, "streaming", json_string("event"));
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}

}

void janus_videoroom_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_VIDEOROOM_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_videoroom_session *session = janus_videoroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	g_atomic_int_set(&session->hangingup, 0);

	/* Media relaying can start now */
	session->started = TRUE;
	if(session->participant) {
		/* If this is a publisher, notify all subscribers about the fact they can
		 * now subscribe; if this is a subscriber, instead, ask the publisher a PLI */
		if(session->participant_type == janus_videoroom_p_type_publisher) {
			janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher(session);
			/* Notify all other participants that there's a new boy in town */
			json_t *list = json_array();
			json_t *pl = json_object();
			json_object_set_new(pl, "id", json_integer(participant->user_id));
			if(participant->display)
				json_object_set_new(pl, "display", json_string(participant->display));
			/* Add proper info on all the streams */
			gboolean audio_added = FALSE, video_added = FALSE;
			json_t *media = json_array();
			GList *temp = participant->streams;
			while(temp) {
				janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
				json_t *info = json_object();
				json_object_set_new(info, "type", json_string(janus_videoroom_media_str(ps->type)));
				json_object_set_new(info, "mindex", json_integer(ps->mindex));
				json_object_set_new(info, "mid", json_string(ps->mid));
				if(ps->description)
					json_object_set_new(info, "description", json_string(ps->description));
				if(ps->type == JANUS_VIDEOROOM_MEDIA_AUDIO) {
					json_object_set_new(info, "codec", json_string(janus_audiocodec_name(ps->acodec)));
					/* FIXME For backwards compatibility, we need audio_codec in the global info */
					if(!audio_added) {
						audio_added = TRUE;
						json_object_set_new(pl, "audio_codec", json_string(janus_audiocodec_name(ps->acodec)));
					}
				} else if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO) {
					json_object_set_new(info, "codec", json_string(janus_videocodec_name(ps->vcodec)));
					/* FIXME For backwards compatibility, we need video_codec in the global info */
					if(!video_added) {
						video_added = TRUE;
						json_object_set_new(pl, "video_codec", json_string(janus_videocodec_name(ps->vcodec)));
					}
					if(ps->simulcast)
						json_object_set_new(info, "simulcast", json_true());
					if(ps->svc)
						json_object_set_new(info, "svc", json_true());
				}
				json_array_append_new(media, info);
				temp = temp->next;
			}
			json_object_set_new(pl, "streams", media);
			json_array_append_new(list, pl);
			json_t *pub = json_object();
			json_object_set_new(pub, "videoroom", json_string("event"));
			json_object_set_new(pub, "room", json_integer(participant->room_id));
			json_object_set_new(pub, "publishers", list);
			janus_mutex_lock(&participant->room->mutex);
			janus_videoroom_notify_participants(participant, pub);
			janus_mutex_unlock(&participant->room->mutex);
			json_decref(pub);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("published"));
				json_object_set_new(info, "room", json_integer(participant->room_id));
				json_object_set_new(info, "id", json_integer(participant->user_id));
				gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
			}
			janus_refcount_decrease(&participant->ref);
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			janus_videoroom_subscriber *s = (janus_videoroom_subscriber *)session->participant;
			if(s && s->streams) {
				/* Send a PLI for all the video streams we subscribed to */
				GList *temp = s->streams;
				while(temp) {
					janus_videoroom_subscriber_stream *ss = (janus_videoroom_subscriber_stream *)temp->data;
					janus_videoroom_publisher_stream *ps = ss->publisher_streams ? ss->publisher_streams->data : NULL;
					if(ps && ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO && ps->publisher && ps->publisher->session) {
						janus_videoroom_reqpli(ps, "New subscriber available");
					}
					temp = temp->next;
				}
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("subscribed"));
					json_object_set_new(info, "room", json_integer(s->room_id));
					/* TODO Fix the event to event handlers, we don't have a single feed anymore */
					//~ json_object_set_new(info, "feed", json_integer(p->user_id));
					gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
				}
			}
		}
	}
	janus_mutex_unlock(&sessions_mutex);
}

void janus_videoroom_incoming_rtp(janus_plugin_session *handle, int mindex, gboolean video, char *buf, int len) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session || g_atomic_int_get(&session->destroyed) || session->participant_type != janus_videoroom_p_type_publisher)
		return;
	janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher_nodebug(session);
	if(participant == NULL)
		return;
	if(g_atomic_int_get(&participant->destroyed) || participant->kicked || !participant->streams || participant->room == NULL) {
		janus_videoroom_publisher_dereference_nodebug(participant);
		return;
	}
	janus_videoroom *videoroom = participant->room;

	/* Find the stream this packet belongs to */
	janus_mutex_lock(&participant->streams_mutex);
	janus_videoroom_publisher_stream *ps = g_hash_table_lookup(participant->streams_byid, GINT_TO_POINTER(mindex));
	janus_mutex_unlock(&participant->streams_mutex);
	if(ps == NULL) {
		/* No stream..? */
		janus_videoroom_publisher_dereference_nodebug(participant);
		return;
	}

	/* In case this is an audio packet and we're doing talk detection, check the audio level extension */
	if(!video && videoroom->audiolevel_event && ps->active && ps->audio_level_extmap_id > 0) {
		int level = 0;
		if(janus_rtp_header_extension_parse_audio_level(buf, len, ps->audio_level_extmap_id, &level) == 0) {
			ps->audio_dBov_sum += level;
			ps->audio_active_packets++;
			ps->audio_dBov_level = level;
			if(ps->audio_active_packets > 0 && ps->audio_active_packets == videoroom->audio_active_packets) {
				gboolean notify_talk_event = FALSE;
				if((float)ps->audio_dBov_sum/(float)ps->audio_active_packets < videoroom->audio_level_average) {
					/* Participant talking, should we notify all participants? */
					if(!ps->talking)
						notify_talk_event = TRUE;
					ps->talking = TRUE;
				} else {
					/* Participant not talking anymore, should we notify all participants? */
					if(ps->talking)
						notify_talk_event = TRUE;
					ps->talking = FALSE;
				}
				ps->audio_active_packets = 0;
				ps->audio_dBov_sum = 0;
				/* Only notify in case of state changes */
				if(notify_talk_event) {
					janus_mutex_lock(&videoroom->mutex);
					json_t *event = json_object();
					json_object_set_new(event, "videoroom", json_string(ps->talking ? "talking" : "stopped-talking"));
					json_object_set_new(event, "room", json_integer(videoroom->room_id));
					json_object_set_new(event, "id", json_integer(participant->user_id));
					/* FIXME Which other properties should we notify here? Just mindex and mid? */
					json_object_set_new(event, "mindex", json_integer(ps->mindex));
					json_object_set_new(event, "mid", json_string(ps->mid));
					janus_videoroom_notify_participants(participant, event);
					json_decref(event);
					janus_mutex_unlock(&videoroom->mutex);
					/* Also notify event handlers */
					if(notify_events && gateway->events_is_enabled()) {
						json_t *info = json_object();
						json_object_set_new(info, "videoroom", json_string(ps->talking ? "talking" : "stopped-talking"));
						json_object_set_new(info, "room", json_integer(videoroom->room_id));
						json_object_set_new(info, "id", json_integer(participant->user_id));
						/* FIXME Which other properties should we notify here? Just mindex and mid? */
						json_object_set_new(event, "mindex", json_integer(ps->mindex));
						json_object_set_new(event, "mid", json_string(ps->mid));
						gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
					}
				}
			}
		}
	}

	if(ps->active) {
		janus_rtp_header *rtp = (janus_rtp_header *)buf;
		int sc = video ? 0 : -1;
		/* Check if we're simulcasting, and if so, keep track of the "layer" */
		if(video && ps->simulcast) {
			uint32_t ssrc = ntohl(rtp->ssrc);
			if(ssrc == ps->vssrc[0])
				sc = 0;
			else if(ssrc == ps->vssrc[1])
				sc = 1;
			else if(ssrc == ps->vssrc[2])
				sc = 2;
			else if(ps->rid_extmap_id > 0) {
				/* We may not know the SSRC yet, try the rid RTP extension */
				char sdes_item[16];
				if(janus_rtp_header_extension_parse_rid(buf, len, ps->rid_extmap_id, sdes_item, sizeof(sdes_item)) == 0) {
					if(ps->rid[2] != NULL && !strcmp(ps->rid[2], sdes_item)) {
						ps->vssrc[0] = ssrc;
						sc = 0;
					} else if(ps->rid[1] != NULL && !strcmp(ps->rid[1], sdes_item)) {
						ps->vssrc[1] = ssrc;
						sc = 1;
					} else if(ps->rid[0] != NULL && !strcmp(ps->rid[0], sdes_item)) {
						ps->vssrc[2] = ssrc;
						sc = 2;
					}
				}
			}
		}
		/* Forward RTP to the appropriate port for the rtp_forwarders associated with this publisher, if there are any */
		janus_mutex_lock(&ps->rtp_forwarders_mutex);
		if(participant->srtp_contexts && g_hash_table_size(participant->srtp_contexts) > 0) {
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, participant->srtp_contexts);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_videoroom_srtp_context *srtp_ctx = (janus_videoroom_srtp_context *)value;
				srtp_ctx->slen = 0;
			}
		}
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, ps->rtp_forwarders);
		while(participant->udp_sock > 0 && g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom_rtp_forwarder *rtp_forward = (janus_videoroom_rtp_forwarder *)value;
			if(rtp_forward->is_data || (video && !rtp_forward->is_video) || (!video && rtp_forward->is_video))
				continue;
			/* Backup the RTP header info, as we may rewrite part of it */
			uint32_t seq_number = ntohs(rtp->seq_number);
			uint32_t timestamp = ntohl(rtp->timestamp);
			int pt = rtp->type;
			uint32_t ssrc = ntohl(rtp->ssrc);
			/* First of all, check if we're simulcasting and if we need to forward or ignore this frame */
			if(video && !rtp_forward->simulcast && rtp_forward->substream != sc) {
				continue;
			} else if(video && rtp_forward->simulcast) {
				/* This is video and we're simulcasting, check if we need to forward this frame */
				if(!janus_rtp_simulcasting_context_process_rtp(&rtp_forward->sim_context,
						buf, len, ps->vssrc, ps->rid, ps->vcodec, &rtp_forward->context))
					continue;
				janus_rtp_header_update(rtp, &rtp_forward->context, TRUE);
				/* By default we use a fixed SSRC (it may be overwritten later) */
				rtp->ssrc = htonl(participant->user_id & 0xffffffff);
			}
			/* Check if payload type and/or SSRC need to be overwritten for this forwarder */
			if(rtp_forward->payload_type > 0)
				rtp->type = rtp_forward->payload_type;
			if(rtp_forward->ssrc > 0)
				rtp->ssrc = htonl(rtp_forward->ssrc);
			/* Check if this is an RTP or SRTP forwarder */
			if(!rtp_forward->is_srtp) {
				/* Plain RTP */
				if(sendto(participant->udp_sock, buf, len, 0, (struct sockaddr*)&rtp_forward->serv_addr, sizeof(rtp_forward->serv_addr)) < 0) {
					JANUS_LOG(LOG_HUGE, "Error forwarding RTP %s packet for %s... %s (len=%d)...\n",
						(video ? "video" : "audio"), participant->display, strerror(errno), len);
				}
			} else {
				/* SRTP: check if we already encrypted the packet before */
				if(rtp_forward->srtp_ctx->slen == 0) {
					memcpy(&rtp_forward->srtp_ctx->sbuf, buf, len);
					int protected = len;
					int res = srtp_protect(rtp_forward->srtp_ctx->ctx, &rtp_forward->srtp_ctx->sbuf, &protected);
					if(res != srtp_err_status_ok) {
						janus_rtp_header *header = (janus_rtp_header *)&rtp_forward->srtp_ctx->sbuf;
						guint32 timestamp = ntohl(header->timestamp);
						guint16 seq = ntohs(header->seq_number);
						JANUS_LOG(LOG_ERR, "Error encrypting %s packet for %s... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
							(video ? "Video" : "Audio"), participant->display, janus_srtp_error_str(res), len, protected, timestamp, seq);
					} else {
						rtp_forward->srtp_ctx->slen = protected;
					}
				}
				if(rtp_forward->srtp_ctx->slen > 0 && sendto(participant->udp_sock, rtp_forward->srtp_ctx->sbuf, rtp_forward->srtp_ctx->slen, 0, (struct sockaddr*)&rtp_forward->serv_addr, sizeof(rtp_forward->serv_addr)) < 0) {
					JANUS_LOG(LOG_HUGE, "Error forwarding SRTP %s packet for %s... %s (len=%d)...\n",
						(video ? "video" : "audio"), participant->display, strerror(errno), rtp_forward->srtp_ctx->slen);
				}
			}
			/* Restore original values of payload type and SSRC before going on */
			rtp->type = pt;
			rtp->ssrc = htonl(ssrc);
			rtp->timestamp = htonl(timestamp);
			rtp->seq_number = htons(seq_number);
		}
		janus_mutex_unlock(&ps->rtp_forwarders_mutex);
		/* Set the payload type of the publisher */
		rtp->type = ps->pt;
		/* Save the frame if we're recording */
		if(!video || !ps->simulcast) {
			janus_recorder_save_frame(ps->rc, buf, len);
		} else {
			/* We're simulcasting, save the best video quality */
			gboolean save = janus_rtp_simulcasting_context_process_rtp(&ps->rec_simctx,
				buf, len, ps->vssrc, ps->rid, ps->vcodec, &ps->rec_ctx);
			if(save) {
				uint32_t seq_number = ntohs(rtp->seq_number);
				uint32_t timestamp = ntohl(rtp->timestamp);
				uint32_t ssrc = ntohl(rtp->ssrc);
				janus_rtp_header_update(rtp, &ps->rec_ctx, TRUE);
				/* We use a fixed SSRC for the whole recording */
				rtp->ssrc = htonl(participant->user_id & 0xffffffff);
				janus_recorder_save_frame(ps->rc, buf, len);
				/* Restore the header, as it will be needed by subscribers */
				rtp->ssrc = htonl(ssrc);
				rtp->timestamp = htonl(timestamp);
				rtp->seq_number = htons(seq_number);
			}
		}
		/* Done, relay it */
		janus_videoroom_rtp_relay_packet packet;
		packet.source = ps;
		packet.data = rtp;
		packet.length = len;
		packet.is_video = video;
		packet.svc = FALSE;
		if(video && ps->svc) {
			/* We're doing SVC: let's parse this packet to see which layers are there */
			int plen = 0;
			char *payload = janus_rtp_payload(buf, len, &plen);
			if(payload == NULL)
				return;
			uint8_t pbit = 0, dbit = 0, ubit = 0, bbit = 0, ebit = 0;
			int found = 0, spatial_layer = 0, temporal_layer = 0;
			if(janus_vp9_parse_svc(payload, plen, &found, &spatial_layer, &temporal_layer, &pbit, &dbit, &ubit, &bbit, &ebit) == 0) {
				if(found) {
					packet.svc = TRUE;
					packet.spatial_layer = spatial_layer;
					packet.temporal_layer = temporal_layer;
					packet.pbit = pbit;
					packet.dbit = dbit;
					packet.ubit = ubit;
					packet.bbit = bbit;
					packet.ebit = ebit;
					/* Update the stream properties, if needed */
					if(!ps->svc)
						ps->svc = TRUE;
				}
			}
		}
		packet.ssrc[0] = (sc != -1 ? ps->vssrc[0] : 0);
		packet.ssrc[1] = (sc != -1 ? ps->vssrc[1] : 0);
		packet.ssrc[2] = (sc != -1 ? ps->vssrc[2] : 0);
		/* Backup the actual timestamp and sequence number set by the publisher, in case switching is involved */
		packet.timestamp = ntohl(packet.data->timestamp);
		packet.seq_number = ntohs(packet.data->seq_number);
		/* Go: some viewers may decide to drop the packet, but that's up to them */
		janus_mutex_lock_nodebug(&ps->subscribers_mutex);
		g_slist_foreach(ps->subscribers, janus_videoroom_relay_rtp_packet, &packet);
		janus_mutex_unlock_nodebug(&ps->subscribers_mutex);

		/* Check if we need to send any REMB or PLI back to this publisher */
		if(video && ps->active) {
			/* Did we send a REMB already, or is it time to send one? */
			gboolean send_remb = FALSE;
			if(participant->remb_latest == 0 && participant->remb_startup > 0) {
				/* Still in the starting phase, send the ramp-up REMB feedback */
				send_remb = TRUE;
			} else if(participant->remb_latest > 0 && janus_get_monotonic_time()-participant->remb_latest >= 5*G_USEC_PER_SEC) {
				/* 5 seconds have passed since the last REMB, send a new one */
				send_remb = TRUE;
			}

			if(send_remb && participant->bitrate) {
				/* We send a few incremental REMB messages at startup */
				uint32_t bitrate = participant->bitrate;
				if(participant->remb_startup > 0) {
					bitrate = bitrate/participant->remb_startup;
					participant->remb_startup--;
				}
				JANUS_LOG(LOG_VERB, "Sending REMB (%s, %"SCNu32")\n", participant->display, bitrate);
				char rtcpbuf[24];
				janus_rtcp_remb((char *)(&rtcpbuf), 24, bitrate);
				gateway->relay_rtcp(handle, -1, video, rtcpbuf, 24);
				if(participant->remb_startup == 0)
					participant->remb_latest = janus_get_monotonic_time();
			}
			/* Generate PLI too, if needed */
			if(video && ps->active && (videoroom->pli_freq > 0)) {
				/* We generate RTCP every tot seconds/frames */
				gint64 now = janus_get_monotonic_time();
				/* First check if this is a keyframe, though: if so, we reset the timer */
				int plen = 0;
				char *payload = janus_rtp_payload(buf, len, &plen);
				if(payload == NULL)
					return;
				if(ps->vcodec == JANUS_VIDEOCODEC_VP8) {
					if(janus_vp8_is_keyframe(payload, plen))
						ps->pli_latest = now;
				} else if(ps->vcodec == JANUS_VIDEOCODEC_VP9) {
					if(janus_vp9_is_keyframe(payload, plen))
						ps->pli_latest = now;
				} else if(ps->vcodec == JANUS_VIDEOCODEC_H264) {
					if(janus_h264_is_keyframe(payload, plen))
						ps->pli_latest = now;
				}
				if((now-ps->pli_latest) >= ((gint64)videoroom->pli_freq*G_USEC_PER_SEC)) {
					/* We send a PLI every tot seconds */
					janus_videoroom_reqpli(ps, "Regular keyframe request");
				}
			}
		}
	}
	janus_videoroom_publisher_dereference_nodebug(participant);
}

void janus_videoroom_incoming_rtcp(janus_plugin_session *handle, int mindex, gboolean video, char *buf, int len) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* A subscriber sent some RTCP, check what it is and if we need to forward it to the publisher */
		janus_videoroom_subscriber *s = (janus_videoroom_subscriber *)session->participant;
		if(s == NULL || g_atomic_int_get(&s->destroyed))
			return;
		/* Find the stream this packet belongs to */
		janus_mutex_lock(&s->streams_mutex);
		janus_videoroom_subscriber_stream *ss = g_hash_table_lookup(s->streams_byid, GINT_TO_POINTER(mindex));
		janus_mutex_unlock(&s->streams_mutex);
		if(ss == NULL || ss->publisher_streams == NULL) {
			/* No stream..? */
			return;
		}
		janus_videoroom_publisher_stream *ps = ss->publisher_streams ? ss->publisher_streams->data : NULL;
		if(ps->type != JANUS_VIDEOROOM_MEDIA_VIDEO)
			return;		/* The only feedback we handle is video related anyway... */
		if(janus_rtcp_has_fir(buf, len) || janus_rtcp_has_pli(buf, len)) {
			/* We got a FIR or PLI, forward a PLI to the publisher */
			janus_videoroom_publisher *p = ps->publisher;
			if(p && p->session)
				janus_videoroom_reqpli(ps, "PLI from subscriber");
		}
		uint32_t bitrate = janus_rtcp_get_remb(buf, len);
		if(bitrate > 0) {
			/* FIXME We got a REMB from this subscriber, should we do something about it? */
		}
	}
}

void janus_videoroom_incoming_data(janus_plugin_session *handle, char *label, char *buf, int len) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
		return;
	if(buf == NULL || len <= 0)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session || g_atomic_int_get(&session->destroyed) || session->participant_type != janus_videoroom_p_type_publisher)
		return;
	janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher_nodebug(session);
	if(participant == NULL)
		return;
	if(g_atomic_int_get(&participant->destroyed) || participant->data_mindex < 0 || !participant->streams || participant->kicked) {
		janus_videoroom_publisher_dereference_nodebug(participant);
		return;
	}
	/* Find the stream this packet belongs to */
	janus_mutex_lock(&participant->streams_mutex);
	janus_videoroom_publisher_stream *ps = g_hash_table_lookup(participant->streams_byid, GINT_TO_POINTER(participant->data_mindex));
	janus_mutex_unlock(&participant->streams_mutex);
	if(ps == NULL || !ps->active) {
		/* No or inactive stream..? */
		janus_videoroom_publisher_dereference_nodebug(participant);
		return;
	}

	/* Any forwarder involved? */
	janus_mutex_lock(&ps->rtp_forwarders_mutex);
	/* Forward RTP to the appropriate port for the rtp_forwarders associated with this publisher, if there are any */
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, ps->rtp_forwarders);
	while(participant->udp_sock > 0 && g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_videoroom_rtp_forwarder* rtp_forward = (janus_videoroom_rtp_forwarder*)value;
		if(rtp_forward->is_data) {
			if(sendto(participant->udp_sock, buf, len, 0, (struct sockaddr*)&rtp_forward->serv_addr, sizeof(rtp_forward->serv_addr)) < 0) {
				JANUS_LOG(LOG_HUGE, "Error forwarding data packet for %s... %s (len=%d)...\n",
					participant->display, strerror(errno), len);
			}
		}
	}
	janus_mutex_unlock(&ps->rtp_forwarders_mutex);
	/* Get a string out of the data */
	char *text = g_malloc(len+1);
	memcpy(text, buf, len);
	*(text+len) = '\0';
	JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes) to forward: %s\n", strlen(text), text);
	/* Save the message if we're recording */
	janus_recorder_save_frame(ps->rc, text, strlen(text));
	/* Relay to all subscribers */
	janus_videoroom_data_relay_packet packet;
	packet.source = ps;
	packet.text = text;
	janus_mutex_lock_nodebug(&ps->subscribers_mutex);
	g_slist_foreach(ps->subscribers, janus_videoroom_relay_data_packet, &packet);
	janus_mutex_unlock_nodebug(&ps->subscribers_mutex);
	g_free(text);
	janus_videoroom_publisher_dereference_nodebug(participant);
}

void janus_videoroom_slow_link(janus_plugin_session *handle, int mindex, gboolean video, gboolean uplink) {
	/* The core is informing us that our peer got too many NACKs, are we pushing media too hard? */
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_videoroom_session *session = janus_videoroom_lookup_session(handle);
	if(!session || g_atomic_int_get(&session->destroyed) || !session->participant) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* Check if it's an uplink (publisher) or downlink (viewer) issue */
	if(session->participant_type == janus_videoroom_p_type_publisher) {
		if(!uplink) {
			janus_videoroom_publisher *publisher = janus_videoroom_session_get_publisher(session);
			if(publisher == NULL || g_atomic_int_get(&publisher->destroyed)) {
				janus_refcount_decrease(&session->ref);
				janus_refcount_decrease(&publisher->ref);
				return;
			}
			/* Send an event on the handle to notify the application: it's
			 * up to the application to then choose a policy and enforce it */
			json_t *event = json_object();
			json_object_set_new(event, "videoroom", json_string("slow_link"));
			/* Also add info on what the current bitrate cap is */
			uint32_t bitrate = publisher->bitrate;
			json_object_set_new(event, "current-bitrate", json_integer(bitrate));
			gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
			json_decref(event);
			janus_refcount_decrease(&publisher->ref);
		} else {
			JANUS_LOG(LOG_WARN, "Got a slow uplink on a VideoRoom publisher? Weird, because it doesn't receive media...\n");
		}
	} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
		if(uplink) {
			janus_videoroom_subscriber *viewer = (janus_videoroom_subscriber *)session->participant;
			if(viewer == NULL || g_atomic_int_get(&viewer->destroyed)) {
				janus_refcount_decrease(&session->ref);
				return;
			}
			/* Send an event on the handle to notify the application: it's
			 * up to the application to then choose a policy and enforce it */
			json_t *event = json_object();
			json_object_set_new(event, "videoroom", json_string("slow_link"));
			gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
			json_decref(event);
		} else {
			JANUS_LOG(LOG_WARN, "Got a slow downlink on a VideoRoom viewer? Weird, because it doesn't send media...\n");
		}
	}
	janus_refcount_decrease(&session->ref);
}

static void janus_videoroom_recorder_create(janus_videoroom_publisher_stream *stream) {
	char filename[255];
	gint64 now = janus_get_real_time();
	if(stream->publisher && stream->rc == NULL) {
		const char *type = NULL;
		switch(stream->type) {
			case JANUS_VIDEOROOM_MEDIA_AUDIO:
				type = janus_audiocodec_name(stream->acodec);
				break;
			case JANUS_VIDEOROOM_MEDIA_VIDEO:
				type = janus_videocodec_name(stream->vcodec);
				break;
			case JANUS_VIDEOROOM_MEDIA_DATA:
				type = "text";
				break;
			default:
				return;
		}
		janus_rtp_switching_context_reset(&stream->rec_ctx);
		janus_rtp_simulcasting_context_reset(&stream->rec_simctx);
		if(stream->type == JANUS_VIDEOROOM_MEDIA_VIDEO) {
			stream->rec_simctx.rid_ext_id = stream->rid_extmap_id;
			stream->rec_simctx.substream_target = 2;
			stream->rec_simctx.templayer_target = 2;
		}
		memset(filename, 0, 255);
		if(stream->publisher->recording_base) {
			/* Use the filename and path we have been provided */
			g_snprintf(filename, 255, "%s-%s-%d", stream->publisher->recording_base,
				janus_videoroom_media_str(stream->type), stream->mindex);
			stream->rc = janus_recorder_create(stream->publisher->room->rec_dir, type, filename);
			if(stream->rc == NULL) {
				JANUS_LOG(LOG_ERR, "Couldn't open a %s recording file for this publisher!\n", janus_videoroom_media_str(stream->type));
			}
		} else {
			/* Build a filename */
			g_snprintf(filename, 255, "videoroom-%"SCNu64"-user-%"SCNu64"-%"SCNi64"-%s-%d",
				stream->publisher->room_id, stream->publisher->user_id, now,
				janus_videoroom_media_str(stream->type), stream->mindex);
			stream->rc = janus_recorder_create(stream->publisher->room->rec_dir, type, filename);
			if(stream->rc == NULL) {
				JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this publisher!\n");
			}
		}
	}
}

static void janus_videoroom_recorder_close(janus_videoroom_publisher *participant) {
	GList *temp = participant->streams;
	while(temp) {
		janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
		if(ps->rc) {
			janus_recorder *rc = ps->rc;
			ps->rc = NULL;
			janus_recorder_close(rc);
			JANUS_LOG(LOG_INFO, "Closed %s recording %s\n", janus_videoroom_media_str(ps->type),
				rc->filename ? rc->filename : "??");
			janus_recorder_destroy(rc);
		}
		temp = temp->next;
	}
}

void janus_videoroom_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore; %p %p\n", JANUS_VIDEOROOM_PACKAGE, handle, handle->gateway_handle, handle->plugin_handle);
	janus_mutex_lock(&sessions_mutex);
	janus_videoroom_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_videoroom_hangup_media_internal(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_videoroom_session *session = janus_videoroom_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	session->started = FALSE;
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	/* Send an event to the browser and tell the PeerConnection is over */
	if(session->participant_type == janus_videoroom_p_type_publisher) {
		/* This publisher just 'unpublished' */
		janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher(session);
		/* Get rid of the recorders, if available */
		janus_mutex_lock(&participant->rec_mutex);
		g_free(participant->recording_base);
		participant->recording_base = NULL;
		janus_videoroom_recorder_close(participant);
		janus_mutex_unlock(&participant->rec_mutex);
		/* Use subscribers_mutex to protect fields used in janus_videoroom_incoming_rtp */
		participant->firefox = FALSE;
		participant->remb_startup = 4;
		participant->remb_latest = 0;
		/* Get rid of streams */
		janus_mutex_lock(&participant->streams_mutex);
		GList *subscribers = NULL;
		GList *temp = participant->streams;
		while(temp) {
			janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
			/* Close all subscriptions to this stream */
			janus_mutex_lock(&ps->subscribers_mutex);
			GSList *temp2 = ps->subscribers;
			while(temp2) {
				janus_videoroom_subscriber_stream *ss = (janus_videoroom_subscriber_stream *)temp2->data;
				temp2 = temp2->next;
				if(ss) {
					/* Remove the subscription (turns the m-line to inactive) */
					janus_videoroom_subscriber_stream_remove(ss, ps, FALSE);
					/* Take note of the subscriber, so that we can send an updated offer */
					if(ss->type != JANUS_VIDEOROOM_MEDIA_DATA && g_list_find(subscribers, ss->subscriber) == NULL) {
						janus_refcount_increase(&ss->subscriber->ref);
						subscribers = g_list_append(subscribers, ss->subscriber);
					}
				}
			}
			g_slist_free(ps->subscribers);
			ps->subscribers = NULL;
			int i=0;
			for(i=0; i<3; i++) {
				ps->vssrc[i] = 0;
				g_free(ps->rid[i]);
				ps->rid[i] = NULL;
			}
			ps->rid_extmap_id = 0;
			janus_mutex_unlock(&ps->subscribers_mutex);
			temp = temp->next;
		}
		/* Any subscriber session to update? */
		if(subscribers != NULL) {
			temp = subscribers;
			while(temp) {
				janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)temp->data;
				/* Send (or schedule) a new offer */
				janus_mutex_lock(&subscriber->streams_mutex);
				if(!g_atomic_int_get(&subscriber->answered)) {
					/* We're still waiting for an answer to a previous offer, postpone this */
					g_atomic_int_set(&subscriber->pending_offer, 1);
					janus_mutex_unlock(&subscriber->streams_mutex);
				} else {
					json_t *event = json_object();
					json_object_set_new(event, "videoroom", json_string("updated"));
					json_object_set_new(event, "room", json_integer(subscriber->room_id));
					json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
					json_object_set_new(event, "streams", media);
					/* Generate a new offer */
					json_t *jsep = janus_videoroom_subscriber_offer(subscriber);
					janus_mutex_unlock(&subscriber->streams_mutex);
					/* How long will the Janus core take to push the event? */
					gint64 start = janus_get_monotonic_time();
					int res = gateway->push_event(subscriber->session->handle, &janus_videoroom_plugin, NULL, event, jsep);
					JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
					json_decref(event);
					json_decref(jsep);
					/* Also notify event handlers */
					if(notify_events && gateway->events_is_enabled()) {
						json_t *info = json_object();
						json_object_set_new(info, "event", json_string("updated"));
						json_object_set_new(info, "room", json_integer(subscriber->room_id));
						json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
						json_object_set_new(info, "streams", media);
						json_object_set_new(info, "private_id", json_integer(subscriber->pvt_id));
						gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
					}
				}
				janus_refcount_decrease(&subscriber->ref);
				temp = temp->next;
			}
		}
		g_list_free(subscribers);
		/* Free streams */
		g_list_free(participant->streams);
		participant->streams = NULL;
		g_hash_table_remove_all(participant->streams_byid);
		g_hash_table_remove_all(participant->streams_bymid);
		janus_mutex_unlock(&participant->streams_mutex);
		janus_videoroom_leave_or_unpublish(participant, FALSE, FALSE);
		janus_refcount_decrease(&participant->ref);
	} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* Get rid of subscriber */
		janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)session->participant;
		if(subscriber) {
			subscriber->paused = TRUE;
			g_atomic_int_set(&subscriber->answered, 0);
			g_atomic_int_set(&subscriber->pending_offer, 0);
			g_atomic_int_set(&subscriber->pending_restart, 0);
			/* TODO Get rid of streams */
			janus_mutex_lock(&subscriber->streams_mutex);
			GList *temp = subscriber->streams;
			while(temp) {
				janus_videoroom_subscriber_stream *s = (janus_videoroom_subscriber_stream *)temp->data;
				GSList *list = s->publisher_streams;
				while(list) {
					janus_videoroom_publisher_stream *ps = list->data;
					if(ps && ps->publisher != NULL) {
						/* Also notify event handlers */
						if(notify_events && gateway->events_is_enabled()) {
							json_t *info = json_object();
							json_object_set_new(info, "event", json_string("unsubscribed"));
							json_object_set_new(info, "room", json_integer(ps->publisher->room_id));
							json_object_set_new(info, "feed", json_integer(ps->publisher->user_id));
							json_object_set_new(info, "mid", json_string(ps->mid));
							gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
						}
					}
					list = list->next;
				}
				janus_videoroom_subscriber_stream_remove(s, NULL, TRUE);
				temp = temp->next;
			}
			/* TODO Free streams */
			g_list_free(subscriber->streams);
			subscriber->streams = NULL;
			g_hash_table_remove_all(subscriber->streams_byid);
			g_hash_table_remove_all(subscriber->streams_bymid);
			janus_mutex_unlock(&subscriber->streams_mutex);
		}
		/* TODO Should we close the handle as well? */
	}
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_videoroom_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining VideoRoom handler thread\n");
	janus_videoroom_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_videoroom_message_free(msg);
			continue;
		}
		janus_videoroom *videoroom = NULL;
		janus_videoroom_publisher *participant = NULL;
		janus_mutex_lock(&sessions_mutex);
		janus_videoroom_session *session = janus_videoroom_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_videoroom_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_videoroom_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = NULL;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_VIDEOROOM_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		root = msg->message;
		/* Get the request first */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *event = NULL;
		gboolean sdp_update = FALSE;
		if(json_object_get(msg->jsep, "update") != NULL)
			sdp_update = json_is_true(json_object_get(msg->jsep, "update"));
		/* 'create' and 'destroy' are handled synchronously: what kind of participant is this session referring to? */
		if(session->participant_type == janus_videoroom_p_type_none) {
			JANUS_LOG(LOG_VERB, "Configuring new participant\n");
			/* Not configured yet, we need to do this now */
			if(strcasecmp(request_text, "join") && strcasecmp(request_text, "joinandconfigure")) {
				JANUS_LOG(LOG_ERR, "Invalid request on unconfigured participant\n");
				error_code = JANUS_VIDEOROOM_ERROR_JOIN_FIRST;
				g_snprintf(error_cause, 512, "Invalid request on unconfigured participant");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, join_parameters,
				error_code, error_cause, TRUE,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			janus_mutex_lock(&rooms_mutex);
			error_code = janus_videoroom_access_room(root, FALSE, TRUE, &videoroom, error_cause, sizeof(error_cause));
			if(error_code != 0) {
				janus_mutex_unlock(&rooms_mutex);
				goto error;
			}
			janus_refcount_increase(&videoroom->ref);
			janus_mutex_lock(&videoroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			json_t *ptype = json_object_get(root, "ptype");
			const char *ptype_text = json_string_value(ptype);
			if(!strcasecmp(ptype_text, "publisher")) {
				JANUS_LOG(LOG_VERB, "Configuring new publisher\n");
				JANUS_VALIDATE_JSON_OBJECT(root, publisher_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0) {
					janus_mutex_unlock(&videoroom->mutex);
					janus_refcount_decrease(&videoroom->ref);
					goto error;
				}
				json_t *descriptions = json_object_get(root, "descriptions");
				if(descriptions != NULL && json_array_size(descriptions) > 0) {
					size_t i = 0;
					for(i=0; i<json_array_size(descriptions); i++) {
						json_t *d = json_array_get(descriptions, i);
						JANUS_VALIDATE_JSON_OBJECT(d, publish_desc_parameters,
							error_code, error_cause, TRUE,
							JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
						if(error_code != 0) {
							janus_mutex_unlock(&videoroom->mutex);
							janus_refcount_decrease(&videoroom->ref);
							goto error;

						}
					}
				}
				/* A token might be required to join */
				if(videoroom->check_allowed) {
					json_t *token = json_object_get(root, "token");
					const char *token_text = token ? json_string_value(token) : NULL;
					if(token_text == NULL || g_hash_table_lookup(videoroom->allowed, token_text) == NULL) {
						janus_mutex_unlock(&videoroom->mutex);
						janus_refcount_decrease(&videoroom->ref);
						JANUS_LOG(LOG_ERR, "Unauthorized (not in the allowed list)\n");
						error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED;
						g_snprintf(error_cause, 512, "Unauthorized (not in the allowed list)");
						goto error;
					}
				}
				json_t *display = json_object_get(root, "display");
				const char *display_text = display ? json_string_value(display) : NULL;
				guint64 user_id = 0;
				json_t *id = json_object_get(root, "id");
				if(id) {
					user_id = json_integer_value(id);
					if(g_hash_table_lookup(videoroom->participants, &user_id) != NULL) {
						janus_mutex_unlock(&videoroom->mutex);
						janus_refcount_decrease(&videoroom->ref);
						/* User ID already taken */
						JANUS_LOG(LOG_ERR, "User ID %"SCNu64" already exists\n", user_id);
						error_code = JANUS_VIDEOROOM_ERROR_ID_EXISTS;
						g_snprintf(error_cause, 512, "User ID %"SCNu64" already exists", user_id);
						goto error;
					}
				}
				if(user_id == 0) {
					/* Generate a random ID */
					while(user_id == 0) {
						user_id = janus_random_uint64();
						if(g_hash_table_lookup(videoroom->participants, &user_id) != NULL) {
							/* User ID already taken, try another one */
							user_id = 0;
						}
					}
				}
				JANUS_LOG(LOG_VERB, "  -- Publisher ID: %"SCNu64"\n", user_id);
				/* Process the request */
				json_t *bitrate = NULL, *record = NULL, *recfile = NULL;
				if(!strcasecmp(request_text, "joinandconfigure")) {
					bitrate = json_object_get(root, "bitrate");
					record = json_object_get(root, "record");
					recfile = json_object_get(root, "filename");
				}
				janus_videoroom_publisher *publisher = g_malloc0(sizeof(janus_videoroom_publisher));
				publisher->session = session;
				publisher->room_id = videoroom->room_id;
				publisher->room = videoroom;
				videoroom = NULL;
				publisher->user_id = user_id;
				publisher->display = display_text ? g_strdup(display_text) : NULL;
				publisher->recording_active = FALSE;
				publisher->recording_base = NULL;
				publisher->firefox = FALSE;
				publisher->bitrate = publisher->room->bitrate;
				publisher->subscriptions = NULL;
				publisher->streams_byid = g_hash_table_new_full(NULL, NULL,
					NULL, (GDestroyNotify)janus_videoroom_publisher_stream_destroy);
				publisher->streams_bymid = g_hash_table_new_full(g_str_hash, g_str_equal,
					(GDestroyNotify)g_free, (GDestroyNotify)janus_videoroom_publisher_stream_unref);
				janus_mutex_init(&publisher->streams_mutex);
				janus_mutex_init(&publisher->subscribers_mutex);
				publisher->remb_startup = 4;
				publisher->remb_latest = 0;
				publisher->srtp_contexts = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)janus_videoroom_srtp_context_free);
				publisher->udp_sock = -1;
				janus_mutex_init(&publisher->rtp_forwarders_mutex);
				publisher->rtp_forwarders = g_hash_table_new(NULL, NULL);
				/* Finally, generate a private ID: this is only needed in case the participant
				 * wants to allow the plugin to know which subscriptions belong to them */
				publisher->pvt_id = 0;
				while(publisher->pvt_id == 0) {
					publisher->pvt_id = janus_random_uint32();
					if(g_hash_table_lookup(publisher->room->private_ids, GUINT_TO_POINTER(publisher->pvt_id)) != NULL) {
						/* Private ID already taken, try another one */
						publisher->pvt_id = 0;
					}
					g_hash_table_insert(publisher->room->private_ids, GUINT_TO_POINTER(publisher->pvt_id), publisher);
				}
				g_atomic_int_set(&publisher->destroyed, 0);
				janus_refcount_init(&publisher->ref, janus_videoroom_publisher_free);
				/* In case we also wanted to configure */
				if(bitrate) {
					publisher->bitrate = json_integer_value(bitrate);
					JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu32" (room %"SCNu64", user %"SCNu64")\n", publisher->bitrate, publisher->room_id, publisher->user_id);
				}
				if(record) {
					publisher->recording_active = json_is_true(record);
					JANUS_LOG(LOG_VERB, "Setting record property: %s (room %"SCNu64", user %"SCNu64")\n", publisher->recording_active ? "true" : "false", publisher->room_id, publisher->user_id);
				}
				if(recfile) {
					publisher->recording_base = g_strdup(json_string_value(recfile));
					JANUS_LOG(LOG_VERB, "Setting recording basename: %s (room %"SCNu64", user %"SCNu64")\n", publisher->recording_base, publisher->room_id, publisher->user_id);
				}
				/* Done */
				janus_mutex_lock(&session->mutex);
				session->participant_type = janus_videoroom_p_type_publisher;
				session->participant = publisher;
				janus_mutex_unlock(&session->mutex);
				/* Return a list of all available publishers (those with an SDP available, that is) */
				json_t *list = json_array(), *attendees = NULL;
				if(publisher->room->notify_joining)
					attendees = json_array();
				GHashTableIter iter;
				gpointer value;
				janus_refcount_increase(&publisher->ref);
				g_hash_table_insert(publisher->room->participants, janus_uint64_dup(publisher->user_id), publisher);
				g_hash_table_iter_init(&iter, publisher->room->participants);
				while(!g_atomic_int_get(&publisher->room->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_videoroom_publisher *p = value;
					if(p == publisher || !p->streams || !p->session->started) {
						/* Check if we're also notifying normal joins and not just publishers */
						if(p != publisher && publisher->room->notify_joining) {
							json_t *al = json_object();
							json_object_set_new(al, "id", json_integer(p->user_id));
							if(p->display)
								json_object_set_new(al, "display", json_string(p->display));
							json_array_append_new(attendees, al);
						}
						continue;
					}
					json_t *pl = json_object();
					json_object_set_new(pl, "id", json_integer(p->user_id));
					if(p->display)
						json_object_set_new(pl, "display", json_string(p->display));
					/* Add proper info on all the streams */
					gboolean audio_added = FALSE, video_added = FALSE, talking_found = FALSE, talking = FALSE;
					json_t *media = json_array();
					GList *temp = p->streams;
					while(temp) {
						janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
						/* Are we updating the description? */
						if(descriptions != NULL && json_array_size(descriptions) > 0) {
							size_t i = 0;
							for(i=0; i<json_array_size(descriptions); i++) {
								json_t *d = json_array_get(descriptions, i);
								const char *d_mid = json_string_value(json_object_get(d, "mid"));
								const char *d_desc = json_string_value(json_object_get(d, "description"));
								if(d_desc && d_mid && ps->mid && !strcasecmp(d_mid, ps->mid)) {
									g_free(ps->description);
									ps->description = g_strdup(d_desc);
									break;
								}
							}
						}
						json_t *info = json_object();
						json_object_set_new(info, "type", json_string(janus_videoroom_media_str(ps->type)));
						json_object_set_new(info, "mindex", json_integer(ps->mindex));
						json_object_set_new(info, "mid", json_string(ps->mid));
						if(ps->description)
							json_object_set_new(info, "description", json_string(ps->description));
						if(ps->type == JANUS_VIDEOROOM_MEDIA_AUDIO) {
							json_object_set_new(info, "codec", json_string(janus_audiocodec_name(ps->acodec)));
							/* FIXME For backwards compatibility, we need audio_codec in the global info */
							if(!audio_added) {
								audio_added = TRUE;
								json_object_set_new(pl, "audio_codec", json_string(janus_audiocodec_name(ps->acodec)));
							}
							if(ps->audio_level_extmap_id > 0) {
								json_object_set_new(info, "talking", talking ? json_true() : json_false());
								/* FIXME For backwards compatibility, we also need talking in the global info */
								talking_found = TRUE;
								talking |= ps->talking;
							}
						} else if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO) {
							/* FIXME For backwards compatibility, we need video_codec in the global info */
							json_object_set_new(info, "codec", json_string(janus_videocodec_name(ps->vcodec)));
							if(!video_added) {
								video_added = TRUE;
								json_object_set_new(pl, "video_codec", json_string(janus_videocodec_name(ps->vcodec)));
							}
							if(ps->simulcast)
								json_object_set_new(info, "simulcast", json_true());
							if(ps->svc)
								json_object_set_new(info, "svc", json_true());
						}
						json_array_append_new(media, info);
						temp = temp->next;
					}
					json_object_set_new(pl, "streams", media);
					if(talking_found)
						json_object_set_new(pl, "talking", talking ? json_true() : json_false());
					json_array_append_new(list, pl);
				}
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("joined"));
				json_object_set_new(event, "room", json_integer(publisher->room->room_id));
				json_object_set_new(event, "description", json_string(publisher->room->room_name));
				json_object_set_new(event, "id", json_integer(user_id));
				json_object_set_new(event, "private_id", json_integer(publisher->pvt_id));
				json_object_set_new(event, "publishers", list);
				if(attendees != NULL)
					json_object_set_new(event, "attendees", attendees);
				/* See if we need to notify about a new participant joined the room (by default, we don't). */
				janus_videoroom_participant_joining(publisher);

				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("joined"));
					json_object_set_new(info, "room", json_integer(publisher->room->room_id));
					json_object_set_new(info, "id", json_integer(user_id));
					json_object_set_new(info, "private_id", json_integer(publisher->pvt_id));
					if(display_text != NULL)
						json_object_set_new(info, "display", json_string(display_text));
					gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
				}
				janus_mutex_unlock(&publisher->room->mutex);
			} else if(!strcasecmp(ptype_text, "subscriber")) {
				JANUS_LOG(LOG_VERB, "Configuring new subscriber\n");
				/* This is a new subscriber */
				JANUS_VALIDATE_JSON_OBJECT(root, subscriber_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0) {
					janus_mutex_unlock(&videoroom->mutex);
					goto error;
				}
				/* Who does this subscription belong to? */
				json_t *pvt = json_object_get(root, "private_id");
				guint64 pvt_id = json_integer_value(pvt), feed_id = 0;
				/* The new way of subscribing is specifying the streams we're interested in */
				json_t *feeds = json_object_get(root, "streams");
				gboolean legacy = FALSE;
				if(feeds == NULL || json_array_size(feeds) == 0) {
					/* For backwards compatibility, we still support the old "feed" property, which means
					 * "subscribe to all the feeds from this publisher" (depending on offer_audio, etc.) */
					json_t *feed = json_object_get(root, "feed");
					feed_id = json_integer_value(feed);
					if(feed_id == 0) {
						JANUS_LOG(LOG_ERR, "At least one between 'streams' and 'feed' must be specified\n");
						error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
						g_snprintf(error_cause, 512, "At least one between 'streams' and 'feed' must be specified");
						janus_mutex_unlock(&videoroom->mutex);
						goto error;
					}
					/* Create a fake "streams" array and put the only feed there */
					json_t *m = json_array();
					json_t *s = json_object();
					json_object_set_new(s, "feed", json_integer(feed_id));
					json_array_append_new(m, s);
					json_object_set_new(root, "streams", m);
					feeds = json_object_get(root, "streams");
					legacy = TRUE;
				}
				json_t *cpc = json_object_get(root, "close_pc");
				gboolean close_pc  = cpc ? json_is_true(cpc) : TRUE;
				/* Make sure all the feeds we're subscribing to exist */
				GList *publishers = NULL;
				size_t i = 0;
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *s = json_array_get(feeds, i);
					JANUS_VALIDATE_JSON_OBJECT(s, subscriber_stream_parameters,
						error_code, error_cause, TRUE,
						JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
					if(error_code != 0) {
						janus_mutex_unlock(&videoroom->mutex);
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					json_t *feed = json_object_get(s, "feed");
					guint64 feed_id = json_integer_value(feed);
					janus_videoroom_publisher *publisher = g_hash_table_lookup(videoroom->participants, &feed_id);
					if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || !publisher->session->started) {
						JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
						error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
						g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", feed_id);
						janus_mutex_unlock(&videoroom->mutex);
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					const char *mid = json_string_value(json_object_get(s, "mid"));
					if(mid != NULL) {
						/* Check the mid too */
						janus_mutex_lock(&publisher->streams_mutex);
						if(g_hash_table_lookup(publisher->streams_bymid, mid) == NULL) {
							janus_mutex_unlock(&publisher->streams_mutex);
							JANUS_LOG(LOG_ERR, "No such mid '%s' in feed (%"SCNu64")\n", mid, feed_id);
							error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
							g_snprintf(error_cause, 512, "No such mid '%s' in feed (%"SCNu64")", mid, feed_id);
							janus_mutex_unlock(&videoroom->mutex);
							/* Unref publishers we may have taken note of so far */
							while(publishers) {
								publisher = (janus_videoroom_publisher *)publishers->data;
								janus_refcount_decrease(&publisher->ref);
								janus_refcount_decrease(&publisher->session->ref);
								publishers = g_list_remove(publishers, publisher);
							}
							goto error;
						}
						janus_mutex_unlock(&publisher->streams_mutex);
					}
					json_t *spatial = json_object_get(s, "spatial_layer");
					json_t *sc_substream = json_object_get(s, "substream");
					if(json_integer_value(spatial) < 0 || json_integer_value(spatial) > 2 ||
							json_integer_value(sc_substream) < 0 || json_integer_value(sc_substream) > 2) {
						JANUS_LOG(LOG_ERR, "Invalid element (substream/spatial_layer should be 0, 1 or 2)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid value (substream/spatial_layer should be 0, 1 or 2)");
						janus_mutex_unlock(&videoroom->mutex);
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					json_t *temporal = json_object_get(s, "temporal_layer");
					json_t *sc_temporal = json_object_get(s, "temporal");
					if(json_integer_value(temporal) < 0 || json_integer_value(temporal) > 2 ||
							json_integer_value(sc_temporal) < 0 || json_integer_value(sc_temporal) > 2) {
						JANUS_LOG(LOG_ERR, "Invalid element (temporal/temporal_layer should be 0, 1 or 2)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid value (temporal/temporal_layer should be 0, 1 or 2)");
						janus_mutex_unlock(&videoroom->mutex);
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					/* Increase the refcount before unlocking so that nobody can remove and free the publisher in the meantime. */
					janus_refcount_increase(&publisher->ref);
					janus_refcount_increase(&publisher->session->ref);
					publishers = g_list_append(publishers, publisher);
				}
				/* TODO These properties are only there for backwards compatibility */
				json_t *offer_audio = json_object_get(root, "offer_audio");
				json_t *offer_video = json_object_get(root, "offer_video");
				json_t *offer_data = json_object_get(root, "offer_data");
				janus_videoroom_publisher *owner = NULL;
				/* Let's check if this room requires valid private_id values */
				if(videoroom->require_pvtid) {
					/* It does, let's make sure this subscription complies */
					owner = g_hash_table_lookup(videoroom->private_ids, GUINT_TO_POINTER(pvt_id));
					if(pvt_id == 0 || owner == NULL) {
						JANUS_LOG(LOG_ERR, "Unauthorized (this room requires a valid private_id)\n");
						error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED;
						g_snprintf(error_cause, 512, "Unauthorized (this room requires a valid private_id)");
						janus_mutex_unlock(&videoroom->mutex);
						/* Unref publishers */
						while(publishers) {
							janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					janus_refcount_increase(&owner->ref);
					janus_refcount_increase(&owner->session->ref);
				}
				janus_mutex_unlock(&videoroom->mutex);
				/* Allocate a new subscriber instance */
				janus_videoroom_subscriber *subscriber = g_malloc0(sizeof(janus_videoroom_subscriber));
				subscriber->session = session;
				subscriber->room_id = videoroom->room_id;
				subscriber->room = videoroom;
				videoroom = NULL;
				subscriber->pvt_id = pvt_id;
				subscriber->close_pc = close_pc;
				subscriber->paused = TRUE;	/* We need an explicit start from the stream */
				subscriber->streams_byid = g_hash_table_new_full(NULL, NULL,
					NULL, (GDestroyNotify)janus_videoroom_subscriber_stream_destroy);
				subscriber->streams_bymid = g_hash_table_new_full(g_str_hash, g_str_equal,
					(GDestroyNotify)g_free, (GDestroyNotify)janus_videoroom_subscriber_stream_unref);
				janus_mutex_init(&subscriber->streams_mutex);
				g_atomic_int_set(&subscriber->destroyed, 0);
				janus_refcount_init(&subscriber->ref, janus_videoroom_subscriber_free);
				/* FIXME backwards compatibility */
				gboolean do_audio = offer_audio ? json_is_true(offer_audio) : TRUE;
				gboolean do_video = offer_video ? json_is_true(offer_video) : TRUE;
				gboolean do_data = offer_data ? json_is_true(offer_data) : TRUE;
				/* Initialize the subscriber streams */
				gboolean data_added = FALSE;
				janus_videoroom_subscriber_stream *data_stream = NULL;
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *s = json_array_get(feeds, i);
					json_t *feed = json_object_get(s, "feed");
					guint64 feed_id = json_integer_value(feed);
					janus_videoroom_publisher *publisher = g_hash_table_lookup(subscriber->room->participants, &feed_id);
					if(publisher == NULL) {
						/* TODO We shouldn't let this happen... */
						JANUS_LOG(LOG_WARN, "Skipping feed %"SCNu64"...\n", feed_id);
						continue;
					}
					janus_mutex_lock(&publisher->streams_mutex);
					const char *mid = json_string_value(json_object_get(s, "mid"));
					json_t *spatial = json_object_get(s, "spatial_layer");
					json_t *sc_substream = json_object_get(s, "substream");
					json_t *temporal = json_object_get(s, "temporal_layer");
					json_t *sc_temporal = json_object_get(s, "temporal");
					if(mid) {
						/* Subscribe to a specific mid */
						janus_videoroom_publisher_stream *ps = g_hash_table_lookup(publisher->streams_bymid, mid);
						if(ps == NULL) {
							/* TODO We shouldn't let this happen either... */
							JANUS_LOG(LOG_WARN, "Skipping mid %s in feed %"SCNu64"...\n", mid, feed_id);
							janus_mutex_unlock(&publisher->streams_mutex);
							continue;
						}
						if(ps->type == JANUS_VIDEOROOM_MEDIA_DATA && data_added) {
							/* We already have a datachannel m-line, no need for others: just update the subscribers list */
							janus_mutex_lock(&ps->subscribers_mutex);
							if(g_slist_find(ps->subscribers, data_stream) == NULL && g_slist_find(data_stream->publisher_streams, ps) == NULL) {
								ps->subscribers = g_slist_append(ps->subscribers, data_stream);
								data_stream->publisher_streams = g_slist_append(data_stream->publisher_streams, ps);
								/* The two streams reference each other */
								janus_refcount_increase(&data_stream->ref);
								janus_refcount_increase(&ps->ref);
							}
							janus_mutex_unlock(&ps->subscribers_mutex);
							janus_mutex_unlock(&publisher->streams_mutex);
							continue;
						}
						janus_videoroom_subscriber_stream *stream = janus_videoroom_subscriber_stream_add(subscriber,
							ps, legacy, do_audio, do_video, do_data);
						if(stream && ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO &&
								(spatial || sc_substream || temporal || sc_temporal)) {
							/* Override the default spatial/substream/temporal targets */
							if(sc_substream)
								stream->sim_context.substream_target = json_integer_value(sc_substream);
							if(sc_temporal)
								stream->sim_context.templayer_target = json_integer_value(sc_temporal);
							if(spatial)
								stream->target_spatial_layer = json_integer_value(spatial);
							if(temporal)
								stream->target_temporal_layer = json_integer_value(temporal);
						}
						if(ps->type == JANUS_VIDEOROOM_MEDIA_DATA) {
							data_added = TRUE;
							data_stream = stream;
						}
					} else {
						/* Subscribe to all streams */
						GList *temp = publisher->streams;
						while(temp) {
							janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
							if(ps->type == JANUS_VIDEOROOM_MEDIA_DATA && data_added) {
								/* We already have a datachannel m-line, no need for others: just update the subscribers list */
								janus_mutex_lock(&ps->subscribers_mutex);
								if(g_slist_find(ps->subscribers, data_stream) == NULL && g_slist_find(data_stream->publisher_streams, ps) == NULL) {
									ps->subscribers = g_slist_append(ps->subscribers, data_stream);
									data_stream->publisher_streams = g_slist_append(data_stream->publisher_streams, ps);
									/* The two streams reference each other */
									janus_refcount_increase(&data_stream->ref);
									janus_refcount_increase(&ps->ref);
								}
								janus_mutex_unlock(&ps->subscribers_mutex);
								temp = temp->next;
								continue;
							}
							janus_videoroom_subscriber_stream *stream = janus_videoroom_subscriber_stream_add(subscriber,
								ps, legacy, do_audio, do_video, do_data);
							if(stream && ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO &&
									(spatial || sc_substream || temporal || sc_temporal)) {
								/* Override the default spatial/substream/temporal targets */
								if(sc_substream)
									stream->sim_context.substream_target = json_integer_value(sc_substream);
								if(sc_temporal)
									stream->sim_context.templayer_target = json_integer_value(sc_temporal);
								if(spatial)
									stream->target_spatial_layer = json_integer_value(spatial);
								if(temporal)
									stream->target_temporal_layer = json_integer_value(temporal);
							}
							if(ps->type == JANUS_VIDEOROOM_MEDIA_DATA) {
								data_added = TRUE;
								data_stream = stream;
							}
							temp = temp->next;
						}
					}
					janus_mutex_unlock(&publisher->streams_mutex);
				}
				/* Make sure we subscribed to at least something */
				if(subscriber->streams == NULL) {
					/* No subscription created? */
					g_free(subscriber);
					/* Unref publishers */
					if(owner) {
						janus_refcount_decrease(&owner->session->ref);
						janus_refcount_decrease(&owner->ref);
					}
					while(publishers) {
						janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
						janus_refcount_decrease(&publisher->ref);
						janus_refcount_decrease(&publisher->session->ref);
						publishers = g_list_remove(publishers, publisher);
					}
					JANUS_LOG(LOG_ERR, "Can't offer an SDP with no stream\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_SDP;
					g_snprintf(error_cause, 512, "Can't offer an SDP with no stream");
					goto error;
				}
				session->participant = subscriber;
				if(owner != NULL) {
					/* Note: we should refcount these subscription-publisher mappings as well */
					janus_mutex_lock(&owner->subscribers_mutex);
					owner->subscriptions = g_slist_append(owner->subscriptions, subscriber);
					janus_mutex_unlock(&owner->subscribers_mutex);
					/* Done adding the subscription, owner is safe to be released */
					janus_refcount_decrease(&owner->session->ref);
					janus_refcount_decrease(&owner->ref);
				}
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("attached"));
				json_object_set_new(event, "room", json_integer(subscriber->room_id));
				/* If this is a legacy subscription, put the feed ID too */
				if(legacy)
					json_object_set_new(event, "id", json_integer(feed_id));
				json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, legacy, event);
				json_object_set_new(event, "streams", media);
				session->participant_type = janus_videoroom_p_type_subscriber;
				JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
				/* Negotiate by crafting a new SDP matching the subscriptions */
				janus_mutex_lock(&subscriber->streams_mutex);
				json_t *jsep = janus_videoroom_subscriber_offer(subscriber);
				janus_mutex_unlock(&subscriber->streams_mutex);
				/* How long will the Janus core take to push the event? */
				g_atomic_int_set(&session->hangingup, 0);
				gint64 start = janus_get_monotonic_time();
				int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, jsep);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
				json_decref(event);
				json_decref(jsep);
				janus_videoroom_message_free(msg);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("subscribing"));
					json_object_set_new(info, "room", json_integer(subscriber->room_id));
					json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
					json_object_set_new(info, "streams", media);
					json_object_set_new(info, "private_id", json_integer(pvt_id));
					gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
				}
				/* Decrease the references we took before */
				while(publishers) {
					janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
					janus_refcount_decrease(&publisher->ref);
					janus_refcount_decrease(&publisher->session->ref);
					publishers = g_list_remove(publishers, publisher);
				}
				continue;
			} else {
				janus_mutex_unlock(&videoroom->mutex);
				JANUS_LOG(LOG_ERR, "Invalid element (ptype)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (ptype)");
				goto error;
			}
		} else if(session->participant_type == janus_videoroom_p_type_publisher) {
			/* Handle this publisher */
			participant = janus_videoroom_session_get_publisher(session);
			if(participant == NULL) {
				JANUS_LOG(LOG_ERR, "Invalid participant instance\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid participant instance");
				goto error;
			}
			if(participant->room == NULL) {
				janus_refcount_decrease(&participant->ref);
				JANUS_LOG(LOG_ERR, "No such room\n");
				error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
				g_snprintf(error_cause, 512, "No such room");
				goto error;
			}
			if(!strcasecmp(request_text, "join") || !strcasecmp(request_text, "joinandconfigure")) {
				janus_refcount_decrease(&participant->ref);
				JANUS_LOG(LOG_ERR, "Already in as a publisher on this handle\n");
				error_code = JANUS_VIDEOROOM_ERROR_ALREADY_JOINED;
				g_snprintf(error_cause, 512, "Already in as a publisher on this handle");
				goto error;
			} else if(!strcasecmp(request_text, "configure") || !strcasecmp(request_text, "publish")) {
				if(!strcasecmp(request_text, "publish") && participant->session->started) {
					janus_refcount_decrease(&participant->ref);
					JANUS_LOG(LOG_ERR, "Can't publish, already published\n");
					error_code = JANUS_VIDEOROOM_ERROR_ALREADY_PUBLISHED;
					g_snprintf(error_cause, 512, "Can't publish, already published");
					goto error;
				}
				if(participant->kicked) {
					janus_refcount_decrease(&participant->ref);
					JANUS_LOG(LOG_ERR, "Unauthorized, you have been kicked\n");
					error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED;
					g_snprintf(error_cause, 512, "Unauthorized, you have been kicked");
					goto error;
				}
				/* Configure (or publish a new feed) audio/video/bitrate for this publisher */
				JANUS_VALIDATE_JSON_OBJECT(root, publish_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0) {
					janus_refcount_decrease(&participant->ref);
					goto error;
				}
				json_t *descriptions = json_object_get(root, "descriptions");
				if(descriptions != NULL && json_array_size(descriptions) > 0) {
					size_t i = 0;
					for(i=0; i<json_array_size(descriptions); i++) {
						json_t *d = json_array_get(descriptions, i);
						JANUS_VALIDATE_JSON_OBJECT(d, publish_desc_parameters,
							error_code, error_cause, TRUE,
							JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
						if(error_code != 0) {
							janus_mutex_unlock(&videoroom->mutex);
							janus_refcount_decrease(&videoroom->ref);
							goto error;

						}
					}
				}
				json_t *audiocodec = json_object_get(root, "audiocodec");
				json_t *videocodec = json_object_get(root, "videocodec");
				json_t *bitrate = json_object_get(root, "bitrate");
				json_t *keyframe = json_object_get(root, "keyframe");
				json_t *record = json_object_get(root, "record");
				json_t *recfile = json_object_get(root, "filename");
				json_t *display = json_object_get(root, "display");
				json_t *update = json_object_get(root, "update");
				/* Audio, video and data are deprecated properties */
				json_t *audio = json_object_get(root, "audio");
				json_t *video = json_object_get(root, "video");
				json_t *data = json_object_get(root, "data");
				/* Better to specify the 'send' property of a specific 'mid' */
				const char *mid = json_string_value(json_object_get(root, "mid"));
				json_t *send = json_object_get(root, "send");
				/* A renegotiation may be taking place */
				gboolean do_update = update ? json_is_true(update) : FALSE;
				if(do_update && !sdp_update) {
					JANUS_LOG(LOG_WARN, "Got an 'update' request, but no SDP update? Ignoring...\n");
					do_update = FALSE;
				}
				/* Check if there's an SDP to take into account */
				if(json_string_value(json_object_get(msg->jsep, "sdp"))) {
					if(audiocodec && !sdp_update) {
						/* The participant would like to use an audio codec in particular */
						janus_audiocodec acodec = janus_audiocodec_from_name(json_string_value(audiocodec));
						if(acodec == JANUS_AUDIOCODEC_NONE ||
								(acodec != participant->room->acodec[0] &&
								acodec != participant->room->acodec[1] &&
								acodec != participant->room->acodec[2])) {
							JANUS_LOG(LOG_ERR, "Participant asked for audio codec '%s', but it's not allowed (room %"SCNu64", user %"SCNu64")\n",
								json_string_value(audiocodec), participant->room_id, participant->user_id);
							janus_refcount_decrease(&participant->ref);
							error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
							g_snprintf(error_cause, 512, "Audio codec unavailable in this room");
							goto error;
						}
						JANUS_LOG(LOG_VERB, "Participant asked for audio codec '%s' (room %"SCNu64", user %"SCNu64")\n",
							json_string_value(audiocodec), participant->room_id, participant->user_id);
					}
					if(videocodec && !sdp_update) {
						/* The participant would like to use a video codec in particular */
						janus_videocodec vcodec = janus_videocodec_from_name(json_string_value(videocodec));
						if(vcodec == JANUS_VIDEOCODEC_NONE ||
								(vcodec != participant->room->vcodec[0] &&
								vcodec != participant->room->vcodec[1] &&
								vcodec != participant->room->vcodec[2])) {
							JANUS_LOG(LOG_ERR, "Participant asked for video codec '%s', but it's not allowed (room %"SCNu64", user %"SCNu64")\n",
								json_string_value(videocodec), participant->room_id, participant->user_id);
							janus_refcount_decrease(&participant->ref);
							error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
							g_snprintf(error_cause, 512, "Video codec unavailable in this room");
							goto error;
						}
						JANUS_LOG(LOG_VERB, "Participant asked for video codec '%s' (room %"SCNu64", user %"SCNu64")\n",
							json_string_value(videocodec), participant->room_id, participant->user_id);
					}
				}
				/* Update the audio/video/data flags, if set (and just configuring) */
				if(audio || video || data || (mid && send)) {
					janus_mutex_lock(&participant->streams_mutex);
					GList *temp = participant->streams;
					while(temp) {
						janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
						gboolean mid_found = (mid && send && !strcasecmp(ps->mid, mid));
						if(ps->type == JANUS_VIDEOROOM_MEDIA_AUDIO && (audio || mid_found)) {
							gboolean audio_active = mid_found ? json_is_true(send) : json_is_true(audio);
							if(!ps->active && audio_active) {
								/* Audio was just resumed, try resetting the RTP headers for viewers */
								janus_mutex_lock(&ps->subscribers_mutex);
								GSList *slist = ps->subscribers;
								while(slist) {
									janus_videoroom_subscriber_stream *s = (janus_videoroom_subscriber_stream *)slist->data;
									if(s)
										s->context.seq_reset = TRUE;
									slist = slist->next;
								}
								janus_mutex_unlock(&ps->subscribers_mutex);
							}
							ps->active = audio_active;
							JANUS_LOG(LOG_VERB, "Setting audio property (%s): %s (room %"SCNu64", user %"SCNu64")\n",
								ps->mid, ps->active ? "true" : "false", participant->room_id, participant->user_id);
						} else if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO && (video || mid_found)) {
							gboolean video_active = mid_found ? json_is_true(send) : json_is_true(video);
							if(!ps->active && video_active) {
								/* Video was just resumed, try resetting the RTP headers for viewers */
								janus_mutex_lock(&participant->subscribers_mutex);
								GSList *slist = ps->subscribers;
								while(slist) {
									janus_videoroom_subscriber_stream *s = (janus_videoroom_subscriber_stream *)slist->data;
									if(s)
										s->context.seq_reset = TRUE;
									slist = slist->next;
								}
								janus_mutex_unlock(&participant->subscribers_mutex);
							}
							ps->active = video_active;
							JANUS_LOG(LOG_VERB, "Setting video property (%s): %s (room %"SCNu64", user %"SCNu64")\n",
								ps->mid, ps->active ? "true" : "false", participant->room_id, participant->user_id);
						} else if(ps->type == JANUS_VIDEOROOM_MEDIA_DATA && (data || mid_found)) {
							gboolean data_active = mid_found ? json_is_true(send) : json_is_true(data);
							ps->active = data_active;
							JANUS_LOG(LOG_VERB, "Setting data property (%s): %s (room %"SCNu64", user %"SCNu64")\n",
								ps->mid, ps->active ? "true" : "false", participant->room_id, participant->user_id);
						}
						temp = temp->next;
					}
					janus_mutex_unlock(&participant->streams_mutex);
				}
				if(bitrate) {
					participant->bitrate = json_integer_value(bitrate);
					JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu32" (room %"SCNu64", user %"SCNu64")\n", participant->bitrate, participant->room_id, participant->user_id);
					/* Send a new REMB */
					if(session->started)
						participant->remb_latest = janus_get_monotonic_time();
					char rtcpbuf[24];
					janus_rtcp_remb((char *)(&rtcpbuf), 24, participant->bitrate);
					gateway->relay_rtcp(msg->handle, -1, TRUE, rtcpbuf, 24);
				}
				if(keyframe && json_is_true(keyframe)) {
					/* FIXME Send a PLI on all video streams */
					GList *temp = participant->streams;
					while(temp) {
						janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
						if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO)
							janus_videoroom_reqpli(ps, "Keyframe request");
						temp = temp->next;
					}
				}
				janus_mutex_lock(&participant->rec_mutex);
				gboolean prev_recording_active = participant->recording_active;
				if(record) {
					participant->recording_active = json_is_true(record);
					JANUS_LOG(LOG_VERB, "Setting record property: %s (room %"SCNu64", user %"SCNu64")\n", participant->recording_active ? "true" : "false", participant->room_id, participant->user_id);
				}
				if(recfile) {
					participant->recording_base = g_strdup(json_string_value(recfile));
					JANUS_LOG(LOG_VERB, "Setting recording basename: %s (room %"SCNu64", user %"SCNu64")\n", participant->recording_base, participant->room_id, participant->user_id);
				}
				/* Do we need to do something with the recordings right now? */
				if(participant->recording_active != prev_recording_active) {
					/* Something changed */
					if(!participant->recording_active) {
						/* Not recording (anymore?) */
						janus_videoroom_recorder_close(participant);
					} else if(participant->recording_active && participant->session->started) {
						/* We've started recording, send a PLI and go on */
						GList *temp = participant->streams;
						while(temp) {
							janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
							janus_videoroom_recorder_create(ps);
							if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO) {
								/* Send a PLI */
								janus_videoroom_reqpli(ps, "Recording video");
							}
							temp = temp->next;
						}
					}
				}
				janus_mutex_unlock(&participant->rec_mutex);
				if(display) {
					janus_mutex_lock(&participant->room->mutex);
					char *old_display = participant->display;
					char *new_display = g_strdup(json_string_value(display));
					participant->display = new_display;
					if(old_display != NULL) {
						/* The display name changed, notify this */
						json_t *display_event = json_object();
						json_object_set_new(display_event, "videoroom", json_string("event"));
						json_object_set_new(display_event, "id", json_integer(participant->user_id));
						json_object_set_new(display_event, "display", json_string(participant->display));
						if(participant->room && !participant->room->destroyed) {
							janus_videoroom_notify_participants(participant, display_event);
						}
						json_decref(display_event);
					}
					g_free(old_display);
					janus_mutex_unlock(&participant->room->mutex);
				}
				/* Done */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(participant->room_id));
				json_object_set_new(event, "configured", json_string("ok"));
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("configured"));
					json_object_set_new(info, "room", json_integer(participant->room_id));
					json_object_set_new(info, "id", json_integer(participant->user_id));
						/* TODO Add info on all the streams, here */
					//~ json_object_set_new(info, "audio_active", participant->audio_active ? json_true() : json_false());
					//~ json_object_set_new(info, "video_active", participant->video_active ? json_true() : json_false());
					//~ json_object_set_new(info, "data_active", participant->data_active ? json_true() : json_false());
					json_object_set_new(info, "bitrate", json_integer(participant->bitrate));
					//~ if(participant->arc || participant->vrc || participant->drc) {
						//~ json_t *recording = json_object();
						//~ if(participant->arc && participant->arc->filename)
							//~ json_object_set_new(recording, "audio", json_string(participant->arc->filename));
						//~ if(participant->vrc && participant->vrc->filename)
							//~ json_object_set_new(recording, "video", json_string(participant->vrc->filename));
						//~ if(participant->drc && participant->drc->filename)
							//~ json_object_set_new(recording, "data", json_string(participant->drc->filename));
						//~ json_object_set_new(info, "recording", recording);
					//~ }
					gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
				}
			} else if(!strcasecmp(request_text, "unpublish")) {
				/* This participant wants to unpublish */
				if(!participant->session->started) {
					janus_refcount_decrease(&participant->ref);
					JANUS_LOG(LOG_ERR, "Can't unpublish, not published\n");
					error_code = JANUS_VIDEOROOM_ERROR_NOT_PUBLISHED;
					g_snprintf(error_cause, 512, "Can't unpublish, not published");
					goto error;
				}
				/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
				janus_videoroom_hangup_media(session->handle);
				gateway->close_pc(session->handle);
				/* Done */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(participant->room_id));
				json_object_set_new(event, "unpublished", json_string("ok"));
			} else if(!strcasecmp(request_text, "leave")) {
				/* Prepare an event to confirm the request */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(participant->room_id));
				json_object_set_new(event, "leaving", json_string("ok"));
				/* This publisher is leaving, tell everybody */
				janus_videoroom_leave_or_unpublish(participant, TRUE, FALSE);
				/* Done */
				session->started = FALSE;
				//~ session->destroy = TRUE;
			} else {
				janus_refcount_decrease(&participant->ref);
				JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
				g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
				goto error;
			}
			janus_refcount_decrease(&participant->ref);
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			/* Handle this subscriber */
			janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)session->participant;
			if(subscriber == NULL) {
				JANUS_LOG(LOG_ERR, "Invalid subscriber instance\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid subscriber instance");
				goto error;
			}
			if(subscriber->room == NULL) {
				JANUS_LOG(LOG_ERR, "No such room\n");
				error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
				g_snprintf(error_cause, 512, "No such room");
				goto error;
			}
			if(!strcasecmp(request_text, "join")) {
				JANUS_LOG(LOG_ERR, "Already in as a subscriber on this handle\n");
				error_code = JANUS_VIDEOROOM_ERROR_ALREADY_JOINED;
				g_snprintf(error_cause, 512, "Already in as a subscriber on this handle");
				goto error;
			} else if(!strcasecmp(request_text, "start")) {
				/* Start/restart receiving the publisher streams */
				if(subscriber->paused && msg->jsep == NULL) {
					/* This is just resuming a paused subscription, reset the RTP sequence numbers on all streams */
					GList *temp = subscriber->streams;
					while(temp) {
						janus_videoroom_subscriber_stream *stream = (janus_videoroom_subscriber_stream *)temp->data;
						stream->context.seq_reset = TRUE;
						temp = temp->next;
					}
				}
				subscriber->paused = FALSE;
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(subscriber->room_id));
				json_object_set_new(event, "started", json_string("ok"));
			} else if(!strcasecmp(request_text, "subscribe")) {
				/* Update a subscription by adding new streams */
				JANUS_LOG(LOG_VERB, "Adding new subscriber streams\n");
				JANUS_VALIDATE_JSON_OBJECT(root, subscriber_update_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				json_t *feeds = json_object_get(root, "streams");
				if(json_array_size(feeds) == 0) {
					JANUS_LOG(LOG_ERR, "Empty subscription list\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Empty subscription list");
					goto error;
				}
				/* Make sure all the feeds we're subscribing to exist */
				GList *publishers = NULL;
				size_t i = 0;
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *s = json_array_get(feeds, i);
					JANUS_VALIDATE_JSON_OBJECT(s, subscriber_stream_parameters,
						error_code, error_cause, TRUE,
						JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
					if(error_code != 0) {
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					json_t *feed = json_object_get(s, "feed");
					guint64 feed_id = json_integer_value(feed);
					janus_mutex_lock(&subscriber->room->mutex);
					janus_videoroom_publisher *publisher = g_hash_table_lookup(subscriber->room->participants, &feed_id);
					janus_mutex_unlock(&subscriber->room->mutex);
					if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || !publisher->session->started) {
						JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
						error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
						g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", feed_id);
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					const char *mid = json_string_value(json_object_get(s, "mid"));
					if(mid != NULL) {
						/* Check the mid too */
						janus_mutex_lock(&publisher->streams_mutex);
						if(g_hash_table_lookup(publisher->streams_bymid, mid) == NULL) {
							janus_mutex_unlock(&publisher->streams_mutex);
							JANUS_LOG(LOG_ERR, "No such mid '%s' in feed (%"SCNu64")\n", mid, feed_id);
							error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
							g_snprintf(error_cause, 512, "No such mid '%s' in feed (%"SCNu64")", mid, feed_id);
							/* Unref publishers we may have taken note of so far */
							while(publishers) {
								publisher = (janus_videoroom_publisher *)publishers->data;
								janus_refcount_decrease(&publisher->ref);
								janus_refcount_decrease(&publisher->session->ref);
								publishers = g_list_remove(publishers, publisher);
							}
							goto error;
						}
						janus_mutex_unlock(&publisher->streams_mutex);
					}
					json_t *spatial = json_object_get(s, "spatial_layer");
					json_t *sc_substream = json_object_get(s, "substream");
					if(json_integer_value(spatial) < 0 || json_integer_value(spatial) > 2 ||
							json_integer_value(sc_substream) < 0 || json_integer_value(sc_substream) > 2) {
						JANUS_LOG(LOG_ERR, "Invalid element (substream/spatial_layer should be 0, 1 or 2)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid value (substream/spatial_layer should be 0, 1 or 2)");
						janus_mutex_unlock(&videoroom->mutex);
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					json_t *temporal = json_object_get(s, "temporal_layer");
					json_t *sc_temporal = json_object_get(s, "temporal");
					if(json_integer_value(temporal) < 0 || json_integer_value(temporal) > 2 ||
							json_integer_value(sc_temporal) < 0 || json_integer_value(sc_temporal) > 2) {
						JANUS_LOG(LOG_ERR, "Invalid element (temporal/temporal_layer should be 0, 1 or 2)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid value (temporal/temporal_layer should be 0, 1 or 2)");
						janus_mutex_unlock(&videoroom->mutex);
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					/* Increase the refcount before unlocking so that nobody can remove and free the publisher in the meantime. */
					janus_refcount_increase(&publisher->ref);
					janus_refcount_increase(&publisher->session->ref);
					publishers = g_list_append(publishers, publisher);
				}
				/* Update subscriptions, adding streams or replacing existing and inactive ones */
				int changes = 0;
				janus_mutex_lock(&subscriber->streams_mutex);
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *s = json_array_get(feeds, i);
					json_t *feed = json_object_get(s, "feed");
					guint64 feed_id = json_integer_value(feed);
					janus_mutex_lock(&subscriber->room->mutex);
					janus_videoroom_publisher *publisher = g_hash_table_lookup(subscriber->room->participants, &feed_id);
					janus_mutex_unlock(&subscriber->room->mutex);
					if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || !publisher->session->started) {
						JANUS_LOG(LOG_WARN, "Publisher '%"SCNu64"' not found, not subscribing...\n", feed_id);
						continue;
					}
					/* Are we subscribing to this publisher as a whole or only to a single stream? */
					const char *mid = json_string_value(json_object_get(s, "mid"));
					json_t *spatial = json_object_get(s, "spatial_layer");
					json_t *sc_substream = json_object_get(s, "substream");
					json_t *temporal = json_object_get(s, "temporal_layer");
					json_t *sc_temporal = json_object_get(s, "temporal");
					if(mid != NULL) {
						janus_mutex_lock(&publisher->streams_mutex);
						janus_videoroom_publisher_stream *ps = g_hash_table_lookup(publisher->streams_bymid, mid);
						janus_mutex_unlock(&publisher->streams_mutex);
						if(ps == NULL) {
							JANUS_LOG(LOG_WARN, "No mid '%s' in publisher '%"SCNu64"', not subscribing...\n", mid, feed_id);
							continue;
						}
						janus_videoroom_subscriber_stream *stream = janus_videoroom_subscriber_stream_add_or_replace(subscriber, ps);
						if(stream) {
							changes++;
							if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO &&
									(spatial || sc_substream || temporal || sc_temporal)) {
								/* Override the default spatial/substream/temporal targets */
								if(sc_substream)
									stream->sim_context.substream_target = json_integer_value(sc_substream);
								if(sc_temporal)
									stream->sim_context.templayer_target = json_integer_value(sc_temporal);
								if(spatial)
									stream->target_spatial_layer = json_integer_value(spatial);
								if(temporal)
									stream->target_temporal_layer = json_integer_value(temporal);
							}
						}
					} else {
						janus_mutex_lock(&publisher->streams_mutex);
						GList *temp = publisher->streams;
						while(temp) {
							janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
							janus_videoroom_subscriber_stream *stream = janus_videoroom_subscriber_stream_add_or_replace(subscriber, ps);
							if(stream) {
								changes++;
								if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO &&
										(spatial || sc_substream || temporal || sc_temporal)) {
									/* Override the default spatial/substream/temporal targets */
									if(sc_substream)
										stream->sim_context.substream_target = json_integer_value(sc_substream);
									if(sc_temporal)
										stream->sim_context.templayer_target = json_integer_value(sc_temporal);
									if(spatial)
										stream->target_spatial_layer = json_integer_value(spatial);
									if(temporal)
										stream->target_temporal_layer = json_integer_value(temporal);
								}
							}
							temp = temp->next;
						}
						janus_mutex_unlock(&publisher->streams_mutex);
					}
				}
				if(changes == 0) {
					janus_mutex_unlock(&subscriber->streams_mutex);
					/* Nothing changes, don't do anything */
					JANUS_LOG(LOG_WARN, "No subscription done, skipping renegotiation\n");
					janus_videoroom_message_free(msg);
					/* Decrease the references we took before */
					while(publishers) {
						janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
						janus_refcount_decrease(&publisher->ref);
						janus_refcount_decrease(&publisher->session->ref);
						publishers = g_list_remove(publishers, publisher);
					}
					continue;
				}
				if(!g_atomic_int_get(&subscriber->answered)) {
					/* We're still waiting for an answer to a previous offer, postpone this */
					g_atomic_int_set(&subscriber->pending_offer, 1);
					janus_mutex_unlock(&subscriber->streams_mutex);
					JANUS_LOG(LOG_VERB, "Post-poning new offer, waiting for previous answer\n");
					/* Decrease the references we took before */
					while(publishers) {
						janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
						janus_refcount_decrease(&publisher->ref);
						janus_refcount_decrease(&publisher->session->ref);
						publishers = g_list_remove(publishers, publisher);
					}
					janus_videoroom_message_free(msg);
					continue;
				}
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("updated"));
				json_object_set_new(event, "room", json_integer(subscriber->room_id));
				json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
				json_object_set_new(event, "streams", media);
				/* Generate a new offer */
				json_t *jsep = janus_videoroom_subscriber_offer(subscriber);
				janus_mutex_unlock(&subscriber->streams_mutex);
				/* How long will the Janus core take to push the event? */
				gint64 start = janus_get_monotonic_time();
				int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, jsep);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
				json_decref(event);
				json_decref(jsep);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("updated"));
					json_object_set_new(info, "room", json_integer(subscriber->room_id));
					json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
					json_object_set_new(info, "streams", media);
					json_object_set_new(info, "private_id", json_integer(subscriber->pvt_id));
					gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
				}
				/* Decrease the references we took before */
				while(publishers) {
					janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
					janus_refcount_decrease(&publisher->ref);
					janus_refcount_decrease(&publisher->session->ref);
					publishers = g_list_remove(publishers, publisher);
				}
				/* Done */
				janus_videoroom_message_free(msg);
				continue;
			} else if(!strcasecmp(request_text, "unsubscribe")) {
				/* TODO Update a subscription by removing existing streams */
				JANUS_LOG(LOG_VERB, "Removing subscriber streams\n");
				JANUS_VALIDATE_JSON_OBJECT(root, subscriber_update_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				json_t *feeds = json_object_get(root, "streams");
				if(json_array_size(feeds) == 0) {
					JANUS_LOG(LOG_ERR, "Empty unsubscription list\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Empty unsubscription list");
					goto error;
				}
				/* Validate the request first */
				size_t i = 0;
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *s = json_array_get(feeds, i);
					JANUS_VALIDATE_JSON_OBJECT(s, subscriber_remove_parameters,
						error_code, error_cause, TRUE,
						JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
					if(error_code != 0)
						goto error;
				}
				/* Now remove the specified subscriptions */
				int changes = 0;
				janus_mutex_lock(&subscriber->streams_mutex);
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *s = json_array_get(feeds, i);
					json_t *feed = json_object_get(s, "feed");
					guint64 feed_id = json_integer_value(feed);
					const char *sub_mid = json_string_value(json_object_get(s, "sub_mid"));
					janus_videoroom_subscriber_stream *stream = NULL;
					if(sub_mid) {
						/* A specific subscription mid has been provided */
						stream = g_hash_table_lookup(subscriber->streams_bymid, sub_mid);
						if(stream == NULL) {
							JANUS_LOG(LOG_WARN, "Subscriber stream with mid '%s' not found, not unsubscribing...\n", sub_mid);
							continue;
						}
						janus_videoroom_subscriber_stream_remove(stream, NULL, TRUE);
						changes++;
					} else if(feed_id > 0) {
						janus_mutex_lock(&subscriber->room->mutex);
						janus_videoroom_publisher *publisher = g_hash_table_lookup(subscriber->room->participants, &feed_id);
						janus_mutex_unlock(&subscriber->room->mutex);
						if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || !publisher->session->started) {
							JANUS_LOG(LOG_WARN, "Publisher '%"SCNu64"' not found, not unsubscribing...\n", feed_id);
							continue;
						}
						/* Are we unsubscribing from the publisher as a whole or only a single stream? */
						const char *mid = json_string_value(json_object_get(s, "mid"));
						/* Iterate on all subscriptions, and remove those that don't match */
						GList *temp = subscriber->streams;
						while(temp) {
							/* We need more fine grained mechanisms for changing streaming properties */
							janus_videoroom_subscriber_stream *stream = (janus_videoroom_subscriber_stream *)temp->data;
							janus_videoroom_publisher_stream *ps = NULL;
							GSList *list = stream->publisher_streams;
							while(list) {
								ps = list->data;
								if(ps == NULL || ps->publisher != publisher) {
									/* Not the publisher we're interested in */
									list = list->next;
									continue;
								}
								if(mid && ps->mid && strcasecmp(ps->mid, mid)) {
									/* Not the mid we're interested in */
									list = list->next;
									continue;
								}
								janus_videoroom_subscriber_stream_remove(stream, ps, TRUE);
								if(stream->type != JANUS_VIDEOROOM_MEDIA_DATA)
									changes++;
								list = list->next;
							}
							temp = temp->next;
						}
					}
				}
				if(changes == 0) {
					janus_mutex_unlock(&subscriber->streams_mutex);
					/* Nothing changes, don't do anything */
					JANUS_LOG(LOG_VERB, "No unsubscription done, skipping renegotiation\n");
					janus_videoroom_message_free(msg);
					continue;
				}
				if(!g_atomic_int_get(&subscriber->answered)) {
					/* We're still waiting for an answer to a previous offer, postpone this */
					g_atomic_int_set(&subscriber->pending_offer, 1);
					janus_mutex_unlock(&subscriber->streams_mutex);
					JANUS_LOG(LOG_VERB, "Post-poning new offer, waiting for previous answer\n");
					janus_videoroom_message_free(msg);
					continue;
				}
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("updated"));
				json_object_set_new(event, "room", json_integer(subscriber->room_id));
				json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
				json_object_set_new(event, "streams", media);
				/* Generate a new offer */
				json_t *jsep = janus_videoroom_subscriber_offer(subscriber);
				janus_mutex_unlock(&subscriber->streams_mutex);
				/* How long will the Janus core take to push the event? */
				gint64 start = janus_get_monotonic_time();
				int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, jsep);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
				json_decref(event);
				json_decref(jsep);
				/* Done */
				janus_videoroom_message_free(msg);
				continue;
			} else if(!strcasecmp(request_text, "configure")) {
				JANUS_VALIDATE_JSON_OBJECT(root, configure_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				if(subscriber->kicked) {
					JANUS_LOG(LOG_ERR, "Unauthorized, you have been kicked\n");
					error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED;
					g_snprintf(error_cause, 512, "Unauthorized, you have been kicked");
					goto error;
				}
				/* Audio, video and data are deprecated properties */
				json_t *audio = json_object_get(root, "audio");
				json_t *video = json_object_get(root, "video");
				json_t *data = json_object_get(root, "data");
				/* Better to specify the 'send' property of a specific 'mid' */
				const char *mid = json_string_value(json_object_get(root, "mid"));
				json_t *send = json_object_get(root, "send");
				json_t *restart = json_object_get(root, "restart");
				json_t *update = json_object_get(root, "update");
				json_t *spatial = json_object_get(root, "spatial_layer");
				json_t *sc_substream = json_object_get(root, "substream");
				if(json_integer_value(spatial) < 0 || json_integer_value(spatial) > 2 ||
						json_integer_value(sc_substream) < 0 || json_integer_value(sc_substream) > 2) {
					JANUS_LOG(LOG_ERR, "Invalid element (substream/spatial_layer should be 0, 1 or 2)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (substream/spatial_layer should be 0, 1 or 2)");
					goto error;
				}
				json_t *temporal = json_object_get(root, "temporal_layer");
				json_t *sc_temporal = json_object_get(root, "temporal");
				if(json_integer_value(temporal) < 0 || json_integer_value(temporal) > 2 ||
						json_integer_value(sc_temporal) < 0 || json_integer_value(sc_temporal) > 2) {
					JANUS_LOG(LOG_ERR, "Invalid element (temporal/temporal_layer should be 0, 1 or 2)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (temporal/temporal_layer should be 0, 1 or 2)");
					goto error;
				}
				/* Update the audio/video/data flags, if set */
				janus_mutex_lock(&subscriber->streams_mutex);
				GList *temp = subscriber->streams;
				while(temp) {
					/* We need more fine grained mechanisms for changing streaming properties */
					janus_videoroom_subscriber_stream *stream = (janus_videoroom_subscriber_stream *)temp->data;
					janus_videoroom_publisher_stream *ps = stream->publisher_streams ? stream->publisher_streams->data : NULL;
					if(audio && stream->type == JANUS_VIDEOROOM_MEDIA_AUDIO) {
						gboolean oldaudio = stream->send;
						gboolean newaudio = json_is_true(audio);
						if(!oldaudio && newaudio) {
							/* Audio just resumed, reset the RTP sequence numbers */
							stream->context.seq_reset = TRUE;
						}
						stream->send = newaudio;
					}
					if(video && stream->type == JANUS_VIDEOROOM_MEDIA_VIDEO) {
						gboolean oldvideo = stream->send;
						gboolean newvideo = json_is_true(video);
						if(!oldvideo && newvideo) {
							/* Audio just resumed, reset the RTP sequence numbers */
							stream->context.seq_reset = TRUE;
						}
						stream->send = newvideo;
						if(newvideo) {
							/* Send a PLI */
							janus_videoroom_reqpli(ps, "Restoring video for subscriber");
						}
					}
					if(data && stream->type == JANUS_VIDEOROOM_MEDIA_DATA)
						stream->send = json_is_true(data);
					/* Let's also see if this is the right mid */
					if(mid && strcasecmp(stream->mid, mid)) {
						temp = temp->next;
						continue;
					}
					if(send) {
						gboolean oldsend = stream->send;
						gboolean newsend = json_is_true(send);
						if(!oldsend && newsend) {
							/* Medium just resumed, reset the RTP sequence numbers */
							stream->context.seq_reset = TRUE;
						}
						stream->send = json_is_true(send);
					}
					/* Next properties are for video only */
					if(stream->type != JANUS_VIDEOROOM_MEDIA_VIDEO) {
						temp = temp->next;
						continue;
					}
					/* Check if a simulcasting-related request is involved */
					if(ps && ps->simulcast) {
						if(sc_substream) {
							stream->sim_context.substream_target = json_integer_value(sc_substream);
							JANUS_LOG(LOG_VERB, "Setting video SSRC to let through (simulcast): %"SCNu32" (index %d, was %d)\n",
								ps->vssrc[stream->sim_context.substream],
								stream->sim_context.substream_target,
								stream->sim_context.substream);
							if(stream->sim_context.substream_target == stream->sim_context.substream) {
								/* No need to do anything, we're already getting the right substream, so notify the user */
								json_t *event = json_object();
								json_object_set_new(event, "videoroom", json_string("event"));
								json_object_set_new(event, "room", json_integer(subscriber->room_id));
								json_object_set_new(event, "mid", json_string(stream->mid));
								json_object_set_new(event, "substream", json_integer(stream->sim_context.substream));
								gateway->push_event(msg->handle, &janus_videoroom_plugin, NULL, event, NULL);
								json_decref(event);
							} else {
								/* Send a PLI */
								janus_videoroom_reqpli(ps, "Simulcasting substream change");
							}
						}
						if(ps->vcodec == JANUS_VIDEOCODEC_VP8 && ps->simulcast && sc_temporal) {
							stream->sim_context.templayer_target = json_integer_value(sc_temporal);
							JANUS_LOG(LOG_VERB, "Setting video temporal layer to let through (simulcast): %d (was %d)\n",
								stream->sim_context.templayer_target, stream->sim_context.templayer);
							if(stream->sim_context.templayer_target == stream->sim_context.templayer) {
								/* No need to do anything, we're already getting the right temporal, so notify the user */
								json_t *event = json_object();
								json_object_set_new(event, "videoroom", json_string("event"));
								json_object_set_new(event, "room", json_integer(subscriber->room_id));
								json_object_set_new(event, "mid", json_string(stream->mid));
								json_object_set_new(event, "temporal", json_integer(stream->sim_context.templayer));
								gateway->push_event(msg->handle, &janus_videoroom_plugin, NULL, event, NULL);
								json_decref(event);
							} else {
								/* Send a PLI */
								janus_videoroom_reqpli(ps, "Simulcasting temporal layer change");
							}
						}
					} else if(ps->svc) {
						/* Also check if the viewer is trying to configure a layer change */
						if(spatial) {
							int spatial_layer = json_integer_value(spatial);
							if(spatial_layer > 1) {
								JANUS_LOG(LOG_WARN, "Spatial layer higher than 1, will probably be ignored\n");
							}
							if(spatial_layer == stream->spatial_layer) {
								/* No need to do anything, we're already getting the right spatial layer, so notify the user */
								json_t *event = json_object();
								json_object_set_new(event, "videoroom", json_string("event"));
								json_object_set_new(event, "room", json_integer(subscriber->room_id));
								json_object_set_new(event, "mid", json_string(stream->mid));
								json_object_set_new(event, "spatial_layer", json_integer(stream->spatial_layer));
								gateway->push_event(msg->handle, &janus_videoroom_plugin, NULL, event, NULL);
								json_decref(event);
							} else if(spatial_layer != stream->target_spatial_layer) {
								/* Send a PLI to the new RTP forward publisher */
								janus_videoroom_reqpli(ps, "Need to downscale spatially");
							}
							stream->target_spatial_layer = spatial_layer;
						}
						if(temporal) {
							int temporal_layer = json_integer_value(temporal);
							if(temporal_layer > 2) {
								JANUS_LOG(LOG_WARN, "Temporal layer higher than 2, will probably be ignored\n");
							}
							if(temporal_layer == stream->temporal_layer) {
								/* No need to do anything, we're already getting the right temporal layer, so notify the user */
								json_t *event = json_object();
								json_object_set_new(event, "videoroom", json_string("event"));
								json_object_set_new(event, "room", json_integer(subscriber->room_id));
								json_object_set_new(event, "mid", json_string(stream->mid));
								json_object_set_new(event, "temporal_layer", json_integer(stream->temporal_layer));
								gateway->push_event(msg->handle, &janus_videoroom_plugin, NULL, event, NULL);
								json_decref(event);
							}
							stream->target_temporal_layer = temporal_layer;
						}
					}
					temp = temp->next;
				}
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(subscriber->room_id));
				json_object_set_new(event, "configured", json_string("ok"));
				/* The user may be interested in an ICE restart */
				gboolean do_restart = restart ? json_is_true(restart) : FALSE;
				gboolean do_update = update ? json_is_true(update) : FALSE;
				if(sdp_update || do_restart || do_update) {
					/* Negotiate by sending the selected publisher SDP back, and/or force an ICE restart */
					if(!g_atomic_int_get(&subscriber->answered)) {
						/* We're still waiting for an answer to a previous offer, postpone this */
						g_atomic_int_set(&subscriber->pending_offer, 1);
						g_atomic_int_set(&subscriber->pending_restart, 1);
						janus_mutex_unlock(&subscriber->streams_mutex);
						JANUS_LOG(LOG_VERB, "Post-poning new ICE restart offer, waiting for previous answer\n");
						janus_videoroom_message_free(msg);
						continue;
					}
					json_t *jsep = janus_videoroom_subscriber_offer(subscriber);
					janus_mutex_unlock(&subscriber->streams_mutex);
					if(do_restart)
						json_object_set_new(jsep, "restart", json_true());
					/* How long will the Janus core take to push the event? */
					gint64 start = janus_get_monotonic_time();
					int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, jsep);
					JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
					json_decref(event);
					json_decref(jsep);
					/* Done */
					janus_videoroom_message_free(msg);
					continue;
				}
				janus_mutex_unlock(&subscriber->streams_mutex);
			} else if(!strcasecmp(request_text, "pause")) {
				/* Stop receiving the publisher streams for a while */
				subscriber->paused = TRUE;
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(subscriber->room_id));
				json_object_set_new(event, "paused", json_string("ok"));
			} else if(!strcasecmp(request_text, "switch")) {
				/* This subscriber wants to switch to a different publisher */
				JANUS_VALIDATE_JSON_OBJECT(root, switch_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(!subscriber->room || g_atomic_int_get(&subscriber->room->destroyed)) {
					JANUS_LOG(LOG_ERR, "Room Destroyed \n");
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
					g_snprintf(error_cause, 512, "No such room ");
					goto error;
				}
				if(g_atomic_int_get(&subscriber->destroyed)) {
					JANUS_LOG(LOG_ERR, "Room Destroyed (%"SCNu64")\n", subscriber->room_id);
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
					g_snprintf(error_cause, 512, "No such room (%"SCNu64")", subscriber->room_id);
					goto error;
				}
				/* While the legacy way of switching by just providing a feed ID is
				 * still supported (at least for now), it isn't flexible enough: the
				 * new proper way of doing that is providing the list of changes that
				 * need to be done, in terms of which stream to switch to, and which
				 * subscription mid to attach it to. This allows for partial switches
				 * (e.g., change the second video source to Bob's camera), while the
				 * old approach simply forces a single publisher as the new source. */
				json_t *feeds = json_object_get(root, "streams");
				json_t *feed = json_object_get(root, "feed");
				GList *publishers = NULL;
				if(feeds == NULL || json_array_size(feeds) == 0) {
					/* For backwards compatibility, we still support the old "feed" property, which means
					 * "switch to all the feeds from this publisher" (much less sophisticated, though) */
					guint64 feed_id = json_integer_value(feed);
					if(feed_id == 0) {
						JANUS_LOG(LOG_ERR, "At least one between 'streams' and 'feed' must be specified\n");
						error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
						g_snprintf(error_cause, 512, "At least one between 'streams' and 'feed' must be specified");
						goto error;
					}
					janus_mutex_lock(&subscriber->room->mutex);
					janus_videoroom_publisher *publisher = g_hash_table_lookup(subscriber->room->participants, &feed_id);
					janus_mutex_unlock(&subscriber->room->mutex);
					if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || !publisher->session->started) {
						JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
						error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
						g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", feed_id);
						goto error;
					}
					/* Create a fake "streams" list out of this publisher */
					feeds = json_array();
					json_object_set_new(root, "streams", feeds);
					janus_refcount_increase(&publisher->ref);
					GList *temp = publisher->streams, *touched_already = NULL;
					while(temp) {
						janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
						/* Look for a subscriber stream compatible with this publisher stream */
						janus_videoroom_subscriber_stream *stream = NULL;
						GList *temp2 = subscriber->streams;
						while(temp2) {
							stream = (janus_videoroom_subscriber_stream *)temp->data;
							if(stream->type == ps->type && !g_list_find(touched_already, stream) &&
									((stream->type == JANUS_VIDEOROOM_MEDIA_AUDIO && stream->acodec == ps->acodec) ||
									(stream->type == JANUS_VIDEOROOM_MEDIA_VIDEO && stream->vcodec == ps->vcodec))) {
								/* This streams looks right */
								touched_already = g_list_append(touched_already, stream);
								json_t *s = json_object();
								json_object_set_new(s, "feed", json_integer(publisher->user_id));
								json_object_set_new(s, "mid", json_string(ps->mid));
								json_object_set_new(s, "sub_mid", json_string(stream->mid));
								json_array_append_new(feeds, s);
							} else {
								JANUS_LOG(LOG_WARN, "Skipping %"SCNu64" stream '%s' legacy switch: no compliant subscriber stream\n",
									publisher->user_id, ps->mid);
							}
							temp2 = temp2->next;
						}
						temp = temp->next;
					}
					g_list_free(touched_already);
					janus_refcount_decrease(&publisher->ref);
					/* Take note of the fact this is a legacy request */
					JANUS_LOG(LOG_WARN, "Legacy 'switch' request: please start using the streams array instead\n");
				}
				/* If we got here, we have a feeds list: make sure we have everything we need */
				if(json_array_size(feeds) == 0) {
					JANUS_LOG(LOG_ERR, "Empty switch list\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Empty switch list");
					goto error;
				}
				/* Make sure all the feeds we're subscribing to exist */
				size_t i = 0;
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *s = json_array_get(feeds, i);
					JANUS_VALIDATE_JSON_OBJECT(s, switch_update_parameters,
						error_code, error_cause, TRUE,
						JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
					if(error_code != 0) {
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					json_t *feed = json_object_get(s, "feed");
					guint64 feed_id = json_integer_value(feed);
					janus_mutex_lock(&subscriber->room->mutex);
					janus_videoroom_publisher *publisher = g_hash_table_lookup(subscriber->room->participants, &feed_id);
					janus_mutex_unlock(&subscriber->room->mutex);
					if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || !publisher->session->started) {
						JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
						error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
						g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", feed_id);
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					const char *mid = json_string_value(json_object_get(s, "mid"));
					/* Check the mid too */
					janus_mutex_lock(&publisher->streams_mutex);
					if(g_hash_table_lookup(publisher->streams_bymid, mid) == NULL) {
						janus_mutex_unlock(&publisher->streams_mutex);
						JANUS_LOG(LOG_ERR, "No such mid '%s' in feed (%"SCNu64")\n", mid, feed_id);
						error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
						g_snprintf(error_cause, 512, "No such mid '%s' in feed (%"SCNu64")", mid, feed_id);
						/* Unref publishers we may have taken note of so far */
						while(publishers) {
							publisher = (janus_videoroom_publisher *)publishers->data;
							janus_refcount_decrease(&publisher->ref);
							janus_refcount_decrease(&publisher->session->ref);
							publishers = g_list_remove(publishers, publisher);
						}
						goto error;
					}
					janus_mutex_unlock(&publisher->streams_mutex);
					/* Increase the refcount before unlocking so that nobody can remove and free the publisher in the meantime. */
					janus_refcount_increase(&publisher->ref);
					janus_refcount_increase(&publisher->session->ref);
					publishers = g_list_append(publishers, publisher);
				}
				gboolean paused = subscriber->paused;
				subscriber->paused = TRUE;
				/* Switch to the new streams, unsubscribing from the ones we replace:
				 * notice that no renegotiation happens, we just switch the sources */
				int changes = 0;
				gboolean update = FALSE;
				janus_mutex_lock(&subscriber->streams_mutex);
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *s = json_array_get(feeds, i);
					/* Look for the specific subscription mid to update */
					const char *sub_mid = json_string_value(json_object_get(s, "sub_mid"));
					janus_videoroom_subscriber_stream *stream = g_hash_table_lookup(subscriber->streams_bymid, sub_mid);
					if(stream == NULL) {
						JANUS_LOG(LOG_WARN, "Subscriber stream with mid '%s' not found, not switching...\n", sub_mid);
						continue;
					}
					/* Look for the publisher stream to switch to */
					json_t *feed = json_object_get(s, "feed");
					guint64 feed_id = json_integer_value(feed);
					const char *mid = json_string_value(json_object_get(s, "mid"));
					janus_mutex_lock(&subscriber->room->mutex);
					janus_videoroom_publisher *publisher = g_hash_table_lookup(subscriber->room->participants, &feed_id);
					janus_mutex_unlock(&subscriber->room->mutex);
					if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || !publisher->session->started) {
						JANUS_LOG(LOG_WARN, "Publisher '%"SCNu64"' not found, not switching...\n", feed_id);
						continue;
					}
					janus_mutex_lock(&publisher->streams_mutex);
					janus_videoroom_publisher_stream *ps = g_hash_table_lookup(publisher->streams_bymid, mid);
					janus_mutex_unlock(&publisher->streams_mutex);
					if(ps == NULL || g_atomic_int_get(&ps->destroyed)) {
						JANUS_LOG(LOG_WARN, "Publisher '%"SCNu64"' doesn't have any mid '%s', not switching...\n", feed_id, mid);
						continue;
					}
					/* If this mapping already exists, do nothing */
					if(g_slist_find(stream->publisher_streams, ps) != NULL) {
						JANUS_LOG(LOG_WARN, "Publisher '%"SCNu64"'/'%s' is already feeding mid '%s', not switching...\n",
							feed_id, mid, sub_mid);
						continue;
					}
					/* If the streams are not of the same type, do nothing */
					if(stream->type != ps->type) {
						JANUS_LOG(LOG_WARN, "Publisher '%"SCNu64"'/'%s' is not the same type as subscription mid '%s', not switching...\n",
							feed_id, mid, sub_mid);
						continue;
					}
					/* If the streams are not using the same codec, do nothing */
					if((stream->type == JANUS_VIDEOROOM_MEDIA_AUDIO && stream->acodec != ps->acodec) ||
							(stream->type == JANUS_VIDEOROOM_MEDIA_VIDEO && stream->vcodec != ps->vcodec)) {
						JANUS_LOG(LOG_WARN, "Publisher '%"SCNu64"'/'%s' is not using same codec as subscription mid '%s', not switching...\n",
							feed_id, mid, sub_mid);
						continue;
					}
					/* Unsubscribe the old stream and update it: we don't replace streams like we
					 * do when doing new subscriptions, as that might change payload type, etc. */
					changes++;
					/* Unsubscribe from the previous source first */
					janus_refcount_increase(&stream->ref);
					gboolean unref = FALSE;
					if(stream->publisher_streams == NULL) {
						/* This stream was inactive, we'll need a renegotiation */
						update = TRUE;
					} else {
						unref = TRUE;
						janus_videoroom_publisher_stream *stream_ps = stream->publisher_streams->data;
						janus_mutex_lock(&stream_ps->subscribers_mutex);
						stream_ps->subscribers = g_slist_remove(stream_ps->subscribers, stream);
						stream->publisher_streams = g_slist_remove(stream->publisher_streams, stream_ps);
						janus_mutex_unlock(&stream_ps->subscribers_mutex);
						janus_refcount_decrease(&stream_ps->ref);
					}
					/* Subscribe to the new one */
					janus_mutex_lock(&ps->subscribers_mutex);
					stream->publisher_streams = g_slist_append(stream->publisher_streams, ps);
					ps->subscribers = g_slist_append(ps->subscribers, stream);
					janus_refcount_increase(&ps->ref);
					janus_refcount_increase(&stream->ref);
					janus_mutex_unlock(&ps->subscribers_mutex);
					janus_videoroom_reqpli(ps, "Subscriber switch");
					if(unref)
						janus_refcount_decrease(&stream->ref);
					janus_refcount_decrease(&stream->ref);
				}
				janus_mutex_unlock(&subscriber->streams_mutex);
				/* Decrease the references we took before */
				while(publishers) {
					janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)publishers->data;
					janus_refcount_decrease(&publisher->ref);
					janus_refcount_decrease(&publisher->session->ref);
					publishers = g_list_remove(publishers, publisher);
				}
				/* Done */
				subscriber->paused = paused;
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "switched", json_string("ok"));
				json_object_set_new(event, "room", json_integer(subscriber->room_id));
				json_object_set_new(event, "changes", json_integer(changes));
				json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
				json_object_set_new(event, "streams", media);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("switched"));
					json_object_set_new(info, "room", json_integer(subscriber->room_id));
					json_object_set_new(event, "changes", json_integer(changes));
					media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
					json_object_set_new(event, "streams", media);
					gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
				}
				/* Check if we need a renegotiation as well */
				if(update) {
					/* We do */
					janus_mutex_lock(&subscriber->streams_mutex);
					if(!g_atomic_int_get(&subscriber->answered)) {
						/* We're still waiting for an answer to a previous offer, postpone this */
						g_atomic_int_set(&subscriber->pending_offer, 1);
						janus_mutex_unlock(&subscriber->streams_mutex);
						JANUS_LOG(LOG_VERB, "Post-poning new offer, waiting for previous answer\n");
					} else {
						json_t *revent = json_object();
						json_object_set_new(revent, "videoroom", json_string("updated"));
						json_object_set_new(revent, "room", json_integer(subscriber->room_id));
						json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
						json_object_set_new(revent, "streams", media);
						/* Generate a new offer */
						json_t *jsep = janus_videoroom_subscriber_offer(subscriber);
						janus_mutex_unlock(&subscriber->streams_mutex);
						/* How long will the Janus core take to push the event? */
						gint64 start = janus_get_monotonic_time();
						int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, revent, jsep);
						JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
						json_decref(revent);
						json_decref(jsep);
						/* Also notify event handlers */
						if(notify_events && gateway->events_is_enabled()) {
							json_t *info = json_object();
							json_object_set_new(info, "event", json_string("updated"));
							json_object_set_new(info, "room", json_integer(subscriber->room_id));
							json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
							json_object_set_new(info, "streams", media);
							json_object_set_new(info, "private_id", json_integer(subscriber->pvt_id));
							gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
						}
					}
				}
			} else if(!strcasecmp(request_text, "leave")) {
				guint64 room_id = subscriber ? subscriber->room_id : 0;
				/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
				janus_videoroom_hangup_media(session->handle);
				gateway->close_pc(session->handle);
				/* Send an event back */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(room_id));
				json_object_set_new(event, "left", json_string("ok"));
				session->started = FALSE;
			} else {
				JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
				g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
				goto error;
			}
		}

		/* Prepare JSON event */
		JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
		/* Any SDP or update to handle? */
		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		json_t *msg_simulcast = json_object_get(msg->jsep, "simulcast");
		if(!msg_sdp) {
			/* No SDP to send */
			int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
		} else {
			/* Generate offer or answer */
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			if(sdp_update) {
				/* Renegotiation: make sure the user provided an offer, and send answer */
				JANUS_LOG(LOG_VERB, "  -- Updating existing publisher\n");
				session->sdp_version++;		/* This needs to be increased when it changes */
			} else {
				/* New PeerConnection */
				session->sdp_version = 1;	/* This needs to be increased when it changes */
				session->sdp_sessid = janus_get_real_time();
			}
			const char *type = NULL;
			if(!strcasecmp(msg_sdp_type, "offer")) {
				/* We need to answer */
				type = "answer";
			} else if(!strcasecmp(msg_sdp_type, "answer")) {
				/* We got an answer (from a subscriber?), no need to negotiate */
				g_atomic_int_set(&session->hangingup, 0);
				int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				json_decref(event);
				/* Take note of the fact we got our answer */
				janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)session->participant;
				janus_mutex_lock(&subscriber->streams_mutex);
				/* Mark all streams that were answered to as ready */
				char error_str[512];
				janus_sdp *answer = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
				GList *temp = answer->m_lines;
				while(temp) {
					janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
					if(m->direction != JANUS_SDP_INACTIVE) {
						janus_videoroom_subscriber_stream *stream = g_hash_table_lookup(subscriber->streams_byid, GINT_TO_POINTER(m->index));
						if(stream)
							g_atomic_int_set(&stream->ready, 1);
					}
					temp = temp->next;
				}
				janus_sdp_destroy(answer);
				janus_videoroom_message_free(msg);
				/* Check if we have other pending offers to send for this subscriber */
				if(g_atomic_int_compare_and_exchange(&subscriber->pending_offer, 1, 0)) {
					JANUS_LOG(LOG_VERB, "Pending offer, sending it now\n");
					event = json_object();
					json_object_set_new(event, "videoroom", json_string("updated"));
					json_object_set_new(event, "room", json_integer(subscriber->room_id));
					json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
					json_object_set_new(event, "streams", media);
					/* Generate a new offer */
					json_t *jsep = janus_videoroom_subscriber_offer(subscriber);
					/* Do we need an ICE restart as well? */
					if(g_atomic_int_compare_and_exchange(&subscriber->pending_restart, 1, 0))
						json_object_set_new(jsep, "restart", json_true());
					janus_mutex_unlock(&subscriber->streams_mutex);
					/* How long will the Janus core take to push the event? */
					gint64 start = janus_get_monotonic_time();
					int res = gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, jsep);
					JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
					json_decref(event);
					json_decref(jsep);
					/* Also notify event handlers */
					if(notify_events && gateway->events_is_enabled()) {
						json_t *info = json_object();
						json_object_set_new(info, "event", json_string("updated"));
						json_object_set_new(info, "room", json_integer(subscriber->room_id));
						json_t *media = janus_videoroom_subscriber_streams_summary(subscriber, FALSE, NULL);
						json_object_set_new(info, "streams", media);
						json_object_set_new(info, "private_id", json_integer(subscriber->pvt_id));
						gateway->notify_event(&janus_videoroom_plugin, session->handle, info);
					}
				} else {
					g_atomic_int_set(&subscriber->answered, 1);
					janus_mutex_unlock(&subscriber->streams_mutex);
				}
				continue;
			} else {
				/* TODO We don't support anything else right now... */
				JANUS_LOG(LOG_ERR, "Unknown SDP type '%s'\n", msg_sdp_type);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_SDP_TYPE;
				g_snprintf(error_cause, 512, "Unknown SDP type '%s'", msg_sdp_type);
				goto error;
			}
			if(session->participant_type != janus_videoroom_p_type_publisher) {
				/* We shouldn't be here, we always offer ourselves */
				JANUS_LOG(LOG_ERR, "Only publishers send offers\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_SDP_TYPE;
				g_snprintf(error_cause, 512, "Only publishers send offers");
				goto error;
			} else {
				/* This is a new publisher: is there room? */
				participant = janus_videoroom_session_get_publisher(session);
				janus_videoroom *videoroom = participant->room;
				int count = 0;
				GHashTableIter iter;
				gpointer value;
				if(!videoroom) {
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
					goto error;
				}
				if(g_atomic_int_get(&videoroom->destroyed)) {
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
					goto error;
				}
				janus_mutex_lock(&videoroom->mutex);
				g_hash_table_iter_init(&iter, videoroom->participants);
				while (!g_atomic_int_get(&videoroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_videoroom_publisher *p = value;
					if(p != participant && p->session->started)
						count++;
				}
				janus_mutex_unlock(&videoroom->mutex);
				if(count == videoroom->max_publishers) {
					JANUS_LOG(LOG_ERR, "Maximum number of publishers (%d) already reached\n", videoroom->max_publishers);
					error_code = JANUS_VIDEOROOM_ERROR_PUBLISHERS_FULL;
					g_snprintf(error_cause, 512, "Maximum number of publishers (%d) already reached", videoroom->max_publishers);
					goto error;
				}
				/* Now prepare the SDP to give back */
				if(strstr(msg_sdp, "mozilla") || strstr(msg_sdp, "Mozilla")) {
					participant->firefox = TRUE;
				}
				/* Start by parsing the offer */
				char error_str[512];
				janus_sdp *offer = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
				if(offer == NULL) {
					json_decref(event);
					JANUS_LOG(LOG_ERR, "Error parsing offer: %s\n", error_str);
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_SDP;
					g_snprintf(error_cause, 512, "Error parsing offer: %s", error_str);
					goto error;
				}
				/* Prepare an answer, by iterating on all m-lines */
				janus_sdp *answer = janus_sdp_generate_answer(offer);
				json_t *media = json_array();
				json_t *descriptions = json_object_get(root, "descriptions");
				const char *audiocodec = NULL, *videocodec = NULL;
				GList *temp = offer->m_lines;
				while(temp) {
					/* Which media are available? */
					janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
					/* Initialize a new publisher stream */
					janus_videoroom_publisher_stream *ps = g_malloc0(sizeof(janus_videoroom_publisher_stream));
					ps->type = JANUS_VIDEOROOM_MEDIA_NONE;
					if(m->type == JANUS_SDP_AUDIO)
						ps->type = JANUS_VIDEOROOM_MEDIA_AUDIO;
					else if(m->type == JANUS_SDP_VIDEO)
						ps->type = JANUS_VIDEOROOM_MEDIA_VIDEO;
					if(m->type == JANUS_SDP_APPLICATION)
						ps->type = JANUS_VIDEOROOM_MEDIA_DATA;
					ps->mindex = g_list_length(participant->streams);
					ps->publisher = participant;
					janus_refcount_increase(&participant->ref);	/* Add a reference to the publisher */
					/* Initialize the stream */
					ps->active = TRUE;
					g_atomic_int_set(&ps->destroyed, 0);
					janus_refcount_init(&ps->ref, janus_videoroom_publisher_stream_free);
					janus_refcount_increase(&ps->ref);	/* This is for the mid-indexed hashtable */
					janus_mutex_init(&ps->subscribers_mutex);
					janus_mutex_init(&ps->rtp_forwarders_mutex);
					ps->rtp_forwarders = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_videoroom_rtp_forwarder_destroy);
					if(m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) {
						/* Are the extmaps we care about there? */
						GList *ma = m->attributes;
						while(ma) {
							janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
							if(a->name && a->value) {
								if(ps->mid == NULL && !strcasecmp(a->name, "mid")) {
									ps->mid = g_strdup(a->value);
								} else if(videoroom->audiolevel_ext && m->type == JANUS_SDP_AUDIO && strstr(a->value, JANUS_RTP_EXTMAP_AUDIO_LEVEL)) {
									ps->audio_level_extmap_id = atoi(a->value);
								} else if(videoroom->videoorient_ext && m->type == JANUS_SDP_VIDEO && strstr(a->value, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION)) {
									ps->video_orient_extmap_id = atoi(a->value);
								} else if(videoroom->playoutdelay_ext && m->type == JANUS_SDP_VIDEO && strstr(a->value, JANUS_RTP_EXTMAP_PLAYOUT_DELAY)) {
									ps->playout_delay_extmap_id = atoi(a->value);
								} else if(videoroom->do_opusfec && m->type == JANUS_SDP_AUDIO && !strcasecmp(a->name, "fmtp") && strstr(a->value, "useinbandfec=1")) {
									ps->opusfec = TRUE;
								}
							}
							ma = ma->next;
						}
					}
					/* Check the codecs we can use, or the ones we should */
					ps->acodec = JANUS_AUDIOCODEC_NONE;
					ps->vcodec = JANUS_VIDEOCODEC_NONE;
					ps->pt = -1;
					if(m->type == JANUS_SDP_AUDIO) {
						int i=0;
						for(i=0; i<3; i++) {
							if(videoroom->acodec[i] == JANUS_AUDIOCODEC_NONE)
								continue;
							if(janus_sdp_get_codec_pt(offer, m->index, janus_audiocodec_name(videoroom->acodec[i])) != -1) {
								ps->acodec = videoroom->acodec[i];
								ps->pt = janus_audiocodec_pt(ps->acodec);
								break;
							}
						}
					} else if(m->type == JANUS_SDP_VIDEO) {
						int i=0;
						for(i=0; i<3; i++) {
							if(videoroom->vcodec[i] == JANUS_VIDEOCODEC_NONE)
								continue;
							if(janus_sdp_get_codec_pt(offer, m->index, janus_videocodec_name(videoroom->vcodec[i])) != -1) {
								ps->vcodec = videoroom->vcodec[i];
								ps->pt = janus_videocodec_pt(ps->vcodec);
								break;
							}
						}
						/* Check if simulcast is in place */
						if(msg_simulcast != NULL && json_array_size(msg_simulcast) > 0 &&
								(ps->vcodec == JANUS_VIDEOCODEC_VP8 || ps->vcodec == JANUS_VIDEOCODEC_H264)) {
							size_t i = 0;
							for(i=0; i<json_array_size(msg_simulcast); i++) {
								json_t *s = json_array_get(msg_simulcast, i);
								int mindex = json_integer_value(json_object_get(s, "mindex"));
								if(mindex != ps->mindex)
									continue;
								JANUS_LOG(LOG_WARN, "Publisher stream is going to do simulcasting (#%d, %s)\n", ps->mindex, ps->mid);
								ps->simulcast = TRUE;
								janus_rtp_simulcasting_prepare(msg_simulcast,
									&ps->rid_extmap_id,
									&ps->framemarking_ext_id,
									ps->vssrc, ps->rid);
							}
						}
					}
					/* Add a new m-line to the answer */
					if(m->type == JANUS_SDP_AUDIO) {
						janus_sdp_generate_answer_mline(offer, answer, m,
							JANUS_SDP_OA_MLINE, JANUS_SDP_AUDIO,
								JANUS_SDP_OA_DIRECTION, ps->acodec != JANUS_AUDIOCODEC_NONE ? JANUS_SDP_RECVONLY : JANUS_SDP_INACTIVE,
								JANUS_SDP_OA_CODEC, janus_audiocodec_name(ps->acodec),
								JANUS_SDP_OA_FMTP, ps->opusfec ? "useinbandfec=1" : NULL,
								JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_MID,
								JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_RID,
								JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_REPAIRED_RID,
								JANUS_SDP_OA_ACCEPT_EXTMAP, videoroom->audiolevel_ext ? JANUS_RTP_EXTMAP_AUDIO_LEVEL : NULL,
								JANUS_SDP_OA_ACCEPT_EXTMAP, videoroom->videoorient_ext ? JANUS_RTP_EXTMAP_VIDEO_ORIENTATION : NULL,
								JANUS_SDP_OA_ACCEPT_EXTMAP, videoroom->playoutdelay_ext ? JANUS_RTP_EXTMAP_PLAYOUT_DELAY : NULL,
								JANUS_SDP_OA_ACCEPT_EXTMAP, videoroom->transport_wide_cc_ext ? JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC : NULL,
							JANUS_SDP_OA_DONE);
						janus_sdp_mline *m_answer = janus_sdp_mline_find_by_index(answer, m->index);
						if(m_answer != NULL) {
							/* TODO Remove, this is just here for backwards compatibility */
							if(audiocodec == NULL)
								audiocodec = janus_audiocodec_name(ps->acodec);
						}
					} else if(m->type == JANUS_SDP_VIDEO) {
						janus_sdp_generate_answer_mline(offer, answer, m,
							JANUS_SDP_OA_MLINE, JANUS_SDP_VIDEO,
								JANUS_SDP_OA_DIRECTION, ps->vcodec != JANUS_VIDEOCODEC_NONE ? JANUS_SDP_RECVONLY : JANUS_SDP_INACTIVE,
								JANUS_SDP_OA_CODEC, janus_videocodec_name(ps->vcodec),
								JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_MID,
								JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_RID,
								JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_REPAIRED_RID,
								JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_FRAME_MARKING,
								JANUS_SDP_OA_ACCEPT_EXTMAP, videoroom->audiolevel_ext ? JANUS_RTP_EXTMAP_AUDIO_LEVEL : NULL,
								JANUS_SDP_OA_ACCEPT_EXTMAP, videoroom->videoorient_ext ? JANUS_RTP_EXTMAP_VIDEO_ORIENTATION : NULL,
								JANUS_SDP_OA_ACCEPT_EXTMAP, videoroom->playoutdelay_ext ? JANUS_RTP_EXTMAP_PLAYOUT_DELAY : NULL,
								JANUS_SDP_OA_ACCEPT_EXTMAP, videoroom->transport_wide_cc_ext ? JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC : NULL,
							JANUS_SDP_OA_DONE);
						janus_sdp_mline *m_answer = janus_sdp_mline_find_by_index(answer, m->index);
						if(m_answer != NULL) {
							/* TODO Remove, this is just here for backwards compatibility */
							if(videocodec == NULL)
								videocodec = janus_videocodec_name(ps->vcodec);
							/* Also add a bandwidth SDP attribute if we're capping the bitrate in the room */
							if(videoroom->bitrate > 0 && videoroom->bitrate_cap) {
								if(participant->firefox) {
									/* Use TIAS (bps) instead of AS (kbps) for the b= attribute, as explained here:
									 * https://github.com/meetecho/janus-gateway/issues/1277#issuecomment-397677746 */
									m->b_name = g_strdup("TIAS");
									m->b_value = videoroom->bitrate;
								} else {
									m->b_name = g_strdup("AS");
									m->b_value = videoroom->bitrate/1000;
								}
							}
						}
					} else if(m->type == JANUS_SDP_APPLICATION) {
						janus_sdp_generate_answer_mline(offer, answer, m,
							JANUS_SDP_OA_MLINE, JANUS_SDP_APPLICATION,
							JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_MID,
							JANUS_SDP_OA_DONE);
					}
					/* Make sure we have a mid */
					if(ps->mid == NULL) {
						char mid[5];
						g_snprintf(mid, sizeof(mid), "%d", ps->mindex);
						ps->mid = g_strdup(mid);
					}
					/* Do we have a description as well? */
					if(descriptions != NULL && json_array_size(descriptions) > 0) {
						size_t i = 0;
						for(i=0; i<json_array_size(descriptions); i++) {
							json_t *d = json_array_get(descriptions, i);
							const char *d_mid = json_string_value(json_object_get(d, "mid"));
							const char *d_desc = json_string_value(json_object_get(d, "description"));
							if(d_desc && d_mid && ps->mid && !strcasecmp(d_mid, ps->mid)) {
								ps->description = g_strdup(d_desc);
								break;
							}
						}
					}
					/* Add the stream to the list */
					janus_mutex_lock(&participant->streams_mutex);
					participant->streams = g_list_append(participant->streams, ps);
					g_hash_table_insert(participant->streams_byid, GINT_TO_POINTER(ps->mindex), ps);
					g_hash_table_insert(participant->streams_bymid, g_strdup(ps->mid), ps);
					janus_mutex_unlock(&participant->streams_mutex);
					temp = temp->next;
					/* Add to the info we send back to the publisher */
					json_t *info = json_object();
					json_object_set_new(info, "type", json_string(janus_videoroom_media_str(ps->type)));
					json_object_set_new(info, "mindex", json_integer(ps->mindex));
					json_object_set_new(info, "mid", json_string(ps->mid));
					if(ps->description)
						json_object_set_new(info, "description", json_string(ps->description));
					if(ps->type == JANUS_VIDEOROOM_MEDIA_AUDIO) {
						json_object_set_new(info, "codec", json_string(janus_audiocodec_name(ps->acodec)));
						if(ps->opusfec)
							json_object_set_new(info, "opus-fec", json_true());
					} else if(ps->type == JANUS_VIDEOROOM_MEDIA_VIDEO) {
						json_object_set_new(info, "codec", json_string(janus_videocodec_name(ps->vcodec)));
						if(ps->simulcast)
							json_object_set_new(info, "simulcast", json_true());
						if(ps->svc)
							json_object_set_new(info, "svc", json_true());
					}
					json_array_append_new(media, info);
				}
				janus_sdp_destroy(offer);
				/* Replace the session name */
				g_free(answer->s_name);
				char s_name[100];
				g_snprintf(s_name, sizeof(s_name), "VideoRoom %"SCNu64, videoroom->room_id);
				answer->s_name = g_strdup(s_name);
				/* Generate an SDP string we can send back to the publisher */
				char *answer_sdp = janus_sdp_write(answer);
				janus_sdp_destroy(answer);
				/* For backwards compatibility, update the event with info on the codecs that we'll be handling
				 * TODO This will make no sense in the future, as different streams may use different codecs */
				if(event) {
					if(audiocodec)
						json_object_set_new(event, "audio_codec", json_string(audiocodec));
					if(videocodec)
						json_object_set_new(event, "video_codec", json_string(videocodec));
				}
				json_object_set_new(event, "streams", media);
				/* Is this room recorded, or are we recording this publisher already? */
				janus_mutex_lock(&participant->rec_mutex);
				if(videoroom->record || participant->recording_active) {
					GList *temp = participant->streams;
					while(temp) {
						janus_videoroom_publisher_stream *ps = (janus_videoroom_publisher_stream *)temp->data;
						janus_videoroom_recorder_create(ps);
						temp = temp->next;
					}
				}
				janus_mutex_unlock(&participant->rec_mutex);
				/* Send the answer back to the publisher */
				JANUS_LOG(LOG_VERB, "Handling publisher: turned this into an '%s':\n%s\n", type, answer_sdp);
				json_t *jsep = json_pack("{ssss}", "type", type, "sdp", answer_sdp);
				g_free(answer_sdp);
				/* How long will the Janus core take to push the event? */
				g_atomic_int_set(&session->hangingup, 0);
				gint64 start = janus_get_monotonic_time();
				int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, jsep);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
				/* Done */
				if(res != JANUS_OK) {
					/* TODO Failed to negotiate? We should remove this publisher */
				} else {
					/* We'll wait for the setup_media event before actually telling subscribers */
				}
				json_decref(event);
				json_decref(jsep);
			}
			if(participant != NULL)
				janus_refcount_decrease(&participant->ref);
		}
		janus_videoroom_message_free(msg);

		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "videoroom", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_videoroom_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving VideoRoom handler thread\n");
	return NULL;
}

/* Helper to quickly relay RTP packets from publishers to subscribers */
static void janus_videoroom_relay_rtp_packet(gpointer data, gpointer user_data) {
	janus_videoroom_rtp_relay_packet *packet = (janus_videoroom_rtp_relay_packet *)user_data;
	if(!packet || !packet->data || packet->length < 1) {
		JANUS_LOG(LOG_ERR, "Invalid packet...\n");
		return;
	}
	janus_videoroom_subscriber_stream *stream = (janus_videoroom_subscriber_stream *)data;
	if(!stream || !g_atomic_int_get(&stream->ready) || g_atomic_int_get(&stream->destroyed) ||
			!stream->send || !stream->publisher_streams ||
			!stream->subscriber || stream->subscriber->paused || stream->subscriber->kicked ||
			!stream->subscriber->session || !stream->subscriber->session->handle || !stream->subscriber->session->started)
		return;
	janus_videoroom_publisher_stream *ps = stream->publisher_streams->data;
	if(ps != packet->source)
		return;
	janus_videoroom_subscriber *subscriber = stream->subscriber;
	janus_videoroom_session *session = subscriber->session;

	/* Make sure there hasn't been a publisher switch by checking the SSRC */
	if(packet->is_video) {
		/* Check if there's any SVC info to take into account */
		if(packet->svc) {
			/* There is: check if this is a layer that can be dropped for this viewer
			 * Note: Following core inspired by the excellent job done by Sergio Garcia Murillo here:
			 * https://github.com/medooze/media-server/blob/master/src/vp9/VP9LayerSelector.cpp */
			gboolean override_mark_bit = FALSE, has_marker_bit = packet->data->markerbit;
			int temporal_layer = stream->temporal_layer;
			if(stream->target_temporal_layer > stream->temporal_layer) {
				/* We need to upscale */
				JANUS_LOG(LOG_HUGE, "We need to upscale temporally:\n");
				if(packet->ubit && packet->bbit && packet->temporal_layer <= stream->target_temporal_layer) {
					JANUS_LOG(LOG_HUGE, "  -- Upscaling temporal layer: %u --> %u\n",
						packet->temporal_layer, stream->target_temporal_layer);
					stream->temporal_layer = packet->temporal_layer;
					temporal_layer = stream->temporal_layer;
					/* Notify the viewer */
					json_t *event = json_object();
					json_object_set_new(event, "videoroom", json_string("event"));
					json_object_set_new(event, "room", json_integer(subscriber->room_id));
					json_object_set_new(event, "mid", json_string(stream->mid));
					json_object_set_new(event, "temporal_layer", json_integer(stream->temporal_layer));
					gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
					json_decref(event);
				}
			} else if(stream->target_temporal_layer < stream->temporal_layer) {
				/* We need to downscale */
				JANUS_LOG(LOG_HUGE, "We need to downscale temporally:\n");
				if(packet->ebit) {
					JANUS_LOG(LOG_HUGE, "  -- Downscaling temporal layer: %u --> %u\n",
						stream->temporal_layer, stream->target_temporal_layer);
					stream->temporal_layer = stream->target_temporal_layer;
					/* Notify the viewer */
					json_t *event = json_object();
					json_object_set_new(event, "videoroom", json_string("event"));
					json_object_set_new(event, "room", json_integer(subscriber->room_id));
					json_object_set_new(event, "mid", json_string(stream->mid));
					json_object_set_new(event, "temporal_layer", json_integer(stream->temporal_layer));
					gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
					json_decref(event);
				}
			}
			if(temporal_layer < packet->temporal_layer) {
				/* Drop the packet: update the context to make sure sequence number is increased normally later */
				JANUS_LOG(LOG_HUGE, "Dropping packet (temporal layer %d < %d)\n", temporal_layer, packet->temporal_layer);
				stream->context.base_seq++;
				return;
			}
			int spatial_layer = stream->spatial_layer;
			if(stream->target_spatial_layer > stream->spatial_layer) {
				JANUS_LOG(LOG_HUGE, "We need to upscale spatially:\n");
				/* We need to upscale */
				if(packet->pbit == 0 && packet->bbit && packet->spatial_layer == stream->spatial_layer+1) {
					JANUS_LOG(LOG_HUGE, "  -- Upscaling spatial layer: %u --> %u\n",
						packet->spatial_layer, stream->target_spatial_layer);
					stream->spatial_layer = packet->spatial_layer;
					spatial_layer = stream->spatial_layer;
					/* Notify the viewer */
					json_t *event = json_object();
					json_object_set_new(event, "videoroom", json_string("event"));
					json_object_set_new(event, "room", json_integer(subscriber->room_id));
					json_object_set_new(event, "mid", json_string(stream->mid));
					json_object_set_new(event, "spatial_layer", json_integer(stream->spatial_layer));
					gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
					json_decref(event);
				}
			} else if(stream->target_spatial_layer < stream->spatial_layer) {
				/* We need to downscale */
				JANUS_LOG(LOG_HUGE, "We need to downscale spatially:\n");
				if(packet->ebit) {
					JANUS_LOG(LOG_HUGE, "  -- Downscaling spatial layer: %u --> %u\n",
						stream->spatial_layer, stream->target_spatial_layer);
					stream->spatial_layer = stream->target_spatial_layer;
					/* Notify the viewer */
					json_t *event = json_object();
					json_object_set_new(event, "videoroom", json_string("event"));
					json_object_set_new(event, "room", json_integer(subscriber->room_id));
					json_object_set_new(event, "mid", json_string(stream->mid));
					json_object_set_new(event, "spatial_layer", json_integer(stream->spatial_layer));
					gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
					json_decref(event);
				}
			}
			if(spatial_layer < packet->spatial_layer) {
				/* Drop the packet: update the context to make sure sequence number is increased normally later */
				JANUS_LOG(LOG_HUGE, "Dropping packet (spatial layer %d < %d)\n", spatial_layer, packet->spatial_layer);
				stream->context.base_seq++;
				return;
			} else if(packet->ebit && spatial_layer == packet->spatial_layer) {
				/* If we stop at layer 0, we need a marker bit now, as the one from layer 1 will not be received */
				override_mark_bit = TRUE;
			}
			/* If we got here, we can send the frame: this doesn't necessarily mean it's
			 * one of the layers the user wants, as there may be dependencies involved */
			JANUS_LOG(LOG_HUGE, "Sending packet (spatial=%d, temporal=%d)\n",
				packet->spatial_layer, packet->temporal_layer);
			/* Fix sequence number and timestamp (publisher switching may be involved) */
			janus_rtp_header_update(packet->data, &stream->context, TRUE);
			if(override_mark_bit && !has_marker_bit) {
				packet->data->markerbit = 1;
			}
			if(gateway != NULL)
				gateway->relay_rtp(session->handle, ps->mindex, TRUE, (char *)packet->data, packet->length);
			if(override_mark_bit && !has_marker_bit) {
				packet->data->markerbit = 0;
			}
			/* Restore the timestamp and sequence number to what the publisher set them to */
			packet->data->timestamp = htonl(packet->timestamp);
			packet->data->seq_number = htons(packet->seq_number);
		} else if(packet->ssrc[0] != 0) {
			/* Handle simulcast: make sure we have a payload to work with */
			int plen = 0;
			char *payload = janus_rtp_payload((char *)packet->data, packet->length, &plen);
			if(payload == NULL)
				return;
			/* Process this packet: don't relay if it's not the SSRC/layer we wanted to handle */
			gboolean relay = janus_rtp_simulcasting_context_process_rtp(&stream->sim_context,
				(char *)packet->data, packet->length, packet->ssrc, NULL, ps->vcodec, &stream->context);
			/* Do we need to drop this? */
			if(!relay)
				return;
			/* Any event we should notify? */
			if(stream->sim_context.changed_substream) {
				/* Notify the user about the substream change */
				json_t *event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(subscriber->room_id));
				json_object_set_new(event, "mid", json_string(stream->mid));
				json_object_set_new(event, "substream", json_integer(stream->sim_context.substream));
				gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
				json_decref(event);
			}
			if(stream->sim_context.need_pli && ps->publisher && ps->publisher->session &&
					ps->publisher->session->handle) {
				/* Send a PLI */
				JANUS_LOG(LOG_VERB, "We need a PLI for the simulcast context\n");
				janus_videoroom_reqpli(ps, "Simulcast");
			}
			if(stream->sim_context.changed_temporal) {
				/* Notify the user about the temporal layer change */
				json_t *event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(subscriber->room_id));
				json_object_set_new(event, "mid", json_string(stream->mid));
				json_object_set_new(event, "temporal", json_integer(stream->sim_context.templayer));
				gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
				json_decref(event);
			}
			/* If we got here, update the RTP header and send the packet */
			janus_rtp_header_update(packet->data, &stream->context, TRUE);
			char vp8pd[6];
			if(ps->vcodec == JANUS_VIDEOCODEC_VP8) {
				/* For VP8, we save the original payload descriptor, to restore it after */
				memcpy(vp8pd, payload, sizeof(vp8pd));
				janus_vp8_simulcast_descriptor_update(payload, plen, &stream->vp8_context,
					stream->sim_context.changed_substream);
			}
			/* Send the packet */
			if(gateway != NULL)
				gateway->relay_rtp(session->handle, stream->mindex, TRUE, (char *)packet->data, packet->length);
			/* Restore the timestamp and sequence number to what the publisher set them to */
			packet->data->timestamp = htonl(packet->timestamp);
			packet->data->seq_number = htons(packet->seq_number);
			if(ps->vcodec == JANUS_VIDEOCODEC_VP8) {
				/* Restore the original payload descriptor as well, as it will be needed by the next viewer */
				memcpy(payload, vp8pd, sizeof(vp8pd));
			}
		} else {
			/* Fix sequence number and timestamp (publisher switching may be involved) */
			janus_rtp_header_update(packet->data, &stream->context, TRUE);
			/* Send the packet */
			if(gateway != NULL)
				gateway->relay_rtp(session->handle, stream->mindex, FALSE, (char *)packet->data, packet->length);
			/* Restore the timestamp and sequence number to what the publisher set them to */
			packet->data->timestamp = htonl(packet->timestamp);
			packet->data->seq_number = htons(packet->seq_number);
		}
	} else {
		/* Fix sequence number and timestamp (publisher switching may be involved) */
		janus_rtp_header_update(packet->data, &stream->context, FALSE);
		/* Send the packet */
		if(gateway != NULL)
			gateway->relay_rtp(session->handle, stream->mindex, TRUE, (char *)packet->data, packet->length);
		/* Restore the timestamp and sequence number to what the publisher set them to */
		packet->data->timestamp = htonl(packet->timestamp);
		packet->data->seq_number = htons(packet->seq_number);
	}

	return;
}

static void janus_videoroom_relay_data_packet(gpointer data, gpointer user_data) {
	janus_videoroom_data_relay_packet *packet = (janus_videoroom_data_relay_packet *)user_data;
	if(!packet || !packet->text) {
		JANUS_LOG(LOG_ERR, "Invalid packet...\n");
		return;
	}
	janus_videoroom_subscriber_stream *stream = (janus_videoroom_subscriber_stream *)data;
	if(!stream || !stream->send || !stream->subscriber || stream->subscriber->paused || stream->subscriber->kicked ||
			!stream->subscriber->session || !stream->subscriber->session->handle || !stream->subscriber->session->started)
		return;
	janus_videoroom_subscriber *subscriber = stream->subscriber;
	janus_videoroom_session *session = subscriber->session;

	/* We use the publisher's user ID as the label for the data channel */
	janus_videoroom_publisher_stream *ps = packet->source;
	if(ps == NULL || ps->publisher == NULL)
		return;
	janus_videoroom_publisher *publisher = ps->publisher;
	char label[64];
	g_snprintf(label, sizeof(label), "%"SCNu64, publisher->user_id);

	char *text = packet->text;
	if(gateway != NULL && text != NULL) {
		JANUS_LOG(LOG_VERB, "Forwarding DataChannel message (%zu bytes) to viewer: %s\n", strlen(text), text);
		gateway->relay_data(session->handle, label, text, strlen(text));
	}
	return;
}

/* The following methods are only relevant if RTCP is used for RTP forwarders */
static void janus_videoroom_rtp_forwarder_rtcp_receive(janus_videoroom_rtp_forwarder *forward) {
	char buffer[1500];
	struct sockaddr_storage remote_addr;
	socklen_t addrlen = sizeof(remote_addr);
	int len = recvfrom(forward->rtcp_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&remote_addr, &addrlen);
	if(len > 0 && janus_is_rtcp(buffer, len)) {
		JANUS_LOG(LOG_HUGE, "Got %s RTCP packet: %d bytes\n", forward->is_video ? "video" : "audio", len);
		/* We only handle incoming video PLI or FIR at the moment */
		if(!janus_rtcp_has_fir(buffer, len) && !janus_rtcp_has_pli(buffer, len))
			return;
		janus_videoroom_reqpli((janus_videoroom_publisher_stream *)forward->source, "RTCP from forwarder");
	}
}

static void *janus_videoroom_rtp_forwarder_rtcp_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Joining RTCP thread for RTP forwarders...\n");
	/* Run the main loop */
	g_main_loop_run(rtcpfwd_loop);
	/* When the loop ends, we're done */
	JANUS_LOG(LOG_VERB, "Leaving RTCP thread for RTP forwarders...\n");
	return NULL;
}
