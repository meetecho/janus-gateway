-- This is a simple example of an video room application built in Lua,
-- and conceived to be used in conjunction with the janus_lua.c plugin
--
-- Note: this example depends on lua-json to do JSON processing
-- (http://luaforge.net/projects/luajson/)
json = require('json')
-- We also import our own SDP helper utilities: you may have better ones
sdp = require('janus-sdp')
-- Let's also use our ugly stdout logger just for the fun of it: to add
-- some color to the text we use the ansicolors library
-- (https://github.com/kikito/ansicolors.lua)
colors = require "ansicolors"
logger = require('janus-logger')

-- Example details
name = "videoroom.lua"
logger.prefix(colors("[%{blue}" .. name .. "%{reset}]"))
logger.print("Loading...")

-- State and properties
sessions = {}
rooms = {}
tasks = {}

-- Errors
JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR	= 499
JANUS_VIDEOROOM_ERROR_NO_MESSAGE = 421
JANUS_VIDEOROOM_ERROR_INVALID_JSON = 422
JANUS_VIDEOROOM_ERROR_INVALID_REQUEST = 423
JANUS_VIDEOROOM_ERROR_JOIN_FIRST = 424
JANUS_VIDEOROOM_ERROR_ALREADY_JOINED = 425
JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM = 426
JANUS_VIDEOROOM_ERROR_ROOM_EXISTS = 427
JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED = 428
JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT = 429
JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT = 430
JANUS_VIDEOROOM_ERROR_INVALID_SDP_TYPE = 431
JANUS_VIDEOROOM_ERROR_PUBLISHERS_FULL = 432
JANUS_VIDEOROOM_ERROR_UNAUTHORIZED = 433
JANUS_VIDEOROOM_ERROR_ALREADY_PUBLISHED = 434
JANUS_VIDEOROOM_ERROR_NOT_PUBLISHED = 435
JANUS_VIDEOROOM_ERROR_ID_EXISTS = 436
JANUS_VIDEOROOM_ERROR_INVALID_SDP = 437


-- Methods
function init(config)
	-- This is where we initialize the plugin, for static properties
	logger.print("Initializing...")
	if config ~= nil then
		-- TODO Should we actually have code to parse a janus.plugin.videoroom.cfg file here?
		logger.print("Configuration file provided (" .. config .. "), but we don't need it")
	end
	logger.print("Initialized")
end

function destroy()
	-- This is where we deinitialize the plugin, when Janus shuts down
	logger.print("Deinitialized")
end

function createSession(id)
	-- Keep track of a new session
	logger.print("Created new session: " .. id)
	sessions[id] = { id = id, lua = name }
end

function destroySession(id)
	-- A Janus plugin session has gone
	logger.print("Destroyed session: " .. id)
	hangupMedia(id)
	-- Remove the user from the list of participants
	local s = sessions[id]
	if s~= nil and s.userId ~= nil then
		local room = nil
		if s.roomId ~= nil then
			room = rooms[s.roomId]
		end
		if room ~= nil then
			-- If this is a publisher, notify other participants that the user is leaving
			if(s["pType"] == "publisher") then
				local event = { videoroom = "event", leaving = s.userId, room = room.roomId }
				local eventjson = json.encode(event)
				for index,partId in pairs(room.participants) do
					local p = sessions[partId]
					if p ~= nil and p.id ~= id then
						pushEvent(p.id, nil, eventjson, nil)
					end
				end
				-- If private IDs are required to prevent lurking, get rid of the subscriptions as well
				if room.requirePvtId == true then
					for index,sub in ipairs(s.subscriptions) do
						logger.print("  -- Getting rid of publisher's subscription: " .. sub)
						endSession(sub)
					end
				end
				s.subscriptions = {}
				if s.privateId ~= nil then
					room.privateIds[s.privateId] = nil
				end
				room.participants[s.userId] = nil
			end
		end
		s.userId = nil
	end
	sessions[id] = nil
end

function querySession(id)
	-- Return info on a session
	logger.print("Queried session: " .. id)
	local s = sessions[id]
	if s == nil then
		return nil
	end
	local info = { script = s["lua"], id = s["id"], display = s["display"],
		room = s["roomId"], ptype = s["pType"], user = s["userId"], feed = s["feedId"],
		audio = s["audio"], audioCodec = s["audioCodec"],
		video = s["video"], videoCodec = s["videoCodec"],
		data = s["data"], bitrate = s["bitrate"] }
	local infojson = json.encode(info)
	return infojson
end

function handleMessage(id, tr, msg, jsep)
	-- Handle a message, synchronously or asynchronously, and return
	-- something accordingly: if it's the latter, we'll do a coroutine
	logger.print("Handling message for session: " .. id)
	local s = sessions[id]
	if s == nil then
		return -1, "Session not found"
	end
	-- Decode the message JSON string to a table
	if msg == nil then
		return -1, "Invalid message"
	end
	local msgT = json.decode(msg)
	local jsepT = nil
	if jsep ~= nil then
		jsepT = json.decode(jsep)
	end
	-- Handle the request
	local request = msgT["request"]
	if request == "create" then
		-- Create a new room
		local roomId = msgT["room"]
		if roomId == nil then
			roomId = math.random(4294967296)
		end
		logger.print("Creating new room: " .. roomId)
		local description = msgT["description"]
		local secret = msgT["secret"]
		local publishers = msgT["publishers"]
		if(publishers == nil) then
			publishers = 3
		end
		local audioCodec = msgT["audiocodec"]
		if(audioCodec == nil) then
			audioCodec = "opus"
		end
		local videoCodec = msgT["videocodec"]
		if(videoCodec == nil) then
			videoCodec = "vp8"
		end
		local bitrate = msgT["bitrate"]
		local pliFreq = msgT["fir_freq"]
		local requirePvtId = msgT["require_pvtid"]
		local notifyJoining = msgT["notify_joining"]
		if rooms[roomId] ~= nil then
			local response = { videoroom = "error", error_code = JANUS_VIDEOROOM_ERROR_ROOM_EXISTS, error = "Room exists" }
			local responsejson = json.encode(response)
			return 0, responsejson
		end
		rooms[roomId] = {
			roomId = roomId,
			description = description,
			secret = secret,
			publishers = publishers,
			audioCodec = split(audioCodec, ","),
			videoCodec = split(videoCodec, ","),
			bitrate = bitrate,
			pliFreq = pliFreq,
			requirePvtId = requirePvtId,
			notifyJoining = notifyJoining,
			participants = {},
			privateIds = {}
		}
		local response = { videoroom = "created", room = roomId }
		local responsejson = json.encode(response)
		return 0, responsejson
	elseif request == "destroy" then
		-- Destroy an existing room
		local roomId = msgT["room"]
		logger.print("Destroying room: " .. roomId)
		local room = rooms[roomId]
		if room == nil then
			local error = { videoroom = "error", error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM, error = "No such room" }
			local responsejson = json.encode(error)
			return 0, responsejson
		end
		if room.secret ~= nil and room.secret ~= msgT["secret"] then
			local error = { videoroom = "error", error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED, error = "Unauthorized (wrong secret)" }
			local responsejson = json.encode(error)
			return 0, responsejson
		end
		-- Kick users
		local event = { videoroom = "destroyed", room = roomId }
		for index,partId in pairs(room.participants) do
			local p = sessions[partId]
			if p ~= nil then
				-- Notify user
				logger.print("Notifying user: " .. p.id)
				local eventjson = json.encode(event)
				pushEvent(p.id, nil, eventjson, nil)
				-- Close the PeerConnection, if any
				if p.started == true then
					hangupMedia(p.id)
					--~ closePc(p.id)
				end
			end
		end
		room.participants = {}
		room.privateIds = {}
		-- Done
		rooms[roomId] = nil
		local response = { videoroom = "destroyed", room = roomId }
		local responsejson = json.encode(response)
		return 0, responsejson
	elseif request == "list" then
		-- List existing rooms
		logger.print("Listing rooms")
		local response = { videoroom = "success", list = rooms }
		local responsejson = json.encode(response)
		return 0, responsejson
	elseif request == "exists" then
		-- Check if an existing room exists
		local exists = false
		local roomId = msgT["room"]
		if roomId ~= nil then
			logger.print("Checking if room exists: " .. roomId)
			if rooms[roomId] ~= nil then
				exists = true
			end
		end
		local response = { videoroom = "success", room = roomId, exists = exists }
		local responsejson = json.encode(response)
		return 0, responsejson
	elseif request == "listparticipants" then
		-- List participants in a room
		local roomId = msgT["room"]
		logger.print("Listing participants in room: " .. roomId)
		local room = rooms[roomId]
		if room == nil then
			local error = { videoroom = "error", error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM, error = "No such room" }
			local responsejson = json.encode(error)
			return 0, responsejson
		end
		local response = { videoroom = "participants", room = roomId, participants = {} }
		for index,partId in pairs(room.participants) do
			local p = sessions[partId]
			if p ~= nil and p.id ~= id and p.sdp ~= nil and p.started == true then
				response.participants[#response.participants+1] = {
					id = p.userId,
					display = p.display,
					audio_codec = p.audioCodec,
					video_codec = p.videoCodec
				}
			end
		end
		local responsejson = json.encode(response)
		logger.print(responsejson)
		if responsejson:find("\"participants\":{}") ~= nil then
			-- Ugly hack, as lua-json turns our empty array into an empty object
			responsejson = string.gsub(responsejson, "\"participants\":{}", "\"participants\":[]")
		end
		return 0, responsejson
	else
		-- Check if it's a request we can handle asynchronously
		if request == "join" or request == "configure" or request == "publish" or request == "unpublish"
				or request == "start" or request == "switch" or request == "leave" then
			-- We need a new coroutine here
			local async = coroutine.create(function(id, tr, comsg, cojsep)
				-- We'll only execute this when the scheduler resumes the task
				logger.print("Handling async message for session: " .. id)
				logger.print("  -- " .. dumpTable(comsg))
				local s = sessions[id]
				if s == nil then
					logger.print("Can't handle async message: so such session")
					return
				end
				local request = comsg["request"]
				logger.print("Handling request: " .. request)
				logger.print("Session: " .. dumpTable(s))
				if request == "join" then
					-- Join a room as publisher or subscriber
					local roomId = comsg["room"]
					local room = rooms[roomId]
					if room == nil then
						local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM, error = "No such room" }
						local eventjson = json.encode(event)
						pushEvent(id, tr, eventjson, nil)
						return
					end
					local pType = comsg["ptype"]
					logger.print("Joining room as " .. pType .. ": " .. roomId)
					if pType == "publisher" then
						-- Setup new publisher
						local userId = comsg["id"]
						local display = comsg["display"]
						if userId == nil then
							userId = math.random(4294967296)
						end
						if room.participants[userId] ~= nil then
							local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_ID_EXISTS, error = "UserID already exists" }
							local eventjson = json.encode(event)
							pushEvent(id, tr, eventjson, nil)
							return
						end
						s["pType"] = pType
						s["roomId"] = roomId
						s["userId"] = userId
						local privateId = math.random(4294967296)
						s.subscriptions = {}
						s["privateId"] = privateId
						s["display"] = display
						s["subscribers"] = {}
						room.participants[userId] = id
						room.privateIds[privateId] = id
						-- Import the room settings
						s["audioCodec"] = nil	-- We'll figure out this later
						s["videoCodec"] = nil	-- We'll figure out this later
						if room.bitrate ~= nil then
							logger.print("Setting bitrate: " .. room.bitrate)
							setBitrate(id, room.bitrate)
							s["bitrate"] = room.bitrate
						end
						if room.pliFreq ~= nil then
							logger.print("Setting PLI frequency: " .. room.pliFreq)
							setPliFreq(id, room.pliFreq)
							s["pliFreq"] = room.pliFreq
						end
						-- Publishers can only send media
						configureMedium(id, "audio", "out", true)
						configureMedium(id, "audio", "in", false)
						configureMedium(id, "video", "out", true)
						configureMedium(id, "video", "in", false)
						configureMedium(id, "data", "out", true)
						configureMedium(id, "data", "in", false)
						-- Send event back with a list of active publishers (and possibly other attendees)
						local event = { videoroom = "joined", room = roomId, description = room.description,
							id = userId, private_id = privateId, publishers = {} }
						if room.notifyJoining then
							event.attendees = {}
						end
						for index,partId in pairs(room.participants) do
							local p = sessions[partId]
							-- Publishers first
							if p ~= nil and p.id ~= id and p.sdp ~= nil and p.started == true then
								event.publishers[#event.publishers+1] = {
									id = p.userId,
									display = p.display,
									audio_codec = p.audioCodec,
									video_codec = p.videoCodec
								}
							end
							-- If notify_joining=true, send a list of attendees as well
							if room.notifyJoining and p ~= nil and p.id ~= id then
								event.attendees[#event.attendees+1] = {
									id = p.userId,
									display = p.display
								}
							end
						end
						local eventjson = json.encode(event)
						if eventjson:find("\"publishers\":{}") ~= nil then
							-- Ugly hack, as lua-json turns our empty array into an empty object
							eventjson = string.gsub(eventjson, "\"publishers\":{}", "\"publishers\":[]")
						end
						if room.notifyJoining and eventjson:find("\"attendees\":{}") ~= nil then
							-- Ugly hack, as lua-json turns our empty array into an empty object
							eventjson = string.gsub(eventjson, "\"attendees\":{}", "\"attendees\":[]")
						end
						pushEvent(id, tr, eventjson, nil)
						-- If notify_joining=true, notify other participants as well
						if room.notifyJoining then
							local event = { videoroom = "event", event = "joining",
								room = room.roomId, id = s.userId, display = s.display }
							local eventjson = json.encode(event)
							for index,partId in pairs(room.participants) do
								local p = sessions[partId]
								if p ~= nil and p.id ~= id then
									pushEvent(p.id, nil, eventjson, nil)
								end
							end
						end
					elseif pType == "subscriber" then
						-- Setup new subscriber
						local feedId = comsg["feed"]
						logger.print("Subscribing to feed: " .. feedId)
						if room.participants[feedId] == nil then
							local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED, error = "No such feed" }
							local eventjson = json.encode(event)
							pushEvent(id, tr, eventjson, nil)
							return
						end
						local f = sessions[room.participants[feedId]]
						if f == nil or f.started ~= true then
							local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED, error = "No such feed" }
							local eventjson = json.encode(event)
							pushEvent(id, tr, eventjson, nil)
							return
						end
						local privateId = comsg["private_id"]
						if room.requirePvtId == true then
							-- Make sure a valid private ID was provided
							local owner = room.privateIds[privateId]
							if owner == nil then
								local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED, error = "Unauthorized (this room requires a valid private_id)" }
								local eventjson = json.encode(event)
								pushEvent(id, tr, eventjson, nil)
								return
							end
							local o = sessions[owner];
							-- Add this session to the owner's subscriptions
							o.subscriptions[#o.subscriptions+1] = id
						end
						s["privateId"] = privateId
						s["pType"] = pType
						s["roomId"] = roomId
						s["feedId"] = feedId
						s["feedSessionId"] = f.id
						f["subscribers"][id] = id
						-- Subscribers can only receive media
						configureMedium(id, "audio", "in", true)
						configureMedium(id, "audio", "out", false)
						s["audio"] = true
						configureMedium(id, "video", "in", true)
						configureMedium(id, "video", "out", false)
						s["video"] = true
						configureMedium(id, "data", "in", true)
						configureMedium(id, "data", "out", false)
						s["data"] = true
						-- Check if we need to drop anything
						if comsg["audio"] == true then
							configureMedium(id, "audio", "in", true)
							s["audio"] = true
						elseif comsg["audio"] == false then
							configureMedium(id, "audio", "in", false)
							s["audio"] = false
						end
						if comsg["video"] == true then
							configureMedium(id, "video", "in", true)
							s["video"] = true
						elseif comsg["video"] == false then
							configureMedium(id, "video", "in", false)
							s["video"] = false
						end
						if comsg["data"] == true then
							configureMedium(id, "data", "in", true)
							s["data"] = true
						elseif comsg["data"] == false then
							configureMedium(id, "data", "in", false)
							s["data"] = false
						end
						local offer_audio = true
						if comsg["offer_audio"] == false then
							offer_audio = false
						end
						local offer_video = true
						if comsg["offer_video"] == false then
							offer_video = false
						end
						local offer_data = true
						if comsg["offer_data"] == false then
							offer_data = false
						end
						-- Prepare offer and send it back
						local baseOffer = sdp.parse(f["sdp"])
						-- Check if we need to remove some m-lines
						if offer_audio == false then
							-- Remove audio m-line
							logger.print("  -- Subscriber doesn't want audio")
							sdp.removeMLine(baseOffer, "audio")
							configureMedium(id, "audio", "in", false)
							s["audio"] = false
						end
						if offer_video == false then
							-- Remove video m-line
							logger.print("  -- Subscriber doesn't want video")
							sdp.removeMLine(baseOffer, "video")
							configureMedium(id, "video", "in", false)
							s["video"] = false
						end
						if offer_data == false then
							-- Remove application m-line
							logger.print("  -- Subscriber doesn't want data")
							sdp.removeMLine(baseOffer, "application")
							configureMedium(id, "data", "in", false)
							s["data"] = false
						end
						-- Generate the offer
						s["sdp"] = sdp.render(baseOffer)
						local event = { videoroom = "attached", room = roomId, id = feedId, display = f["display"] }
						local eventjson = json.encode(event)
						logger.print("Prepared offer for subscriber: " .. s["sdp"])
						local offer = { type = "offer", sdp = s["sdp"] }
						local offerjson = json.encode(offer)
						pushEvent(id, tr, eventjson, offerjson)
					else
						logger.print("Invalid element")
						local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, error = "Invalid element (ptype)" }
						local eventjson = json.encode(event)
						pushEvent(id, tr, eventjson, nil)
					end
				elseif request == "configure" or request == "publish" then
					-- Modify properties for a session, and/or start publishing
					logger.print("Received a " .. request .. " by a " .. s["pType"] .. ": " .. s["roomId"])
					if s["pType"] == "publisher" then
						-- Prepare a response
						local event = { videoroom = "event", room = s["roomId"], configured = "ok" }
						-- Check if there's an SDP offer
						local answerjson = nil
						if cojsep ~= nil then
							-- There's an SDP: is this a new offer, or a renegotiation?
							if cojsep["update"] == true then
								logger.print("Renegotiation occurring on the publisher")
							else
								logger.print("Setting up new PeerConnection for publisher")
							end
							-- Make sure the publisher is sendonly
							local room = rooms[s["roomId"]]
							local sdpoffer = string.gsub(cojsep["sdp"], "sendrecv", "sendonly")
							local offer = sdp.parse(sdpoffer)
							logger.print("Got offer from publisher: " .. sdp.render(offer))
							-- Check which codecs are allowed in the room
							local audioCodec = comsg["audiocodec"]
							if audioCodec ~= nil then
								-- The publisher wants to use a specific codec, let's see if that's possible
								logger.print("Publisher wants to use audio codec: " .. audioCodec)
								for index,codec in ipairs(room.audioCodec) do
									if codec == audioCodec then
										logger.print("  -- Publisher audio codec found");
										s.audioCodec = codec
									end
								end
								if s.audioCodec == nil then
									logger.print("  -- Publisher audio codec NOT found");
									local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, error = "Audio codec unavailable in this room" }
									local eventjson = json.encode(event)
									pushEvent(id, tr, eventjson, nil)
									return
								end
							else
								-- Pick the best audio codec (SDP vs. room preferences)
								s["audioCodec"] = nil
								for index,codec in ipairs(room.audioCodec) do
									if s.audioCodec == nil then
										logger.print("Looking for audio codec " .. codec)
										if sdp.findPayloadType(offer, codec) == -1 then
											logger.print("  -- Not found, trying next audio codec...")
										else
											logger.print("  -- Publisher audio codec found")
											s.audioCodec = codec
										end
									end
								end
							end
							local videoCodec = comsg["videocodec"]
							if videoCodec ~= nil then
								-- The publisher wants to use a specific codec, let's see if that's possible
								logger.print("Publisher wants to use video codec: " .. videoCodec)
								for index,codec in ipairs(room.videoCodec) do
									if codec == videoCodec then
										logger.print("  -- Publisher video codec found");
										s.videoCodec = codec
									end
								end
								if s.videoCodec == nil then
									logger.print("  -- Publisher video codec NOT found");
									local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, error = "Video codec unavailable in this room" }
									local eventjson = json.encode(event)
									pushEvent(id, tr, eventjson, nil)
									return
								end
							else
								-- Pick the best video codec (SDP vs. room preferences)
								s["videoCodec"] = nil
								for index,codec in ipairs(room.videoCodec) do
									if s.videoCodec == nil then
										logger.print("Looking for video codec " .. codec)
										if sdp.findPayloadType(offer, codec) == -1 then
											logger.print("  -- Not found, trying next video codec...")
										else
											logger.print("  -- Publisher video codec found")
											s.videoCodec = codec
										end
									end
								end
							end
							-- Generate answer
							local answer = sdp.generateAnswer(offer, {
								audio = (s.audioCodec ~= nil), audioCodec = s.audioCodec,
								video = (s.videoCodec ~= nil), videoCodec = s.videoCodec,
								data = true })
							logger.print("Generated answer for publisher: " .. sdp.render(answer))
							local jsepanswer = { type = "answer", sdp = sdp.render(answer) }
							answerjson = json.encode(jsepanswer)
							-- Prepare a revised version of the offer to send to subscribers
							s["sdp"] = string.gsub(jsepanswer.sdp, "recvonly", "sendonly")
							-- Prepare the event to send back
							event["audio_codec"] = s.audioCodec
							event["video_codec"] = s.videoCodec
						end
						-- Check what we need to configure
						if comsg["audio"] == true then
							logger.print("Enabling audio")
							configureMedium(id, "audio", "out", true)
							s["audio"] = true
						elseif comsg["audio"] == false then
							logger.print("Disabling audio")
							configureMedium(id, "audio", "out", false)
							s["audio"] = false
						end
						if comsg["video"] == true then
							logger.print("Enabling video")
							configureMedium(id, "video", "out", true)
							sendPli(id)
							s["video"] = true
						elseif comsg["video"] == false then
							logger.print("Disabling video")
							configureMedium(id, "video", "out", false)
							s["video"] = false
						end
						if comsg["data"] == true then
							logger.print("Enabling data")
							configureMedium(id, "data", "out", true)
							s["data"] = true
						elseif comsg["data"] == false then
							logger.print("Disabling data")
							configureMedium(id, "data", "out", false)
							s["data"] = false
						end
						if comsg["bitrate"] ~= nil then
							logger.print("Setting bitrate: " .. comsg["bitrate"])
							setBitrate(id, comsg["bitrate"])
							s["bitrate"] = comsg["bitrate"]
						end
						if comsg["fir_freq"] ~= nil then
							logger.print("Setting PLI frequency: " .. comsg["fir_freq"])
							setPliFreq(id, comsg["fir_freq"])
							s["pliFreq"] = comsg["fir_freq"]
						end
						-- Done
						local eventjson = json.encode(event)
						pushEvent(id, tr, eventjson, answerjson)
					elseif s["pType"] == "subscriber" then
						-- Configure the subscription properties
						if request == "publish" then
							logger.print("Invalid request: " .. request)
							local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST, error = "Invalid request" }
							local eventjson = json.encode(event)
							pushEvent(id, tr, eventjson, nil)
							return
						end
						if comsg["audio"] == true then
							configureMedium(id, "audio", "in", true)
						elseif comsg["audio"] == false then
							configureMedium(id, "audio", "in", false)
						end
						if comsg["video"] == true then
							configureMedium(id, "video", "in", true)
							sendPli(id)
						elseif comsg["video"] == false then
							configureMedium(id, "video", "in", false)
						end
						if comsg["data"] == true then
							configureMedium(id, "data", "in", true)
						elseif comsg["data"] == false then
							configureMedium(id, "data", "in", false)
						end
						-- Also check if we need to send an ICE restart
						local restartjson = nil
						if comsg["restart"] == true then
							-- Prepare new offer and send it back
							local f = sessions[s["feedSessionId"]]
							if f ~= nil and s["sdp"] ~= nil then
								logger.print("Preparing new offer (ICE restart) for subscriber: " .. s["sdp"])
								local offer = { type = "offer", sdp = s["sdp"], restart = true }
								restartjson = json.encode(offer)
							end
						end
						local event = { videoroom = "event", room = s["roomId"], configured = "ok" }
						local eventjson = json.encode(event)
						pushEvent(id, tr, eventjson, restartjson)
					end
				elseif request == "unpublish" then
					-- Stop publishing in a room (publishers only)
					logger.print("Unpublishing in room: " .. s["roomId"])
					if s["pType"] ~= "publisher" then
						logger.print("Invalid request: " .. request)
						local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST, error = "Invalid request" }
						local eventjson = json.encode(event)
						pushEvent(id, tr, eventjson, nil)
						return
					end
					-- Close the PeerConnection
					hangupMedia(id)
					closePc(id)
					local event = { videoroom = "event", room = s["roomId"], unpublished = "ok" }
					local eventjson = json.encode(event)
					pushEvent(id, tr, eventjson, nil)
				elseif request == "leave" then
					-- Leave a room
					logger.print("Leaving room: " .. s["roomId"])
					-- Clean up the PeerConnection
					hangupMedia(id)
					closePc(id)
					local event = { videoroom = "event", room = s["roomId"], leaving = "ok" }
					local eventjson = json.encode(event)
					pushEvent(id, tr, eventjson, nil)
					-- If private IDs are required to prevent lurking, get rid of the subscriptions as well
					local room = rooms[s["roomId"]]
					if room ~= nil and room.requirePvtId == true then
						for index,sub in ipairs(s.subscriptions) do
							logger.print("  -- Getting rid of publisher's subscription: " .. sub)
							endSession(sub)
						end
					end
					s.subscriptions = {}
					if room ~= nil and s.privateId ~= nil then
						room.privateIds[s.privateId] = nil
					end
					room.participants[s.userId] = nil
				elseif request == "start" then
					-- Start subscribing to a publisher (subscribers only)
					logger.print("Starting a subscription")
					if s["pType"] ~= "subscriber" then
						logger.print("Invalid request: " .. request)
						local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST, error = "Invalid request" }
						local eventjson = json.encode(event)
						pushEvent(id, tr, eventjson, nil)
						return
					end
					local event = { videoroom = "event", room = s["roomId"], started = "ok" }
					local eventjson = json.encode(event)
					pushEvent(id, tr, eventjson, nil)
				elseif request == "switch" then
					-- Switch to a new publisher (subscribers only)
					if s["pType"] ~= "subscriber" then
						logger.print("Invalid request: " .. request)
						local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST, error = "Invalid request" }
						local eventjson = json.encode(event)
						pushEvent(id, tr, eventjson, nil)
						return
					end
					-- TODO
					local event = { videoroom = "event", room = s["roomId"], switched = "ok" }
					local eventjson = json.encode(event)
					pushEvent(id, tr, eventjson, nil)
				elseif request == "keyframe" then
					-- Programmatically ask the publisher for a keyframe
					if s["pType"] ~= "subscriber" then
						logger.print("Invalid request: " .. request)
						local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST, error = "Invalid request" }
						local eventjson = json.encode(event)
						pushEvent(id, tr, eventjson, nil)
						return
					end
					-- Send a PLI to the publisher
					if s["feedSessionId"] ~= nil then
						local f = sessions[s["feedSessionId"]]
						if f ~= nil then
							logger.print("Session " .. id .. " is going to be fed by " .. f.id)
							addRecipient(f.id, id)
							sendPli(f.id)
						end
					end
					-- Done
					local event = { videoroom = "event", room = s["roomId"], sent = "ok" }
					local eventjson = json.encode(event)
					pushEvent(id, tr, eventjson, nil)
				else
					logger.print("Invalid request: " .. request)
					local event = { videoroom = "event", error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST, error = "Invalid request" }
					local eventjson = json.encode(event)
					pushEvent(id, tr, eventjson, nil)
				end
				logger.print("Done handling request: " .. request)
			end)
			-- Enqueue it: the scheduler will resume it later
			tasks[#tasks+1] = { co = async, id = id, tr = tr, msg = msgT, jsep = jsepT }
			-- Return explaining that this is will be handled asynchronously
			pokeScheduler()
			return 1, nil
		else
			local response = { videoroom = "error", error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST, error = "Unknown request" }
			local responsejson = json.encode(response)
			return 0, responsejson
		end
	end
end

function setupMedia(id)
	-- WebRTC is now available
	logger.print("WebRTC PeerConnection is up for session: " .. id)
	local s = sessions[id]
	if s == nil then
		return -1, "Session not found"
	end
	s["started"] = true
	-- If this is a publisher, notify other users
	if(s["pType"] == "publisher") then
		if(s["bitrate"] ~= nil) then
			setBitrate(id, s["bitrate"])
		end
		local room = rooms[s.roomId]
		if room == nil then
			return
		end
		local event = { videoroom = "event", room = room.roomId, description = room.description,
			id = s.userId, publishers = {} }
		event.publishers[#event.publishers+1] = {
			id = s.userId,
			display = s.display,
			audio_codec = s.audioCodec,
			video_codec = s.videoCodec
		}
		local eventjson = json.encode(event)
		if eventjson:find("\"publishers\":{}") ~= nil then
			-- Ugly hack, as lua-json turns our empty array into an empty object
			eventjson = string.gsub(eventjson, "\"publishers\":{}", "\"publishers\":[]")
		end
		for index,partId in pairs(room.participants) do
			local p = sessions[partId]
			if p ~= nil and p.id ~= id then
				pushEvent(p.id, nil, eventjson, nil)
			end
		end
	-- If this is a subscriber, attach it as a recipient to the publisher
	elseif(s["pType"] == "subscriber") then
		local f = sessions[s["feedSessionId"]]
		if f ~= nil then
			logger.print("Session " .. id .. " is going to be fed by " .. f.id)
			addRecipient(f.id, id)
			sendPli(f.id)
		end
	end
end

function hangupMedia(id)
	-- WebRTC not available anymore
	logger.print("WebRTC PeerConnection is down for session: " .. id)
	local s = sessions[id]
	if s == nil then
		return -1, "Session not found"
	end
	s["started"] = false
	s["sdp"] = nil
	-- If this is a publisher, detach all subscribers, otherwise detach from publisher
	if(s["pType"] == "publisher") then
		-- Detach all subscribers
		for index,subId in pairs(s.subscribers) do
			logger.print("Unlinking session " .. subId .. " from feed " .. id)
			removeRecipient(id, subId)
		end
		s.subscribers = {}
		-- Notify other participants this publisher is gone
		local room = rooms[s.roomId]
		if room == nil then
			return
		end
		local event = { videoroom = "event", unpublished = s.userId, room = room.roomId }
		local eventjson = json.encode(event)
		for index,partId in pairs(room.participants) do
			local p = sessions[partId]
			if p ~= nil and p.id ~= id then
				pushEvent(p.id, nil, eventjson, nil)
			end
		end
	elseif(s["pType"] == "subscriber") then
		local f = sessions[s["feedSessionId"]]
		if f ~= nil then
			logger.print("Unlinking session " .. id .. " from feed " .. f.id)
			f.subscribers[id] = nil
			removeRecipient(f.id, id)
		end
	end
end

function resumeScheduler()
	-- This is the function responsible for resuming coroutines associated
	-- with whatever is relevant to the Lua script, e.g., for this script,
	-- with asynchronous requests: if you're handling async stuff yourself,
	-- you're free not to use this and just return, but the C Lua plugin
	-- expects this method to exist so it MUST be present, even if empty
	logger.print("Resuming coroutines")
	for index,task in ipairs(tasks) do
		local success, result = coroutine.resume(task.co, task.id, task.tr, task.msg, task.jsep)
		if not success then
			logger.print(colors("[%{red}exception%{reset}]") .. " " .. dumpTable(result))
		end
	end
	logger.print("Coroutines resumed")
	tasks = {}
end

-- Helper for logging tables
-- https://stackoverflow.com/a/27028488
function dumpTable(o)
	if type(o) == 'table' then
		local s = '{ '
		for k,v in pairs(o) do
			if type(k) ~= 'number' then k = '"'..k..'"' end
			s = s .. '['..k..'] = ' .. dumpTable(v) .. ','
		end
		return s .. '} '
	else
		return tostring(o)
	end
end

-- Helper for splitting strings using a pattern (http://lua-users.org/wiki/SplitJoin)
function split(str, pat)
	local t = {}  -- NOTE: use {n = 0} in Lua-5.0
	local fpat = "(.-)" .. pat
	local last_end = 1
	local s, e, cap = str:find(fpat, 1)
	while s do
		if s ~= 1 or cap ~= "" then
			table.insert(t,cap)
		end
		last_end = e+1
		s, e, cap = str:find(fpat, last_end)
	end
	if last_end <= #str then
		cap = str:sub(last_end)
		table.insert(t, cap)
	end
	return t
end

-- Done
logger.print("Loaded")
