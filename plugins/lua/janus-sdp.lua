-- Set of utilities for parsing, processing and managing Janus SDPs in Lua,
-- as the C Janus SDP utils that Janus provides are unavailable otherwise

local JANUSSDP = {}

function JANUSSDP.parse(text)
	if text == nil then
		return nil
	end
	local lines = {}
	local s = nil
	for s in text:gmatch("[^\r\n]+") do
		table.insert(lines, s)
	end
	local sdp = {}
	local index = nil
	local line = nil
	for index,line in pairs(lines) do
		local t = line:sub(1,1)
		local ll = line:sub(3)
		local sc = ll:find(":")
		local n, v
		if sc == nil then
			n = ll
		else
			n = ll:sub(1,sc-1)
			v = ll:sub(sc+1)
		end
		table.insert(sdp, {type = t, name = n, value = v})
	end
	return sdp
end

function JANUSSDP.render(sdp)
	if sdp == nil then
		return nil
	end
	local sdpString = ""
	local index = nil
	local a = nil
	for index,a in pairs(sdp) do
		if a.value == nil then
			sdpString = sdpString .. a.type .. "=" .. a.name .. "\r\n"
		else
			sdpString = sdpString .. a.type .. "=" .. a.name .. ":" .. a.value .. "\r\n"
		end
	end
	return sdpString
end

function JANUSSDP.findPayloadType(sdp, codec, profile)
	if sdp == nil or codec == nil then
		return -1
	end
	local pt = -1
	local codecUpper = codec:upper()
	local codecLower = codec:lower()
	local index = nil
	local a = nil
	local checkProfile = false
	for index,a in pairs(sdp) do
		if checkProfile and a.name == "fmtp" and a.value ~= nil then
			checkProfile = false
			if codec == "vp9" then
				if a.value:find("profile%-id%=" .. profile) ~= nil then
					-- Found
					break
				end
				pt = -1
			elseif codec == "h264" then
				if a.value:find("profile%-level%-id%=" .. profile:lower()) ~= nil then
					-- Found
					break
				elseif a.value:find("profile%-level%-id%=" .. profile:upper()) ~= nil then
					-- Found
					break
				end
				pt = -1
			end
		elseif a.name == "rtpmap" and a.value ~= nil then
			if a.value:find(codecLower) ~= nil or a.value:find(codecUpper) ~= nil then
				local n = a.value:gmatch("[^ ]+")
				pt = tonumber(n())
				if profile == nil then
					-- We're done
					break
				else
					-- We need to make sure the profile matches
					checkProfile = true
				end
			end
		end
	end
	return pt
end

function JANUSSDP.findCodec(sdp, pt)
	if sdp == nil or pt == nil then
		return -1
	end
	if pt == 0 then
		return "pcmu"
	elseif pt == 8 then
		return "pcma"
	elseif pt == 9 then
		return "g722"
	end
	local codec = nil
	local index = nil
	local a = nil
	for index,a in pairs(sdp) do
		if a.name == "rtpmap" and a.value ~= nil then
			local n = a.value:gmatch("[^ ]+")
			if tonumber(n()) == pt then
				if a.value:find("vp8") ~= nil or a.value:find("VP8") ~= nil then
					codec = "vp8"
				elseif a.value:find("vp9") ~= nil or a.value:find("VP9") ~= nil then
					codec = "vp9"
				elseif a.value:find("h264") ~= nil or a.value:find("H264") ~= nil then
					codec = "h264"
				elseif a.value:find("opus") ~= nil or a.value:find("OPUS") ~= nil then
					codec = "opus"
				elseif a.value:find("multiopus") ~= nil or a.value:find("MULTIOPUS") ~= nil then
					codec = "multiopus"
				elseif a.value:find("pcmu") ~= nil or a.value:find("PCMU") ~= nil then
					codec = "pcmu"
				elseif a.value:find("pcma") ~= nil or a.value:find("PCMA") ~= nil then
					codec = "pcma"
				elseif a.value:find("isac16") ~= nil or a.value:find("ISAC16") ~= nil then
					codec = "isac16"
				elseif a.value:find("isac32") ~= nil or a.value:find("ISAC32") ~= nil then
					codec = "isac32"
				elseif a.value:find("telephone-event") ~= nil or a.value:find("TELEPHONE-EVENT") ~= nil then
					codec = "isac32"
				end
				break
			end
		end
	end
	return codec
end

function JANUSSDP.removeMLine(sdp, type)
	if sdp == nil or type == nil then
		return
	end
	local removelist = {}
	local index = nil
	local a = nil
	local removing = false
	for index,a in pairs(sdp) do
		if a.type == "m" then
			if a.name:find(type) ~= nil then
				removing = true
			else
				removing = false
			end
		end
		if removing == true then
			removelist[#removelist+1] = index
		end
	end
	local i = nil
	for i=#removelist,1,-1 do
		if removelist[i] ~= nil then
			table.remove(sdp, removelist[i])
		end
	end
end

function JANUSSDP.removePayloadType(sdp, pt)
	if sdp == nil or pt == nil then
		return
	end
	local removelist = {}
	local index = nil
	local a = nil
	for index,a in pairs(sdp) do
		if a.type == "m" then
			local m = a.name:gsub(" " .. pt .. " ", " ")
			if m ~= nil then a.name = m end
			a.name = a.name .. "\r\n"
			local m = a.name:gsub(" " .. pt .. "\r\n", "\r\n")
			if m ~= nil then a.name = m end
			a.name = a.name:gsub("\r\n", "")
		elseif a.type == "a" and a.value ~= nil then
			local n = a.value:gmatch("[^ ]+")
			if tonumber(n()) == pt then
				removelist[#removelist+1] = index
			end
		end
	end
	local i = nil
	for i=#removelist,1,-1 do
		if removelist[i] ~= nil then
			table.remove(sdp, removelist[i])
		end
	end
end

function JANUSSDP.generateOffer(options)
	-- Let's set some defaults for the options, in case none were given
	if options == nil then options = {} end
	if options.audio == nil then options.audio = true end
	if options.audio == true and options.audioPt == nil then options.audioPt = 111 end
	if options.audio == true and options.audioCodec == nil then
		options.audioCodec = "opus"
	end
	if options.audio == true then
		if options.audioCodec == "opus" then
			options.audioRtpmap = "opus/48000/2"
		elseif options.audioCodec == "multiopus" then
			options.audioRtpmap = "multiopus/48000/6"
		elseif options.audioCodec == "pcmu" then
			options.audioRtpmap = "PCMU/8000"
			options.audioPt = 0
		elseif options.audioCodec == "pcma" then
			options.audioRtpmap = "PCMA/8000"
			options.audioPt = 8
		elseif options.audioCodec == "g722" then
			options.audioRtpmap = "G722/8000"
			options.audioPt = 9
		elseif options.audioCodec == "isac16" then
			options.audioRtpmap = "ISAC/16000"
		elseif options.audioCodec == "isac32" then
			options.audioRtpmap = "ISAC/32000"
		else
			-- Unsupported codec
			options.audio = false
		end
	end
	if options.audioDir == nil then options.audioDir = "sendrecv" end
	if options.video == nil then options.video = true end
	if options.video == true and options.videoPt == nil then options.videoPt = 96 end
	if options.video == true and options.videoCodec == nil then
		options.videoCodec = "vp8"
	end
	if options.video == true then
		if options.videoCodec == "vp8" then
			options.videoRtpmap = "VP8/90000"
		elseif options.videoCodec == "vp9" then
			options.videoRtpmap = "VP9/90000"
		elseif options.videoCodec == "h264" then
			options.videoRtpmap = "H264/90000"
		else
			-- Unsupported codec
			options.video = false
		end
	end
	if options.videoDir == nil then options.videoDir = "sendrecv" end
	if options.videoRtcpfb == nil then options.videoRtcpfb = true end
	if options.data == nil then options.data = false end
	if options.data == true then options.dataDir = "sendrecv" end
	local address = options.address
	if address == nil then address = "127.0.0.1" end
	local ipv6 = false
	if options.ipv6 == true then ipv6 = true end
	local sessionName = options.sessionName
	if options.sessionName == nil then options.sessionName = "Janus Lua session" end
	-- Do we have enough for an offer?
	if options.audio == false and options.video == false and options.data == false then return nil end
	-- Let's prepare the offer
	local offer = {}
	-- Let's start from the session-level attributes
	offer[#offer+1] = { type = "v", name = "0" }
	offer[#offer+1] = { type = "o", name = "- " .. math.floor(math.random(4294967296)) .. " 1 IN " ..
		(ipv6 == true and "IP6 " or "IP4 ") .. address }
	offer[#offer+1] = { type = "s", name = options.sessionName }
	offer[#offer+1] = { type = "t", name = "0 0" }
	offer[#offer+1] = { type = "c", name = "IN " .. (ipv6 == true and "IP6 " or "IP4 ") .. address }
	-- Now let's add the media lines
	if options.audio == true then
		offer[#offer+1] = { type = "m", name = "audio 9 UDP/TLS/RTP/SAVPF " .. options.audioPt }
		offer[#offer+1] = { type = "c", name = "IN " .. (ipv6 == true and "IP6 " or "IP4 ") .. address }
		offer[#offer+1] = { type = "a", name = options.audioDir }
		offer[#offer+1] = { type = "a", name = "rtpmap", value = options.audioPt .. " " .. options.audioRtpmap }
		if options.audioFmtp ~= nil then
			offer[#offer+1] = { type = "a", name = "fmtp", value = options.audioPt .. " " .. options.audioFmtp }
		end
	end
	if options.video == true then
		offer[#offer+1] = { type = "m", name = "video 9 UDP/TLS/RTP/SAVPF " .. options.videoPt }
		offer[#offer+1] = { type = "c", name = "IN " .. (ipv6 == true and "IP6 " or "IP4 ") .. address }
		offer[#offer+1] = { type = "a", name = options.videoDir }
		offer[#offer+1] = { type = "a", name = "rtpmap", value = options.videoPt .. " " .. options.videoRtpmap }
		if options.videoRtcpfb == true then
			offer[#offer+1] = { type = "a", name = "rtcp-fb", value = options.videoPt .. " ccm fir" }
			offer[#offer+1] = { type = "a", name = "rtcp-fb", value = options.videoPt .. " nack" }
			offer[#offer+1] = { type = "a", name = "rtcp-fb", value = options.videoPt .. " nack pli" }
			offer[#offer+1] = { type = "a", name = "rtcp-fb", value = options.videoPt .. " goog-remb" }
		end
		if options.videoCodec == "vp9" and options.vp9Profile ~= nil then
			offer[#offer+1] = { type = "a", name = "fmtp", value = options.videoPt .. " profile-id=" .. options.vp9Profile }
		elseif options.videoCodec == "h264" and options.h264Profile then
			offer[#offer+1] = { type = "a", name = "fmtp", value = options.videoPt .. " profile-level-id=" .. options.h264Profile .. ";packetization-mode=1" }
		elseif options.videoFmtp ~= nil then
			offer[#offer+1] = { type = "a", name = "fmtp", value = options.videoPt .. " " .. options.videoFmtp }
		elseif options.videoCodec == "h264" then
			offer[#offer+1] = { type = "a", name = "fmtp", value = options.videoPt .. " profile-level-id=42e01f;packetization-mode=1" }
		end
	end
	if options.data == true then
		offer[#offer+1] = { type = "m", name = "application 9 DTLS/SCTP 5000" }
		offer[#offer+1] = { type = "c", name = "IN " .. (ipv6 == true and "IP6 " or "IP4 ") .. address }
		offer[#offer+1] = { type = "a", name = "sendrecv" }
		offer[#offer+1] = { type = "a", name = "sctmap", value = "5000 webrtc-datachannel 16" }
	end
	-- Done
	return offer
end

function JANUSSDP.generateAnswer(offer, options)
	if offer == nil then
		return nil
	end
	-- Let's set some defaults for the options, in case none were given
	if options == nil then options = {} end
	if options.audio == nil then options.audio = true end
	if options.audioCodec == nil then
		if JANUSSDP.findPayloadType(offer, "opus") > 0 then
			options.audioCodec = "opus"
		elseif JANUSSDP.findPayloadType(offer, "multiopus") > 0 then
			options.audioCodec = "multiopus"
		elseif JANUSSDP.findPayloadType(offer, "pcmu") > 0 then
			options.audioCodec = "pcmu"
		elseif JANUSSDP.findPayloadType(offer, "pcma") > 0 then
			options.audioCodec = "pcma"
		elseif JANUSSDP.findPayloadType(offer, "g722") > 0 then
			options.audioCodec = "g722"
		elseif JANUSSDP.findPayloadType(offer, "isac16") > 0 then
			options.audioCodec = "isac16"
		elseif JANUSSDP.findPayloadType(offer, "isac32") > 0 then
			options.audioCodec = "isac32"
		end
	end
	if options.video == nil then options.video = true end
	if options.videoCodec == nil then
		if JANUSSDP.findPayloadType(offer, "vp8") > 0 then
			options.videoCodec = "vp8"
		elseif JANUSSDP.findPayloadType(offer, "vp9", options.vp9Profile) > 0 then
			options.videoCodec = "vp9"
		elseif JANUSSDP.findPayloadType(offer, "h264", options.h264Profile) > 0 then
			options.videoCodec = "h264"
		end
	end
	if options.data == nil then options.data = true end
	if options.disableTwcc == nil then options.disableTwcc = false end
	-- Let's prepare the answer
	local answer = {}
	-- Iterate on all lines
	local audio = 0
	local video = 0
	local data = 0
	local audioPt = -1
	local videoPt = -1
	local medium = nil
	local reject = false
	local index = nil
	local a = nil
	for index,a in pairs(offer) do
		if medium == nil and a.type ~= "m" then
			-- We just copy all the session-level attributes
			if a.value == nil then
				answer[#answer+1] = a
			end
		end
		if a.type == "m" then
			-- New m-line
			reject = false
			if a.name:find("audio") ~= nil then
				medium = "audio"
				audio = audio+1
				if audioPt < 0 then
					audioPt = JANUSSDP.findPayloadType(offer, options.audioCodec)
				end
				if audioPt < 0 then
					audio = audio+1
				end
				if audio > 1 then
					reject = true
					answer[#answer+1] = { type = "m", name = "audio 0 UDP/TLS/RTP/SAVPF 0" }
				else
					answer[#answer+1] = { type = "m", name = "audio 9 UDP/TLS/RTP/SAVPF " .. audioPt }
				end
			elseif a.name:find("video") ~= nil then
				medium = "video"
				video = video+1
				if videoPt < 0 then
					if options.videoCodec == "vp9" then
						videoPt = JANUSSDP.findPayloadType(offer, options.videoCodec, options.vp9Profile)
					elseif options.videoCodec == "h264" then
						videoPt = JANUSSDP.findPayloadType(offer, options.videoCodec, options.h264Profile)
					else
						videoPt = JANUSSDP.findPayloadType(offer, options.videoCodec)
					end
				end
				if videoPt < 0 then
					video = video+1
				end
				if video > 1 then
					reject = true
					answer[#answer+1] = { type = "m", name = "video 0 UDP/TLS/RTP/SAVPF 0" }
				else
					answer[#answer+1] = { type = "m", name = "video 9 UDP/TLS/RTP/SAVPF " .. videoPt }
				end
			elseif a.name:find("application") ~= nil then
				medium = "application"
				data = data+1
				if data > 1 then
					reject = true
					answer[#answer+1] = { type = "m", name = "application 0 DTLS/SCTP 5000" }
				else
					answer[#answer+1] = { type = "m", name = a.name }
				end
			end
		elseif a.type == "a" then
			if a.name == "sendonly" then
				answer[#answer+1] = { type = "a", name = "recvonly" }
			elseif a.name == "recvonly" then
				answer[#answer+1] = { type = "a", name = "sendonly" }
			elseif a.value ~= nil then
				if a.name == "rtpmap" or a.name == "fmtp" or a.name == "rtcp-fb" then
					-- Drop attributes associated to payload types we're getting rid of
					local n = a.value:gmatch("[^ ]+")
					if medium == "audio" and tonumber(n()) == audioPt then
						answer[#answer+1] = a
					elseif medium == "video" and tonumber(n()) == videoPt then
						answer[#answer+1] = a
					end
				elseif a.name == "extmap" then
					-- We do negotiate some RTP extensions
					if a.value:find("urn:ietf:params:rtp-hdrext:sdes:mid", 1, true) then
						answer[#answer+1] = a
					elseif a.value:find("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", 1, true) then
						answer[#answer+1] = a
					elseif a.value:find("urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id", 1, true) then
						answer[#answer+1] = a
					elseif options.disableTwcc ~= true and a.value:find("draft-holmer-rmcat-transport-wide-cc-extensions-01", 1, true) then
						answer[#answer+1] = a
					end
				end
			else
				answer[#answer+1] = a
			end
			-- TODO Handle/filter other attributes
		end
	end
	-- Done
	return answer
end

return JANUSSDP
