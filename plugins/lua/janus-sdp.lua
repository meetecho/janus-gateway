-- Set of utilities for parsing, processing and managing JANUSSDPs in Lua,
-- as the C JANUSSDP utils that Janus provides are unavailable otherwise

local JANUSSDP = {}

function JANUSSDP.parse(text)
	if text == nil then
		return nil
	end
	lines = {}
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

function JANUSSDP.findPayloadType(sdp, codec)
	if sdp == nil or codec == nil then
		return -1
	end
	local pt = -1
	local codecUpper = codec:upper()
	local codecLower = codec:lower()
	local index = nil
	local a = nil
	for index,a in pairs(sdp) do
		if a.name == "rtpmap" and a.value ~= nil then
			if a.value:find(codecLower) ~= nil or a.value:find(codecUpper) ~= nil then
				local n = a.value:gmatch("[^ ]+")
				pt = tonumber(n())
				break
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
				elseif a.value:find("pcmu") ~= nil or a.value:find("PCMU") ~= nil then
					codec = "pcmu"
				elseif a.value:find("pcma") ~= nil or a.value:find("PCMA") ~= nil then
					codec = "pcma"
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
		elseif JANUSSDP.findPayloadType(offer, "vp9") > 0 then
			options.videoCodec = "vp9"
		elseif JANUSSDP.findPayloadType(offer, "h264") > 0 then
			options.videoCodec = "h264"
		end
	end
	if options.data == nil then options.data = true end
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
					videoPt = JANUSSDP.findPayloadType(offer, options.videoCodec)
				end
				if videoPt < 0 then
					audio = audio+1
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
