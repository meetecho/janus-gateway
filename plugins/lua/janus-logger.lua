-- Simple logger for Lua scripts, which at the moment simply wraps calls
-- to print(..), with the ability to specify a custom prefix. In the
-- future this may be made much more sophisticated, but we don't care now.

local JANUSLOG = {}

logPrefix = ""

function JANUSLOG.prefix(prefix)
	if prefix ~= nil then
		logPrefix = prefix .. " "
	end
end

function JANUSLOG.print(text)
	if text ~= nil then
		janusLog(4, logPrefix .. text)
	else
		janusLog(4, logPrefix .. "(nil)")
	end
end

function JANUSLOG.verbose(text)
	if text ~= nil then
		janusLog(5, logPrefix .. text)
	else
		janusLog(5, logPrefix .. "(nil)")
	end
end

function JANUSLOG.warn(text)
	if text ~= nil then
		janusLog(3, logPrefix .. text)
	else
		janusLog(3, logPrefix .. "(nil)")
	end
end

function JANUSLOG.error(text)
	if text ~= nil then
		janusLog(2, logPrefix .. text)
	else
		janusLog(2, logPrefix .. "(nil)")
	end
end

return JANUSLOG
