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
		print(logPrefix .. text)
	else
		print(logPrefix .. "(nil)")
	end
end

return JANUSLOG
