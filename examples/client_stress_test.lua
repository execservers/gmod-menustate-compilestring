-- Controlled CLIENT test. No built-in rate limit or rejection is expected.
-- This may still be slow because MENU callbacks are synchronous.
assert(CLIENT, "Run in CLIENT")

local CS = CompileString
local original = CS("return true", string.rep("i", 4097))
assert(type(original) == "function" and original() == true)

for i = 1, 512 do
    local fn = CS("return true", tostring(i) .. "no.lua")
    assert(type(fn) == "function" and fn() == true)
end

print("[msc] all 513 calls remained allowed without a user policy")
