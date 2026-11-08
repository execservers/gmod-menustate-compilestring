-- Run once in MENU after the DLL has initialized.
assert(MENU_DLL and type(MenuCompileStringControl) == "table", "MENU API unavailable")
MenuCompileStringControl.enabled = true

local maxCode, maxIdentifier, rate = 1024 * 1024, 4096, 256
local tokens, last = rate, SysTime()

hook.Add("compilestring", "protection", function(code, identifier)
    local now = SysTime()
    tokens = math.min(rate, tokens + math.max(0, now - last) * rate)
    last = now

    if tokens < 1 then return false end
    tokens = tokens - 1
    if #code > maxCode or #identifier > maxIdentifier then return false end
end)
