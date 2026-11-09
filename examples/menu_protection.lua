-- Run once in MENU after the DLL has initialized.
assert(MENU_DLL and type(MenuCompileStringControl) == "table", "MENU API unavailable")
MenuCompileStringControl.enabled = true

local maxCode, maxIdentifier, rate = 1024 * 1024, 4096, 256
local tokens, last = rate, SysTime()
local lastPrint, suppressed = -math.huge, 0

local function block(reason, identifier, now)
    if now - lastPrint >= 1 then
        print("[MSC] BLOCKED:", reason, "identifier:", identifier:sub(1, 96), "suppressed:", suppressed)
        lastPrint, suppressed = now, 0
    else
        suppressed = suppressed + 1
    end
    return false
end

hook.Add("compilestring", "msc_protection", function(code, identifier)
    local now = SysTime()
    tokens = math.min(rate, tokens + math.max(0, now - last) * rate)
    last = now

    if tokens < 1 then return block("rate limit", identifier, now) end
    tokens = tokens - 1
    if #code > maxCode then return block("code too large", identifier, now) end
    if #identifier > maxIdentifier then return block("identifier too long", identifier, now) end
end)

print("[MSC] CompileString protection enabled")
