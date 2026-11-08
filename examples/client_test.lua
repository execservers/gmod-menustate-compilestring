-- Execute in CLIENT state after DLL status == 1 and the MENU hook is registered.
assert(CLIENT, "client_test.lua must be run in CLIENT Lua state")
local allow = CompileString("print('[msc] original compiled and executed')", "msc_test_allowed")
assert(type(allow) == "function")
allow()

local blocked = CompileString("error('THIS SHOULD NEVER EXECUTE')", "msc_test_blocked")
assert(type(blocked) == "function")
blocked()

local replaced = CompileString("error('THIS SHOULD BE REPLACED')", "msc_test_replaced")
assert(type(replaced) == "function")
replaced()

-- With handleError=false, original error-return-string behavior is preserved.
local syntaxError = CompileString("local =", "msc_syntax_error", false)
assert(type(syntaxError) == "string")

print("[msc] CLIENT tests finished")
