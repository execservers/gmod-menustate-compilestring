-- CLIENT-side smoke test. With the observer example, nothing is blocked/rewritten.
assert(CLIENT, "Run this script in CLIENT")

local fn = CompileString("return 42", "msc_test_original")
assert(type(fn) == "function" and fn() == 42)

local alias = CompileString
local second = alias("return 'alias'", "msc_test_local_alias")
assert(type(second) == "function" and second() == "alias")

local syntaxError = CompileString("local =", "msc_syntax_error", false)
assert(type(syntaxError) == "string")

print("[msc] original CompileString behavior preserved")
