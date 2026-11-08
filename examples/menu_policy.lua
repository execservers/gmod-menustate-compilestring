-- Execute this Lua file in MENU state (MENU_DLL == true), not CLIENT.
-- All callbacks use: (code, identifier, handleError).
assert(MENU_DLL, "menu_policy.lua must be run in MENU Lua state")

hook.Add("compilestring", "msc_example_policy", function(code, identifier, handleError)
    -- Example: only log the identifier, not the full code.
    MsgN("[msc] CompileString: ", identifier, " (", #code, " bytes)")

    -- Explicitly deny one test chunk. Return false to substitute a no-op function.
    if identifier == "msc_test_blocked" then
        return false
    end

    -- Replace a test chunk's source. Returning nil means unchanged.
    if identifier == "msc_test_replaced" then
        return "print('[msc] replacement compiled and executed')"
    end
end)
