-- Run in MENU, after MenuCompileStringControl becomes available.
assert(MENU_DLL, "Run this script in the MENU Lua state")
assert(type(MenuCompileStringControl) == "table", "DLL's MENU API is not ready")

MenuCompileStringControl.enabled = true

hook.Add("compilestring", "observer", function(code, identifier, handleError)
    MsgN("[msc] ", identifier, " (", #code, " bytes, handleError=", tostring(handleError), ")")
end)
