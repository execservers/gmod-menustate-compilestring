-- Execute on your own CLIENT after the early wrapper is active.
-- A bounded version of the startup example; DOES NOT allocate 100 MB.
assert(CLIENT)
assert(type(rawget(_G, '__msc_wrapper_40ad3b1e')) == 'function',
    'DLL global wrapper is not installed in CLIENT')

local CS = CompileString -- Tests the local alias scenario.

local oversized = CS('-- harmless', string.rep('x', 4097))
assert(type(oversized) == 'function')

for i = 1, 5000 do
    local fn = CS('-- harmless', tostring(i) .. 'no.lua')
    assert(type(fn) == 'function')
end

print('[msc] stress test finished; check sampled BLOCKED messages in stdout')
