// Windows-only injected Garry's Mod CLIENT CompileString bridge to MENU hook.Run.
// The DLL is process-lifetime: unloading it while Lua owns our C function is unsafe.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/LuaInterface.h>
#include <GarrysMod/Lua/LuaShared.h>

#include <algorithm>
#include <atomic>
#include <string>

#ifdef MENUSTATE_COMPILESTRING_STDOUT
#include "stdout_console.h"
#endif

namespace {
namespace LuaType = GarrysMod::Lua::Type;
using GarrysMod::Lua::ILuaBase;
using GarrysMod::Lua::ILuaInterface;
using GarrysMod::Lua::ILuaShared;
using Factory = void* (__cdecl*)(const char*, int*);
using RunStringFn = bool (__thiscall*)(ILuaInterface*, const char*, const char*,
                                      const char*, bool, bool);
using RunStringExFn = bool (__thiscall*)(ILuaInterface*, const char*, const char*,
                                        const char*, bool, bool, bool, bool);
using FindAndRunScriptFn = bool (__thiscall*)(ILuaInterface*, const char*, bool,
                                             bool, const char*, bool);

// garrysmod_common MSVC vtable layout: ILuaBase has 55 virtual functions.
// Check these indices against the selected header revision before upgrades.
constexpr size_t kRunStringSlot = 92;
constexpr size_t kRunStringExSlot = 111;
constexpr size_t kFindAndRunScriptSlot = 97;

// Prevent attacker-controlled strings/floods from forcing large allocations,
// excessive MENU transitions, or unbounded stdout work on the game thread.
constexpr unsigned int kMaxIdentifierBytes = 4096;
constexpr unsigned int kMaxSourceBytes = 1024 * 1024;
constexpr unsigned int kMaxCallsPerSecond = 256;
#ifdef MENUSTATE_COMPILESTRING_STDOUT
constexpr unsigned int kPreviewBytes = 160;
#endif


constexpr char kBridgeName[] = "__msc_bridge_40ad3b1e";
constexpr char kMarkerName[] = "__msc_wrapper_40ad3b1e";
constexpr char kHookName[] = "compilestring";

// Runs within CLIENT, only to delegate the decision to MENU; compilation still
// goes through the original client Lua function (preserving its error behavior).
constexpr char kClientBootstrap[] = R"LUA(
do
    local original = rawget(_G, "CompileString")
    local bridge = rawget(_G, "__msc_bridge_40ad3b1e")
    if type(original) ~= "function" or type(bridge) ~= "function" then return end

    local blockedFunction = function() end -- Reuse this for large batches.
    local wrapper = function(code, ...)
        if type(code) == "string" then
            local identifier, handleError = ...
            if type(identifier) == "string" then
                local verdict = bridge(code, identifier, handleError)
                if verdict == false then
                    return blockedFunction -- No per-call closure allocation.
                elseif type(verdict) == "string" then
                    code = verdict
                end
            end
        end
        return original(code, ...) -- Preserve argument count, errors and varargs.
    end

    rawset(_G, "CompileString", wrapper)
    rawset(_G, "__msc_wrapper_40ad3b1e", wrapper)
    rawset(_G, "__msc_bridge_40ad3b1e", nil) -- Keep C function in local upvalue only.
end
)LUA";

// 0: waiting for CLIENT/MENU; 1: wrapped; 2: global replaced externally;
// -1: fatal bootstrap error. Never automatically unpin or unload the DLL.
std::atomic<int> g_status{0};
std::atomic<DWORD> g_gameThreadId{0};
std::atomic<ILuaShared*> g_shared{nullptr};
std::atomic<HHOOK> g_windowHook{nullptr};
std::atomic<unsigned> g_errorLogs{0};
std::atomic<bool> g_earlyDetoursInstalled{false};
RunStringFn g_originalRunString = nullptr;
RunStringExFn g_originalRunStringEx = nullptr;
FindAndRunScriptFn g_originalFindAndRunScript = nullptr;
thread_local bool g_inMenuHook = false;
thread_local bool g_installing = false;
thread_local ULONGLONG g_rateWindowStart = 0;
thread_local unsigned int g_rateWindowCalls = 0;
thread_local unsigned int g_suppressed = 0;

void Log(const char* message) noexcept {
    OutputDebugStringA(message);
}

void LogHookFailure() noexcept {
    if (g_errorLogs.fetch_add(1, std::memory_order_relaxed) < 5)
        Log("[msc] MENU compilestring hook errored; allowing original CompileString\n");
}

class ScopedLuaStack final {
public:
    explicit ScopedLuaStack(ILuaBase* lua) : lua_(lua), top_(lua->Top()) {}
    ~ScopedLuaStack() {
        const int extra = lua_->Top() - top_;
        if (extra > 0) lua_->Pop(extra);
    }
    ScopedLuaStack(const ScopedLuaStack&) = delete;
    ScopedLuaStack& operator=(const ScopedLuaStack&) = delete;
private:
    ILuaBase* lua_;
    int top_;
};

class ScopedInstalling final {
public:
    ScopedInstalling() : prior_(g_installing) { g_installing = true; }
    ~ScopedInstalling() { g_installing = prior_; }
    ScopedInstalling(const ScopedInstalling&) = delete;
    ScopedInstalling& operator=(const ScopedInstalling&) = delete;
private:
    bool prior_;
};

class ScopedCallback final {
public:
    ScopedCallback() { g_inMenuHook = true; }
    ~ScopedCallback() { g_inMenuHook = false; }
    ScopedCallback(const ScopedCallback&) = delete;
    ScopedCallback& operator=(const ScopedCallback&) = delete;
};

// Called by the Lua wrapper only. Returns nil (allow), false (block), or a
// replacement string. Strings are transferred by value, not as Lua references.
int ClientDecision(lua_State* state) {
    ILuaBase* client = state->luabase;
    client->SetState(state);

    if (client->GetType(1) != LuaType::String ||
        client->GetType(2) != LuaType::String) return 0;

    try {
        unsigned int codeLen = 0, idLen = 0;
        const char* code = client->GetString(1, &codeLen);
        const char* identifier = client->GetString(2, &idLen);
        if (!code || !identifier) return 0;

        // Never copy a huge Lua string into C++ or pass it to MENU. The large
        // identifier in the reported init.lua snippet is ~100 million bytes.
        if (idLen > kMaxIdentifierBytes || codeLen > kMaxSourceBytes) {
#ifdef MENUSTATE_COMPILESTRING_STDOUT
            const std::string idPreview(identifier, std::min(idLen, kPreviewBytes));
            const std::string codePreview(code, std::min(codeLen, kPreviewBytes));
            StdoutConsole::Publish(idPreview, codePreview,
                idLen > kMaxIdentifierBytes ? "BLOCKED (oversized identifier; preview only)"
                                            : "BLOCKED (oversized source; preview only)", nullptr);
#endif
            client->PushBool(false);
            return 1;
        }

        // Protect the UI thread against Lua compilation floods. Even 250,000
        // tiny MENU callbacks can exceed the ~10s budget in the supplied case.
        const ULONGLONG now = GetTickCount64();
        if (!g_rateWindowStart || now - g_rateWindowStart >= 1000) {
            g_rateWindowStart = now;
            g_rateWindowCalls = 0;
            g_suppressed = 0;
        }
        if (++g_rateWindowCalls > kMaxCallsPerSecond) {
            ++g_suppressed;
#ifdef MENUSTATE_COMPILESTRING_STDOUT
            // Log sparsely; do not enqueue a quarter-million log messages.
            if (g_suppressed == 1 || (g_suppressed % 16384) == 0) {
                const std::string idPreview(identifier, std::min(idLen, kPreviewBytes));
                const std::string codePreview(code, std::min(codeLen, kPreviewBytes));
                StdoutConsole::Publish(idPreview, codePreview,
                    "BLOCKED (CompileString rate limit; preview only)", nullptr);
            }
#endif
            client->PushBool(false);
            return 1;
        }

        // Copy data before entering another Lua realm; MENU callbacks may GC.
        const std::string source(code, codeLen);
        const std::string chunk(identifier, idLen);
        const bool handleError = client->Top() < 3 ||
                                 client->GetType(3) == LuaType::Nil ||
                                 client->GetBool(3);
        // The non-stdout build has no console dependency or logging overhead.
        const auto report = [&](const char* decision,
                                const std::string* replacement = nullptr) noexcept {
#ifdef MENUSTATE_COMPILESTRING_STDOUT
            StdoutConsole::Publish(chunk, source, decision, replacement);
#else
            (void)decision;
            (void)replacement;
#endif
        };

        if (g_inMenuHook ||
            GetCurrentThreadId() != g_gameThreadId.load(std::memory_order_acquire)) {
            report("BYPASS (reentrant or wrong thread)");
            return 0; // Fail open on recursion or unexpected Lua thread.
        }

        ILuaShared* shared = g_shared.load(std::memory_order_acquire);
        if (!shared) {
            report("BYPASS (lua_shared unavailable)");
            return 0;
        }
        // At the earliest CLIENT bootstrap GetLuaInterface(CLIENT) may not be
        // exposed yet. The VM's native realm check still identifies CLIENT.
        ILuaInterface* knownClient = shared->GetLuaInterface(GarrysMod::Lua::State::CLIENT);
        if (knownClient ? static_cast<ILuaBase*>(knownClient) != client
                        : !static_cast<ILuaInterface*>(client)->IsClient()) {
            report("BYPASS (unexpected Lua realm)");
            return 0;
        }
        ILuaInterface* menu = shared->GetLuaInterface(GarrysMod::Lua::State::MENU);
        if (!menu) {
            report("BYPASS (MENU state unavailable)");
            return 0;
        }

        ScopedCallback callbackGuard;
        ILuaBase* lua = static_cast<ILuaBase*>(menu);
        ScopedLuaStack menuStack(lua);
        lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
        lua->GetField(-1, "hook");
        if (lua->GetType(-1) != LuaType::Table) {
            report("ALLOW (no MENU hook table)");
            return 0;
        }
        lua->GetField(-1, "Run");
        if (lua->GetType(-1) != LuaType::Function) {
            report("ALLOW (no MENU hook.Run)");
            return 0;
        }
        lua->PushString(kHookName);
        lua->PushString(source.data(), codeLen);
        lua->PushString(chunk.data(), idLen);
        lua->PushBool(handleError);
        if (lua->PCall(4, 1, 0) != 0) {
            LogHookFailure();
            report("ALLOW (MENU hook error)");
            return 0;
        }
        if (lua->GetType(-1) == LuaType::Bool && !lua->GetBool(-1)) {
            report("BLOCKED");
            client->PushBool(false);
            return 1;
        }
        if (lua->GetType(-1) == LuaType::String) {
            unsigned int replacementLen = 0;
            const char* replacement = lua->GetString(-1, &replacementLen);
            if (replacement) {
                if (replacementLen > kMaxSourceBytes) {
                    report("BLOCKED (oversized MENU replacement)");
                    client->PushBool(false);
                    return 1;
                }
                const std::string rewritten(replacement, replacementLen);
                report("REPLACED", &rewritten);
                client->PushString(rewritten.data(), replacementLen);
                return 1;
            }
        }
        report("ALLOWED");
    } catch (...) {
        LogHookFailure();
    }
    return 0;
}

// The marker lives in the CLIENT global table and disappears when that realm is
// recreated. Never retain Lua references across disconnect/reconnect cycles.
enum class ClientState { Waiting, Installed, Replaced };
ClientState CheckClient(ILuaBase* lua) {
    ScopedLuaStack stack(lua);
    lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
    lua->GetField(-1, "CompileString");
    const bool compilable = lua->GetType(-1) == LuaType::Function;
    lua->GetField(-2, kMarkerName);
    const bool marked = lua->GetType(-1) == LuaType::Function;
    if (!marked) return ClientState::Waiting;
    if (compilable && lua->RawEqual(-1, -2)) return ClientState::Installed;
    return ClientState::Replaced;
}

bool InstallClient(ILuaInterface* client) {
    ScopedInstalling installGuard; // Bootstrap itself may enter RunStringEx.
    ILuaBase* lua = static_cast<ILuaBase*>(client);
    {
        ScopedLuaStack stack(lua);
        lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
        lua->GetField(-1, "CompileString");
        if (lua->GetType(-1) != LuaType::Function) return false;
        lua->Pop();
        lua->PushCFunction(&ClientDecision);
        lua->SetField(-2, kBridgeName);
    }

    // RunString is used solely to install a Lua wrapper, NOT as a detour.
    // This leaves the game's native CompileString untouched.
    client->RunString(
        "msc_compilestring_bootstrap", "LUA", kClientBootstrap, true, true);
    const bool installed = CheckClient(lua) == ClientState::Installed;
    if (!installed) {
        ScopedLuaStack stack(lua);
        lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
        lua->PushNil();
        lua->SetField(-2, kBridgeName);
    }
    return installed;
}

ILuaShared* FindShared() {
    ILuaShared* shared = g_shared.load(std::memory_order_acquire);
    if (shared) return shared;
    HMODULE library = GetModuleHandleW(L"lua_shared.dll");
    if (!library) return nullptr;
    auto factory = reinterpret_cast<Factory>(GetProcAddress(library, "CreateInterface"));
    if (!factory) return nullptr;
    shared = static_cast<ILuaShared*>(factory(GMOD_LUASHARED_INTERFACE, nullptr));
    if (shared) g_shared.store(shared, std::memory_order_release);
    return shared;
}

// Early interception is essential: lua/includes/init.lua is the first CLIENT
// script. Polling for an already running CLIENT state is too late, especially
// for scripts that cache local CS = CompileString before our wrapper exists.
// Install detours on the existing MENU interface vtable while still in menu.
// They do not replace script content; before the first CLIENT script entry they
// install the same lightweight global CompileString wrapper as before.
#if defined(_M_IX86)
#define MSC_DETOUR_CALL __fastcall
#define MSC_DETOUR_THIS ILuaInterface* self, void*,
#else
#define MSC_DETOUR_CALL
#define MSC_DETOUR_THIS ILuaInterface* self,
#endif

void BeforeClientScript(ILuaInterface* self) {
    if (g_status.load(std::memory_order_acquire) == -1 ||
        g_installing || !self || !g_earlyDetoursInstalled.load(std::memory_order_acquire))
        return;
    if (GetCurrentThreadId() != g_gameThreadId.load(std::memory_order_acquire))
        return;
    ILuaShared* shared = g_shared.load(std::memory_order_acquire);
    if (!shared) return;
    // IsClient also works during creation when GetLuaInterface(CLIENT) might
    // not yet have been published by ILuaShared.
    if (!self->IsClient()) return;
    if (shared->GetLuaInterface(GarrysMod::Lua::State::MENU) == self) return;
    try {
        auto* lua = static_cast<ILuaBase*>(self);
        const ClientState state = CheckClient(lua);
        if (state == ClientState::Waiting && InstallClient(self)) {
            g_status.store(1, std::memory_order_release);
            Log("[msc] installed before CLIENT script execution\n");
        }
    } catch (...) {
        Log("[msc] early CLIENT wrapper installation failed\n");
    }
}

void GuardedBeforeClientScript(ILuaInterface* self) {
    __try {
        BeforeClientScript(self);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_status.store(-1, std::memory_order_release);
        Log("[msc] exception at early script-entry probe; disabling instrumentation\n");
    }
}

bool MSC_DETOUR_CALL OnRunString(MSC_DETOUR_THIS const char* filename,
        const char* path, const char* source, bool run, bool errors) {
    if (!g_originalRunString) return false;
    GuardedBeforeClientScript(self);
    return g_originalRunString(self, filename, path, source, run, errors);
}

bool MSC_DETOUR_CALL OnRunStringEx(MSC_DETOUR_THIS const char* filename,
        const char* path, const char* source, bool run, bool errors,
        bool dontPushErrors, bool noReturns) {
    if (!g_originalRunStringEx) return false;
    GuardedBeforeClientScript(self);
    return g_originalRunStringEx(self, filename, path, source, run, errors,
                                  dontPushErrors, noReturns);
}

bool MSC_DETOUR_CALL OnFindAndRunScript(MSC_DETOUR_THIS const char* filename,
        bool run, bool errors, const char* source, bool noReturns) {
    if (!g_originalFindAndRunScript) return false;
    GuardedBeforeClientScript(self);
    return g_originalFindAndRunScript(self, filename, run, errors, source, noReturns);
}

bool PatchSlot(void** slot, void* replacement) {
    DWORD oldProtection = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtection))
        return false;
    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(slot), replacement);
    DWORD ignored = 0;
    VirtualProtect(slot, sizeof(void*), oldProtection, &ignored);
    return true;
}

bool InstallEarlyDetours(ILuaInterface* menu) {
    if (g_earlyDetoursInstalled.load(std::memory_order_acquire)) return true;
    if (!menu) return false;
    // MENU must be initialized before we install the early CLIENT trampoline.
    ILuaBase* lua = static_cast<ILuaBase*>(menu);
    ScopedLuaStack stack(lua);
    lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
    lua->GetField(-1, "hook");
    if (lua->GetType(-1) != LuaType::Table) return false;
    lua->GetField(-1, "Run");
    if (lua->GetType(-1) != LuaType::Function) return false;

    auto** table = *reinterpret_cast<void***>(menu);
    if (!table || !table[kRunStringSlot] || !table[kRunStringExSlot] ||
        !table[kFindAndRunScriptSlot]) return false;
    g_originalRunString = reinterpret_cast<RunStringFn>(table[kRunStringSlot]);
    g_originalRunStringEx = reinterpret_cast<RunStringExFn>(table[kRunStringExSlot]);
    g_originalFindAndRunScript =
        reinterpret_cast<FindAndRunScriptFn>(table[kFindAndRunScriptSlot]);
    if (!PatchSlot(&table[kRunStringSlot], reinterpret_cast<void*>(&OnRunString)))
        return false;
    if (!PatchSlot(&table[kRunStringExSlot], reinterpret_cast<void*>(&OnRunStringEx))) {
        PatchSlot(&table[kRunStringSlot], reinterpret_cast<void*>(g_originalRunString));
        return false;
    }
    if (!PatchSlot(&table[kFindAndRunScriptSlot],
                   reinterpret_cast<void*>(&OnFindAndRunScript))) {
        PatchSlot(&table[kRunStringExSlot], reinterpret_cast<void*>(g_originalRunStringEx));
        PatchSlot(&table[kRunStringSlot], reinterpret_cast<void*>(g_originalRunString));
        return false;
    }
    g_earlyDetoursInstalled.store(true, std::memory_order_release);
    Log("[msc] early script-entry monitoring armed; join a server now\n");
    return true;
}

void Tick() {
    ILuaShared* shared = FindShared();
    if (!shared) return;
    ILuaInterface* menu = shared->GetLuaInterface(GarrysMod::Lua::State::MENU);
    if (menu) InstallEarlyDetours(menu);
    ILuaInterface* client = shared->GetLuaInterface(GarrysMod::Lua::State::CLIENT);
    if (!menu || !client) {
        g_status.store(0, std::memory_order_release);
        return;
    }
    auto* lua = static_cast<ILuaBase*>(client);
    const ClientState state = CheckClient(lua);
    if (state == ClientState::Installed) {
        g_status.store(1, std::memory_order_release);
        return;
    }
    if (state == ClientState::Replaced) {
        // Another addon may have deliberately wrapped our function. Rewrapping
        // it would cause duplicate policies, so do not change it again.
        if (g_status.exchange(2, std::memory_order_acq_rel) != 2)
            Log("[msc] CLIENT CompileString changed after installation; not rewrapping\n");
        return;
    }
    // Fallback for injection into an already running CLIENT. Cannot recover
    // CompileString calls that occurred during includes/init.lua.
    if (InstallClient(client)) {
        g_status.store(1, std::memory_order_release);
        Log("[msc] CLIENT wrapper installed late; earlier calls were missed\n");
    }
}

int WINAPI ProbeFilter(unsigned int) {
    g_status.store(-1, std::memory_order_release);
    Log("[msc] exception during interface probing; hook disabled\n");
    return EXCEPTION_EXECUTE_HANDLER;
}

void GuardedTick() {
    __try {
        Tick();
    } __except (ProbeFilter(GetExceptionCode())) {
        // A stale engine interface or incompatible ABI cannot be safely retried.
    }
}

LRESULT CALLBACK OnGetMessage(int code, WPARAM wp, LPARAM lp) {
    if (code >= 0 && g_status.load(std::memory_order_acquire) != -1) {
        static thread_local bool busy = false;
        static thread_local ULONGLONG nextCheck = 0;
        const ULONGLONG now = GetTickCount64();
        if (!busy && now >= nextCheck) {
            busy = true;
            nextCheck = now + 750;
            g_gameThreadId.store(GetCurrentThreadId(), std::memory_order_release);
            GuardedTick();
            busy = false;
        }
    }
    return CallNextHookEx(g_windowHook.load(std::memory_order_acquire), code, wp, lp);
}

struct GameWindow { DWORD threadId = 0; HWND handle = nullptr; };
BOOL CALLBACK FindGameWindow(HWND hwnd, LPARAM pointer) {
    auto* result = reinterpret_cast<GameWindow*>(pointer);
    DWORD processId = 0;
    const DWORD threadId = GetWindowThreadProcessId(hwnd, &processId);
    if (processId != GetCurrentProcessId() || !threadId ||
        !IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER)) return TRUE;
    wchar_t klass[128] = {};
    GetClassNameW(hwnd, klass, 128);
    if (!result->handle || lstrcmpiW(klass, L"Valve001") == 0) {
        result->handle = hwnd;
        result->threadId = threadId;
    }
    return lstrcmpiW(klass, L"Valve001") != 0;
}

DWORD WINAPI Bootstrap(void*) {
    // Pin this DLL: CLIENT Lua may retain our native callback indefinitely.
    HMODULE pinned = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&Bootstrap), &pinned)) {
        g_status.store(-1, std::memory_order_release);
        return 1;
    }
#ifdef MENUSTATE_COMPILESTRING_STDOUT
    StdoutConsole::Start();
#endif
    Log("[msc] injected; waiting for game window and Lua realms\n");
    for (;;) {
        if (g_status.load(std::memory_order_acquire) == -1) return 1;
        GameWindow window{};
        EnumWindows(&FindGameWindow, reinterpret_cast<LPARAM>(&window));
        if (window.handle && window.threadId &&
            !g_windowHook.load(std::memory_order_acquire)) {
            HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, &OnGetMessage,
                                           nullptr, window.threadId);
            if (hook) g_windowHook.store(hook, std::memory_order_release);
        }
        if (window.handle && g_windowHook.load(std::memory_order_acquire))
            PostMessageW(window.handle, WM_NULL, 0, 0);
        Sleep(500);
    }
}
} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        // No Lua or engine APIs under the loader lock. Worker only starts later.
        HANDLE worker = CreateThread(nullptr, 0, &Bootstrap, nullptr, 0, nullptr);
        if (!worker) return FALSE;
        CloseHandle(worker);
    }
    return TRUE;
}

extern "C" __declspec(dllexport) int __cdecl MenuCompileString_Status() {
    return g_status.load(std::memory_order_acquire);
}

// 1 means early native RunString monitoring is active; join AFTER observing it.
extern "C" __declspec(dllexport) int __cdecl MenuCompileString_EarlyHookStatus() {
    return g_earlyDetoursInstalled.load(std::memory_order_acquire) ? 1 : 0;
}
