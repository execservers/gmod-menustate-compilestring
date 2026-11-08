// Windows-only injected Garry's Mod CLIENT CompileString bridge to MENU hook.Run.
// The DLL is process-lifetime: unloading it while Lua owns our C function is unsafe.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/LuaInterface.h>
#include <GarrysMod/Lua/LuaShared.h>

#include <atomic>
#include <string>
#include <string_view>

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

constexpr char kBridgeName[] = "__msc_bridge_40ad3b1e";
constexpr char kMarkerName[] = "__msc_wrapper_40ad3b1e";
constexpr char kHookName[] = "compilestring";
constexpr char kControlName[] = "MenuCompileStringControl";

// Runs within CLIENT, only to delegate the decision to MENU; compilation still
// goes through the original client Lua function (preserving its error behavior).
constexpr char kClientBootstrap[] = R"LUA(
do
    local original = rawget(_G, "CompileString")
    local bridge = rawget(_G, "__msc_bridge_40ad3b1e")
    if type(original) ~= "function" or type(bridge) ~= "function" then return end

    local blockedFunction = function() end
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

void Log(const char* message) noexcept {
    OutputDebugStringA(message);
}

void LogHookFailure() noexcept {
    if (g_errorLogs.fetch_add(1, std::memory_order_relaxed) < 5)
        Log("[msc] MENU compilestring hook failed; keeping original CompileString\n");
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

// Lua bridge: only a MENU hook may alter a CompileString invocation.
// No built-in size, frequency or source-content policy is applied.
// In the _stdout_ build, only the diagnostic *copy* is bounded/truncated.
int ClientDecision(lua_State* state) {
    ILuaBase* client = state->luabase;
    client->SetState(state);

    if (client->GetType(1) != LuaType::String ||
        client->GetType(2) != LuaType::String) return 0;

    unsigned int codeLength = 0;
    unsigned int identifierLength = 0;
    const char* code = client->GetString(1, &codeLength);
    const char* identifier = client->GetString(2, &identifierLength);
    if (!code || !identifier) return 0;

#ifdef MENUSTATE_COMPILESTRING_STDOUT
    const std::string_view codeView(code, codeLength);
    const std::string_view identifierView(identifier, identifierLength);
    const auto report = [&](const char* result,
                            const std::string_view* replacement = nullptr) noexcept {
        StdoutConsole::Publish(identifierView, codeView, result, replacement);
    };
#else
    const auto report = [](const char*, const std::string_view* = nullptr) noexcept {};
#endif

    if (g_inMenuHook ||
        GetCurrentThreadId() != g_gameThreadId.load(std::memory_order_acquire)) {
        report("UNCHANGED (reentrant or unexpected thread)");
        return 0;
    }

    try {
        ILuaShared* shared = g_shared.load(std::memory_order_acquire);
        if (!shared) {
            report("UNCHANGED (lua_shared unavailable)");
            return 0;
        }
        ILuaInterface* knownClient = shared->GetLuaInterface(GarrysMod::Lua::State::CLIENT);
        if (knownClient ? static_cast<ILuaBase*>(knownClient) != client
                        : !static_cast<ILuaInterface*>(client)->IsClient()) {
            report("UNCHANGED (unexpected Lua realm)");
            return 0;
        }
        ILuaInterface* menu = shared->GetLuaInterface(GarrysMod::Lua::State::MENU);
        if (!menu) {
            report("UNCHANGED (MENU unavailable)");
            return 0;
        }

        ScopedCallback callbackGuard;
        ILuaBase* lua = static_cast<ILuaBase*>(menu);
        ScopedLuaStack menuStack(lua);
        lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);

        // An explicit MENU API option can suspend callbacks. stdout diagnostics
        // remain independent of this option and never change compilation.
        lua->GetField(-1, kControlName);
        if (lua->GetType(-1) == LuaType::Table) {
            lua->GetField(-1, "enabled");
            const bool disabled = lua->GetType(-1) == LuaType::Bool && !lua->GetBool(-1);
            lua->Pop();
            if (disabled) {
                report("UNCHANGED (disabled by MENU)");
                return 0;
            }
        }
        lua->Pop(); // MenuCompileStringControl or nil

        lua->GetField(-1, "hook");
        if (lua->GetType(-1) != LuaType::Table) {
            report("UNCHANGED (no MENU hook library)");
            return 0;
        }
        lua->GetField(-1, "Run");
        if (lua->GetType(-1) != LuaType::Function) {
            report("UNCHANGED (no MENU hook.Run)");
            return 0;
        }

        // Strings are copied before calling into a different Lua realm. This
        // allocation is the cost of handing the *complete* data to MENU.
        const std::string source(code, codeLength);
        const std::string chunk(identifier, identifierLength);
        const bool handleError = client->Top() < 3 ||
                                 client->GetType(3) == LuaType::Nil ||
                                 client->GetBool(3);

        lua->PushString(kHookName);
        lua->PushString(source.data(), codeLength);
        lua->PushString(chunk.data(), identifierLength);
        lua->PushBool(handleError);
        if (lua->PCall(4, 1, 0) != 0) {
            LogHookFailure();
            report("UNCHANGED (MENU hook error)");
            return 0;
        }
        if (lua->GetType(-1) == LuaType::Bool && !lua->GetBool(-1)) {
            report("BLOCKED (MENU returned false)");
            client->PushBool(false);
            return 1;
        }
        if (lua->GetType(-1) == LuaType::String) {
            unsigned int replacementLength = 0;
            const char* replacement = lua->GetString(-1, &replacementLength);
            if (replacement) {
                const std::string_view rewritten(replacement, replacementLength);
                report("REPLACED (MENU returned string)", &rewritten);
                client->PushString(rewritten.data(), replacementLength);
                return 1;
            }
        }
        report("UNCHANGED");
    } catch (...) {
        LogHookFailure();
        report("UNCHANGED (bridge exception)");
    }
    return 0;
}

// MENU global is created as soon as MENU becomes available to the injector.
// It is a plain Lua table; users own the callback decisions via hook.Add.
// Only 'enabled' is user-writable. Other fields are diagnostic snapshots.
void UpdateMenuControl(ILuaInterface* menu) {
    ILuaBase* lua = static_cast<ILuaBase*>(menu);
    ScopedLuaStack stack(lua);
    lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
    lua->GetField(-1, kControlName);
    if (lua->GetType(-1) != LuaType::Table) {
        lua->Pop();
        lua->CreateTable();
        lua->PushBool(true);
        lua->SetField(-2, "enabled");
        lua->Push(-1);
        lua->SetField(-3, kControlName);
    }

    lua->PushBool(g_earlyDetoursInstalled.load(std::memory_order_acquire));
    lua->SetField(-2, "earlyHookInstalled");
    const int status = g_status.load(std::memory_order_acquire);
    lua->PushBool(status == 1);
    lua->SetField(-2, "clientHookInstalled");
    const char* statusName = "waiting";
    if (status == 1) statusName = "installed";
    else if (status == 2) statusName = "replaced";
    else if (status == -1) statusName = "disabled";
    lua->PushString(statusName);
    lua->SetField(-2, "status");
#ifdef MENUSTATE_COMPILESTRING_STDOUT
    lua->PushBool(true);
#else
    lua->PushBool(false);
#endif
    lua->SetField(-2, "stdout");
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
    if (!menu) return;
    InstallEarlyDetours(menu);
    ILuaInterface* client = shared->GetLuaInterface(GarrysMod::Lua::State::CLIENT);
    if (!client) {
        g_status.store(0, std::memory_order_release);
        UpdateMenuControl(menu);
        return;
    }
    auto* lua = static_cast<ILuaBase*>(client);
    const ClientState state = CheckClient(lua);
    if (state == ClientState::Installed) {
        g_status.store(1, std::memory_order_release);
        UpdateMenuControl(menu);
        return;
    }
    if (state == ClientState::Replaced) {
        // Another addon may have wrapped the function. Do not overwrite it.
        if (g_status.exchange(2, std::memory_order_acq_rel) != 2)
            Log("[msc] CLIENT CompileString changed after installation; not rewrapping\n");
        UpdateMenuControl(menu);
        return;
    }
    // Fallback for injection into an already running CLIENT. Cannot recover
    // CompileString calls that occurred during includes/init.lua.
    if (InstallClient(client)) {
        g_status.store(1, std::memory_order_release);
        Log("[msc] CLIENT wrapper installed late; earlier calls were missed\n");
    }
    UpdateMenuControl(menu);
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

