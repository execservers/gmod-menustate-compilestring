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

namespace {
namespace LuaType = GarrysMod::Lua::Type;
using GarrysMod::Lua::ILuaBase;
using GarrysMod::Lua::ILuaInterface;
using GarrysMod::Lua::ILuaShared;
using Factory = void* (__cdecl*)(const char*, int*);

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

    local wrapper = function(code, ...)
        if type(code) == "string" then
            local identifier, handleError = ...
            if type(identifier) == "string" then
                local verdict = bridge(code, identifier, handleError)
                if verdict == false then
                    return function() end -- Suppress execution, still return a function.
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
thread_local bool g_inMenuHook = false;

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

    if (g_inMenuHook ||
        GetCurrentThreadId() != g_gameThreadId.load(std::memory_order_acquire) ||
        client->GetType(1) != LuaType::String ||
        client->GetType(2) != LuaType::String) {
        return 0; // Fail open if this would cross threads or recurse.
    }

    ILuaShared* shared = g_shared.load(std::memory_order_acquire);
    if (!shared || shared->GetLuaInterface(GarrysMod::Lua::State::CLIENT) != client)
        return 0;
    ILuaInterface* menu = shared->GetLuaInterface(GarrysMod::Lua::State::MENU);
    if (!menu) return 0;

    try {
        unsigned int codeLen = 0, idLen = 0;
        const char* code = client->GetString(1, &codeLen);
        const char* identifier = client->GetString(2, &idLen);
        if (!code || !identifier) return 0;

        // Copy before invoking another Lua realm: the source state may perform GC
        // as a consequence of other native MENU callbacks.
        const std::string source(code, codeLen);
        const std::string chunk(identifier, idLen);
        const bool handleError = client->Top() < 3 ||
                                 client->GetType(3) == LuaType::Nil ||
                                 client->GetBool(3);

        ScopedCallback callbackGuard;
        ILuaBase* lua = static_cast<ILuaBase*>(menu);
        ScopedLuaStack menuStack(lua);
        lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
        lua->GetField(-1, "hook");
        if (lua->GetType(-1) != LuaType::Table) return 0;
        lua->GetField(-1, "Run");
        if (lua->GetType(-1) != LuaType::Function) return 0;
        lua->PushString(kHookName);
        lua->PushString(source.c_str(), codeLen);
        lua->PushString(chunk.c_str(), idLen);
        lua->PushBool(handleError);
        if (lua->PCall(4, 1, 0) != 0) {
            LogHookFailure();
            return 0;
        }
        if (lua->GetType(-1) == LuaType::Bool && !lua->GetBool(-1)) {
            client->PushBool(false);
            return 1;
        }
        if (lua->GetType(-1) == LuaType::String) {
            unsigned int replacementLen = 0;
            const char* replacement = lua->GetString(-1, &replacementLen);
            if (replacement) {
                client->PushString(replacement, replacementLen);
                return 1;
            }
        }
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

void Tick() {
    ILuaShared* shared = FindShared();
    if (!shared) return;
    ILuaInterface* menu = shared->GetLuaInterface(GarrysMod::Lua::State::MENU);
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
    if (InstallClient(client)) {
        g_status.store(1, std::memory_order_release);
        Log("[msc] CLIENT CompileString wrapper installed; MENU hook is available\n");
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
