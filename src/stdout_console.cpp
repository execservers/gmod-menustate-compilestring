// Optional asynchronous console for CompileString diagnostics.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "stdout_console.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace {
struct Entry {
    std::string identifier;
    std::string source;
    std::string result;
    std::string replacement;
    bool replaced = false;
    size_t identifierLength = 0;
    size_t sourceLength = 0;
    size_t replacementLength = 0;

    size_t Size() const noexcept {
        return identifier.size() + source.size() + replacement.size();
    }
};

// Bound memory consumption if the game compiles faster than a terminal can print.
constexpr size_t kMaxQueuedBytes = 16 * 1024 * 1024;
constexpr size_t kMaxQueuedEntries = 256;
constexpr DWORD kWriteChunk = 16 * 1024;
// Limits affect console output ONLY, never CLIENT compilation or MENU decisions.
constexpr size_t kMaxLogIdentifier = 1024;
constexpr size_t kMaxLogSource = 64 * 1024;
constexpr size_t kMaxLogReplacement = 64 * 1024;

struct Queue {
    std::mutex mutex;
    std::condition_variable wakeup;
    std::deque<Entry> entries;
    size_t bytes = 0;
};

std::atomic<bool> g_active{false};
std::atomic<uint64_t> g_dropped{0};

Queue& SharedQueue() {
    // Both the pinned DLL and the detached writer live until process exit.
    static Queue* const queue = new Queue();
    return *queue;
}

void WriteBytes(HANDLE output, const char* value, size_t length) noexcept {
    while (length != 0) {
        DWORD written = 0;
        const DWORD chunk = static_cast<DWORD>(std::min(length, static_cast<size_t>(kWriteChunk)));
        if (!WriteFile(output, value, chunk, &written, nullptr) || !written) return;
        value += written;
        length -= written;
    }
}

void WriteText(HANDLE output, const char* text) noexcept {
    WriteBytes(output, text, std::char_traits<char>::length(text));
}

void WritePreview(HANDLE output, const std::string& text, size_t originalLength) noexcept {
    WriteBytes(output, text.data(), text.size());
    if (text.size() < originalLength) {
        const std::string suffix = "\r\n[truncated; " + std::to_string(originalLength) +
                                   " original bytes]";
        WriteBytes(output, suffix.data(), suffix.size());
    }
}

void Print(HANDLE output, const Entry& entry) noexcept {
    WriteText(output, "\r\n========== CompileString ==========\r\nIDENTIFIER: ");
    WritePreview(output, entry.identifier, entry.identifierLength);
    WriteText(output, "\r\nRESULT: ");
    WriteBytes(output, entry.result.data(), entry.result.size());
    WriteText(output, "\r\nSOURCE:\r\n");
    WritePreview(output, entry.source, entry.sourceLength);
    WriteText(output, "\r\n");
    if (entry.replaced) {
        WriteText(output, "REPLACEMENT:\r\n");
        WritePreview(output, entry.replacement, entry.replacementLength);
        WriteText(output, "\r\n");
    }
    WriteText(output, "===================================\r\n");
}

void Writer(HANDLE output) {
    for (;;) {
        Entry entry;
        {
            Queue& queue = SharedQueue();
            std::unique_lock<std::mutex> lock(queue.mutex);
            queue.wakeup.wait(lock, [&queue] { return !queue.entries.empty(); });
            entry = std::move(queue.entries.front());
            queue.bytes -= entry.Size();
            queue.entries.pop_front();
        }
        const uint64_t dropped = g_dropped.exchange(0, std::memory_order_relaxed);
        if (dropped) {
            WriteText(output, "\r\n[msc stdout] Dropped CompileString logs (full/busy queue): ");
            const std::string count = std::to_string(dropped);
            WriteBytes(output, count.data(), count.size());
            WriteText(output, "\r\n");
        }
        Print(output, entry);
    }
}
} // namespace

void StdoutConsole::Start() noexcept {
    // Do not steal or detach an existing console belonging to the host.
    const bool created = AllocConsole() != FALSE;
    if (!created && GetLastError() != ERROR_ACCESS_DENIED) return;

    if (created) {
        SetConsoleTitleW(L"GMod CompileString _stdout_");
        SetConsoleOutputCP(CP_UTF8);
        // Closing the new console via its X normally terminates the host game.
        // Disable the close menu item; the window closes when the game exits.
        if (HWND window = GetConsoleWindow()) {
            if (HMENU menu = GetSystemMenu(window, FALSE)) {
                EnableMenuItem(menu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
            }
        }
    }

    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!output || output == INVALID_HANDLE_VALUE) {
        if (created) FreeConsole();
        return;
    }
    try {
        SharedQueue();
        std::thread(Writer, output).detach();
        g_active.store(true, std::memory_order_release);
        WriteText(output, "[msc stdout] CompileString logging active (CLIENT -> MENU).\r\n");
    } catch (...) {
        // Not active unless the writer was successfully created.
        if (created) FreeConsole();
    }
}

void StdoutConsole::Publish(std::string_view identifier, std::string_view source,
                            const char* result, const std::string_view* replacement) noexcept {
    if (!g_active.load(std::memory_order_acquire)) return;
    try {
        Queue& queue = SharedQueue();
        // Do not wait for the console thread or copy large CLIENT strings while
        // the queue is busy. Dropped logs never affect compilation.
        std::unique_lock<std::mutex> lock(queue.mutex, std::try_to_lock);
        if (!lock.owns_lock() || queue.entries.size() >= kMaxQueuedEntries) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        Entry entry;
        entry.identifierLength = identifier.size();
        entry.sourceLength = source.size();
        entry.identifier.assign(identifier.data(), std::min(identifier.size(), kMaxLogIdentifier));
        entry.source.assign(source.data(), std::min(source.size(), kMaxLogSource));
        entry.result = result;
        entry.replaced = replacement != nullptr;
        if (replacement) {
            entry.replacementLength = replacement->size();
            entry.replacement.assign(replacement->data(),
                                     std::min(replacement->size(), kMaxLogReplacement));
        }

        const size_t bytes = entry.Size();
        if (bytes > kMaxQueuedBytes - queue.bytes) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        queue.entries.push_back(std::move(entry));
        queue.bytes += bytes;
        lock.unlock();
        queue.wakeup.notify_one();
    } catch (...) {
        g_dropped.fetch_add(1, std::memory_order_relaxed);
    }
}
