#pragma once

#include <string_view>

// Built only in *_stdout_ DLLs. Never writes to the console from Lua threads.
namespace StdoutConsole {
void Start() noexcept;
void Publish(std::string_view identifier, std::string_view source,
             const char* result, const std::string_view* replacement = nullptr) noexcept;
} // namespace StdoutConsole
