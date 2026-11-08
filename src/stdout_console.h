#pragma once

#include <string>

// Built only in *_stdout_ DLLs. Never writes to a console on a Lua thread.
namespace StdoutConsole {
void Start() noexcept;
void Publish(const std::string& identifier, const std::string& source,
             const char* result, const std::string* replacement = nullptr) noexcept;
} // namespace StdoutConsole
