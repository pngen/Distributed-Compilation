// Distributed Compilation - shared command line application helpers.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_APP_COMMON_HPP
#define DC_APP_COMMON_HPP

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"
#include "dc/persistence.hpp"
#include "dc/wire.hpp"

namespace dc {
namespace app {

// Optional service log. A long-running coordinator or worker appends every
// status line here so that a post-mortem does not depend on a live console.
inline std::string& service_log_path() {
  static std::string path;
  return path;
}

inline std::mutex& service_log_mutex() {
  static std::mutex mutex;
  return mutex;
}

inline void append_service_log(const std::string& line) {
  const std::string& path = service_log_path();
  if (path.empty()) return;
  std::lock_guard<std::mutex> guard(service_log_mutex());
#ifdef _WIN32
  // _fsopen with _SH_DENYNO is required: the default fopen sharing mode denies
  // concurrent writers, so a compile thread and the main loop would otherwise
  // silently lose lines.
  FILE* file = _fsopen(path.c_str(), "ab", _SH_DENYNO);
#else
  FILE* file = std::fopen(path.c_str(), "ab");
#endif
  if (file == nullptr) return;
  std::fwrite(line.data(), 1, line.size(), file);
  std::fputc('\n', file);
  std::fflush(file);
  std::fclose(file);
}

inline void emit(const std::string& line) {
  std::fwrite(line.data(), 1, line.size(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
  append_service_log(line);
}

inline void emit_error(const std::string& line) {
  std::fwrite(line.data(), 1, line.size(), stderr);
  std::fputc('\n', stderr);
  std::fflush(stderr);
  append_service_log("ERROR " + line);
}

struct Arguments {
  std::vector<std::string> positional;
  std::map<std::string, std::vector<std::string>> options;

  bool has(const std::string& key) const { return options.count(key) != 0; }

  std::string get(const std::string& key, const std::string& fallback = {}) const {
    auto found = options.find(key);
    if (found == options.end() || found->second.empty()) return fallback;
    return found->second.back();
  }

  std::vector<std::string> all(const std::string& key) const {
    auto found = options.find(key);
    if (found == options.end()) return {};
    return found->second;
  }

  long long get_int(const std::string& key, long long fallback) const {
    const std::string value = get(key);
    if (value.empty()) return fallback;
    try {
      return std::stoll(value);
    } catch (...) {
      return fallback;
    }
  }

  // Parses "--key value", "--key=value", "--flag" and positional arguments.
  static Arguments parse(int argc, char** argv, int first) {
    Arguments arguments;
    for (int i = first; i < argc; ++i) {
      const std::string token = argv[i];
      if (token.size() > 2 && token[0] == '-' && token[1] == '-') {
        const std::size_t equals = token.find('=');
        if (equals != std::string::npos) {
          arguments.options[token.substr(2, equals - 2)].push_back(token.substr(equals + 1));
          continue;
        }
        const std::string key = token.substr(2);
        if (i + 1 < argc && argv[i + 1][0] != '-') {
          arguments.options[key].push_back(argv[++i]);
        } else {
          arguments.options[key].push_back("true");
        }
      } else {
        arguments.positional.push_back(token);
      }
    }
    return arguments;
  }
};

inline bool parse_endpoint(const std::string& text, std::string& host, std::uint16_t& port) {
  const std::size_t colon = text.rfind(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 >= text.size()) return false;
  host = text.substr(0, colon);
  try {
    const long value = std::stol(text.substr(colon + 1));
    // Port zero is valid for a listener: it asks the OS for an ephemeral port,
    // which the coordinator then publishes in its readiness line.
    if (value < 0 || value > 65535) return false;
    port = static_cast<std::uint16_t>(value);
  } catch (...) {
    return false;
  }
  return true;
}

inline std::filesystem::path unique_temp_path(const std::string& prefix) {
  static std::atomic<std::uint64_t> counter{0};
  const auto now = SystemClock().now();
  const std::uint64_t id = counter.fetch_add(1) + 1;
  std::filesystem::path base;
#ifdef _WIN32
  const char* temp = std::getenv("TEMP");
  base = temp != nullptr ? std::filesystem::path(temp) : std::filesystem::path(".");
#else
  const char* temp = std::getenv("TMPDIR");
  base = temp != nullptr ? std::filesystem::path(temp) : std::filesystem::path("/tmp");
#endif
  return base / (prefix + "-" + std::to_string(now) + "-" + std::to_string(id));
}

// Reads a file into a blob whose digest is computed from its contents.
inline bool read_blob_file(const std::filesystem::path& path, Blob& out, std::uint64_t max_bytes,
                           std::string& error) {
  std::vector<std::byte> bytes;
  Status status = read_file_bounded(path, max_bytes, bytes);
  if (!status.ok()) {
    error = status.describe();
    return false;
  }
  out.bytes = std::move(bytes);
  out.digest = sha256(std::span<const std::byte>(out.bytes.data(), out.bytes.size()));
  return true;
}

inline ContentRef ref_of(const Blob& blob) {
  ContentRef ref;
  ref.digest = blob.digest;
  ref.size = blob.bytes.size();
  return ref;
}

// Selects a discovered toolchain by family name or explicit path fragment.
inline const ToolchainIdentity* pick_toolchain(const std::vector<ToolchainIdentity>& toolchains,
                                               const std::string& selector) {
  if (toolchains.empty()) return nullptr;
  if (selector.empty() || selector == "auto") {
    // Prefer a real toolchain with a known binary digest.
    for (const auto& toolchain : toolchains) {
      if (toolchain.evidence == EvidenceClass::Real && toolchain.compiler.state == BinaryIdState::Known) {
        return &toolchain;
      }
    }
    return &toolchains.front();
  }
  CompilerFamily family = CompilerFamily::Unknown;
  if (parse_compiler_family(selector, family)) {
    for (const auto& toolchain : toolchains) {
      if (toolchain.family == family) return &toolchain;
    }
  }
  for (const auto& toolchain : toolchains) {
    if (toolchain.compiler.path.find(selector) != std::string::npos) return &toolchain;
    if (toolchain.version_string == selector) return &toolchain;
    if (std::to_string(toolchain.id.value()) == selector) return &toolchain;
  }
  return nullptr;
}

// Selects a toolchain for the work actually being requested. An "auto" choice
// must never hand a C++ translation unit to a CUDA device compiler or a device
// image to a host compiler: the compiler family has to match the input form.
inline const ToolchainIdentity* pick_toolchain_for(const std::vector<ToolchainIdentity>& toolchains,
                                                   const std::string& selector, InputFormat format,
                                                   OutputKind output_kind, bool cuda_device_target) {
  if (toolchains.empty()) return nullptr;
  const bool device_work = cuda_device_target || output_kind == OutputKind::Cubin ||
                           output_kind == OutputKind::Ptx || format == InputFormat::Cubin ||
                           format == InputFormat::Ptx;
  if (!selector.empty() && selector != "auto") {
    return pick_toolchain(toolchains, selector);
  }
  const auto known = [](const ToolchainIdentity& toolchain) {
    return toolchain.evidence == EvidenceClass::Real && toolchain.compiler.state == BinaryIdState::Known;
  };
  if (device_work) {
    for (const auto& toolchain : toolchains) {
      if (toolchain.family == CompilerFamily::NvidiaNvcc && known(toolchain)) return &toolchain;
    }
    return nullptr;
  }
  const CompilerFamily preferred[] = {CompilerFamily::Msvc, CompilerFamily::Clang, CompilerFamily::Gnu};
  for (CompilerFamily family : preferred) {
    for (const auto& toolchain : toolchains) {
      if (toolchain.family == family && known(toolchain)) return &toolchain;
    }
  }
  for (const auto& toolchain : toolchains) {
    if (toolchain.family != CompilerFamily::NvidiaNvcc &&
        toolchain.family != CompilerFamily::SyntheticRocm &&
        toolchain.family != CompilerFamily::SyntheticLevelZero) {
      return &toolchain;
    }
  }
  return nullptr;
}

inline const TargetIdentity* pick_target(const std::vector<TargetIdentity>& targets,
                                         const std::string& selector) {
  if (targets.empty()) return nullptr;
  if (selector.empty()) return &targets.front();
  for (const auto& target : targets) {
    if (target.triple == selector) return &target;
  }
  for (const auto& target : targets) {
    if (!target.accelerator.architecture.empty() && target.accelerator.architecture == selector) {
      return &target;
    }
  }
  for (const auto& target : targets) {
    if (selector == std::string(to_string(target.accelerator.vendor))) return &target;
  }
  return nullptr;
}

// Directory containing the running executable, used to locate sibling
// executables such as dc_coordinator and dc_cuda_probe.
inline std::filesystem::path executable_directory() {
#ifdef _WIN32
  wchar_t buffer[32768] = {0};
  const unsigned long length = GetModuleFileNameW(nullptr, buffer, 32768);
  if (length == 0) return std::filesystem::current_path();
  return std::filesystem::path(buffer).parent_path();
#else
  return std::filesystem::current_path();
#endif
}

inline std::vector<std::string> split(const std::string& text, char separator) {
  std::vector<std::string> parts;
  std::string current;
  for (char c : text) {
    if (c == separator) {
      parts.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(c);
  }
  parts.push_back(current);
  return parts;
}

}  // namespace app
}  // namespace dc

#endif  // DC_APP_COMMON_HPP
