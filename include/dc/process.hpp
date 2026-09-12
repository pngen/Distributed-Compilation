// Distributed Compilation - child process management and attempt workspaces.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Compiler invocation never goes through a shell. Arguments are passed as an
// array to the platform process API, so a hostile flag cannot become a command.
#ifndef DC_PROCESS_HPP
#define DC_PROCESS_HPP

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "dc/types.hpp"

namespace dc {

struct ProcessSpec {
  std::filesystem::path executable;
  std::vector<std::string> arguments;
  std::filesystem::path working_directory;
  // When inherit_environment is false the child receives exactly these
  // variables (plus a minimal required set), which is what makes a compile
  // environment reproducible.
  std::vector<std::pair<std::string, std::string>> environment;
  bool inherit_environment = false;
  std::uint64_t max_output_bytes = 1ull << 20;
  std::uint32_t timeout_millis = 600000;
  // When set, the child tree is terminated as soon as the flag becomes true.
  // This is how a cancelled compile actually stops compiling.
  const std::atomic<bool>* cancel_flag = nullptr;
};

struct ProcessResult {
  bool started = false;
  bool timed_out = false;
  bool killed = false;
  int exit_code = -1;
  std::uint64_t wall_millis = 0;
  std::string stdout_text;
  std::string stderr_text;
  bool stdout_truncated = false;
  bool stderr_truncated = false;
  ErrorCode error = ErrorCode::Ok;
  std::string error_detail;

  bool succeeded() const { return started && !timed_out && !killed && exit_code == 0; }
  std::string describe() const;
};

// Quotes a single argument using the documented MSVC/CRT rules. Exposed for
// tests: a quoting bug here would be a command-injection bug.
std::string quote_windows_argument(const std::string& argument);
std::string build_command_line(const std::filesystem::path& executable,
                               const std::vector<std::string>& arguments);

class ChildProcess {
 public:
  ChildProcess();
  ~ChildProcess();

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  static Result<std::unique_ptr<ChildProcess>> start(const ProcessSpec& spec);

  bool running() const;
  // Terminates the whole child tree (job object on Windows, process group on
  // POSIX) so that no compiler grandchild is orphaned.
  Status terminate();
  ProcessResult wait(std::uint32_t timeout_millis);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

ProcessResult run_process(const ProcessSpec& spec);

// ---------------------------------------------------------------------------
// Attempt workspace
// ---------------------------------------------------------------------------
// Every compile attempt gets its own directory. Paths are validated: a
// relative path that escapes the workspace, an absolute path, or a name with a
// parent-directory component is refused.
class Workspace {
 public:
  Workspace();
  ~Workspace();

  Workspace(const Workspace&) = delete;
  Workspace& operator=(const Workspace&) = delete;
  Workspace(Workspace&&) noexcept;
  Workspace& operator=(Workspace&&) noexcept;

  static Result<Workspace> create(const std::filesystem::path& root, std::string_view token);

  const std::filesystem::path& path() const noexcept { return path_; }
  bool valid() const noexcept { return !path_.empty(); }

  // Resolves a workspace-relative path, refusing traversal and absolute paths.
  Result<std::filesystem::path> resolve(std::string_view relative) const;
  Status write_file(std::string_view relative, std::span<const std::byte> bytes) const;
  Status read_file(std::string_view relative, std::uint64_t max_bytes, std::vector<std::byte>& out) const;
  Status cleanup();

 private:
  std::filesystem::path path_;
  std::filesystem::path root_;
};

// Sanitizes an opaque token into a safe single path component. Returns an empty
// string when the token cannot be made safe, which the caller must treat as a
// refusal rather than substituting a default.
std::string sanitize_token(std::string_view token);

}  // namespace dc

#endif  // DC_PROCESS_HPP
