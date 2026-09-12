// Distributed Compilation - child process management and attempt workspaces.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/process.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

#include "dc/persistence.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace dc {
namespace {

std::uint64_t now_millis_monotonic() {
  using namespace std::chrono;
  return static_cast<std::uint64_t>(
      duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

[[maybe_unused]] std::string lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

}  // namespace

std::string ProcessResult::describe() const {
  std::string out;
  if (!started) {
    out = "process did not start";
    if (error != ErrorCode::Ok) out += std::string(": ") + std::string(to_string(error));
    if (!error_detail.empty()) out += " (" + error_detail + ")";
    return out;
  }
  out = "exit=" + std::to_string(exit_code);
  if (timed_out) out += " timed_out";
  if (killed) out += " killed";
  if (stdout_truncated) out += " stdout_truncated";
  if (stderr_truncated) out += " stderr_truncated";
  if (!stderr_text.empty()) {
    std::string trimmed = stderr_text.substr(0, std::min<std::size_t>(stderr_text.size(), 512));
    out += " stderr=" + trimmed;
  }
  return out;
}

std::string quote_windows_argument(const std::string& argument) {
  if (!argument.empty() && argument.find_first_of(" \t\n\v\"") == std::string::npos) {
    return argument;
  }
  std::string out;
  out.push_back('"');
  std::size_t backslashes = 0;
  for (char c : argument) {
    if (c == '\\') {
      ++backslashes;
      continue;
    }
    if (c == '"') {
      out.append(backslashes * 2 + 1, '\\');
      backslashes = 0;
      out.push_back('"');
      continue;
    }
    out.append(backslashes, '\\');
    backslashes = 0;
    out.push_back(c);
  }
  out.append(backslashes * 2, '\\');
  out.push_back('"');
  return out;
}

std::string build_command_line(const std::filesystem::path& executable,
                               const std::vector<std::string>& arguments) {
  std::string command = quote_windows_argument(executable.string());
  for (const auto& argument : arguments) {
    command.push_back(' ');
    command += quote_windows_argument(argument);
  }
  return command;
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------
#ifdef _WIN32
namespace {

struct HandleCloser {
  void operator()(void* handle) const {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) CloseHandle(static_cast<HANDLE>(handle));
  }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

std::string wide_to_utf8(const std::wstring& text) {
  if (text.empty()) return {};
  const int needed = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0,
                                         nullptr, nullptr);
  std::string out(static_cast<std::size_t>(needed), '\0');
  WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
  return out;
}

std::wstring utf8_to_wide(const std::string& text) {
  if (text.empty()) return {};
  const int needed = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
  std::wstring out(static_cast<std::size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), needed);
  return out;
}

struct PipeReader {
  HANDLE pipe = nullptr;
  std::thread worker;
  std::string data;
  bool truncated = false;
};

void read_pipe_bounded(PipeReader* reader, std::uint64_t max_bytes) {
  char buffer[8192];
  DWORD read = 0;
  while (ReadFile(reader->pipe, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
    if (reader->data.size() < max_bytes) {
      const std::size_t room = static_cast<std::size_t>(max_bytes - reader->data.size());
      const std::size_t take = std::min<std::size_t>(room, read);
      reader->data.append(buffer, take);
      if (take < read) reader->truncated = true;
    } else {
      // Keep draining so the child never blocks on a full pipe, but stop
      // growing memory: output is bounded by policy, not by the compiler.
      reader->truncated = true;
    }
  }
}

}  // namespace

struct ChildProcess::Impl {
  UniqueHandle process;
  UniqueHandle job;
  UniqueHandle stdout_read;
  UniqueHandle stderr_read;
  PipeReader out_reader;
  PipeReader err_reader;
  std::uint64_t started_at = 0;
  bool finished = false;
  ProcessResult result;
};

ChildProcess::ChildProcess() : impl_(std::make_unique<Impl>()) {}

ChildProcess::~ChildProcess() {
  if (impl_ && impl_->process) {
    terminate();
  }
}

Result<std::unique_ptr<ChildProcess>> ChildProcess::start(const ProcessSpec& spec) {
  if (spec.executable.empty()) {
    return Result<std::unique_ptr<ChildProcess>>(
        Status::error(ErrorCode::InvalidArgument, "process executable path is empty"));
  }
  std::error_code ec;
  if (!std::filesystem::exists(spec.executable, ec)) {
    return Result<std::unique_ptr<ChildProcess>>(
        Status::error(ErrorCode::NotFound, "process executable not found: " + spec.executable.string()));
  }

  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;

  HANDLE out_read = nullptr;
  HANDLE out_write = nullptr;
  HANDLE err_read = nullptr;
  HANDLE err_write = nullptr;
  if (CreatePipe(&out_read, &out_write, &security, 0) == 0) {
    return Result<std::unique_ptr<ChildProcess>>(
        Status::error(ErrorCode::IoError, "cannot create stdout pipe"));
  }
  if (CreatePipe(&err_read, &err_write, &security, 0) == 0) {
    CloseHandle(out_read);
    CloseHandle(out_write);
    return Result<std::unique_ptr<ChildProcess>>(
        Status::error(ErrorCode::IoError, "cannot create stderr pipe"));
  }
  SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  startup.hStdOutput = out_write;
  startup.hStdError = err_write;
  startup.hStdInput = nullptr;

  PROCESS_INFORMATION info{};
  std::string command = build_command_line(spec.executable, spec.arguments);
  std::wstring command_wide = utf8_to_wide(command);
  std::wstring cwd = spec.working_directory.empty() ? std::wstring() : spec.working_directory.wstring();

  std::vector<wchar_t> environment_block;
  LPVOID environment_pointer = nullptr;
  if (!spec.inherit_environment) {
    std::vector<std::pair<std::string, std::string>> variables = spec.environment;
    std::sort(variables.begin(), variables.end(),
              [](const auto& a, const auto& b) { return lowercase(a.first) < lowercase(b.first); });
    for (const auto& kv : variables) {
      const std::wstring entry = utf8_to_wide(kv.first + "=" + kv.second);
      environment_block.insert(environment_block.end(), entry.begin(), entry.end());
      environment_block.push_back(L'\0');
    }
    environment_block.push_back(L'\0');
    environment_pointer = environment_block.data();
  }

  const DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED;
  const BOOL created = CreateProcessW(spec.executable.wstring().c_str(), command_wide.data(), nullptr, nullptr, TRUE,
                                      flags, environment_pointer, cwd.empty() ? nullptr : cwd.c_str(), &startup,
                                      &info);
  CloseHandle(out_write);
  CloseHandle(err_write);

  if (created == 0) {
    const DWORD last_error = GetLastError();
    CloseHandle(out_read);
    CloseHandle(err_read);
    return Result<std::unique_ptr<ChildProcess>>(Status::error(
        ErrorCode::IoError, "CreateProcess failed with error " + std::to_string(last_error)));
  }

  auto handle = std::unique_ptr<ChildProcess>(new ChildProcess());
  handle->impl_->process.reset(info.hProcess);
  UniqueHandle thread_handle(info.hThread);
  handle->impl_->stdout_read.reset(out_read);
  handle->impl_->stderr_read.reset(err_read);
  handle->impl_->out_reader.pipe = out_read;
  handle->impl_->err_reader.pipe = err_read;
  handle->impl_->started_at = now_millis_monotonic();

  // A job object guarantees that no compiler grandchild survives the worker,
  // even if the worker itself is killed.
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (job != nullptr) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != 0) {
      if (AssignProcessToJobObject(job, info.hProcess) == 0) {
        // The process may already belong to a job that forbids nesting; the
        // job is then useless for cleanup, so drop it and rely on explicit
        // termination.
        CloseHandle(job);
        job = nullptr;
      }
    } else {
      CloseHandle(job);
      job = nullptr;
    }
  }
  handle->impl_->job.reset(job);

  if (ResumeThread(info.hThread) == static_cast<DWORD>(-1)) {
    TerminateProcess(info.hProcess, 1);
    return Result<std::unique_ptr<ChildProcess>>(
        Status::error(ErrorCode::IoError, "cannot resume child process"));
  }

  handle->impl_->out_reader.worker = std::thread(read_pipe_bounded, &handle->impl_->out_reader,
                                                 spec.max_output_bytes);
  handle->impl_->err_reader.worker = std::thread(read_pipe_bounded, &handle->impl_->err_reader,
                                                 spec.max_output_bytes);
  return Result<std::unique_ptr<ChildProcess>>(std::move(handle));
}

bool ChildProcess::running() const {
  if (!impl_ || !impl_->process || impl_->finished) return false;
  return WaitForSingleObject(impl_->process.get(), 0) == WAIT_TIMEOUT;
}

Status ChildProcess::terminate() {
  if (!impl_ || !impl_->process) return Status::success();
  if (impl_->finished) return Status::success();
  if (impl_->job) {
    TerminateJobObject(impl_->job.get(), 1);
  }
  TerminateProcess(impl_->process.get(), 1);
  return Status::success();
}

ProcessResult ChildProcess::wait(std::uint32_t timeout_millis) {
  ProcessResult result;
  if (!impl_ || !impl_->process) {
    result.error = ErrorCode::InvalidArgument;
    result.error_detail = "no child process";
    return result;
  }
  if (impl_->finished) return impl_->result;

  const DWORD wait_result = WaitForSingleObject(impl_->process.get(), timeout_millis);
  if (wait_result == WAIT_TIMEOUT) {
    result.timed_out = true;
    terminate();
    WaitForSingleObject(impl_->process.get(), 30000);
  } else if (wait_result == WAIT_FAILED) {
    result.error = ErrorCode::IoError;
    result.error_detail = "WaitForSingleObject failed";
  }

  DWORD exit_code = 0;
  if (GetExitCodeProcess(impl_->process.get(), &exit_code) != 0) {
    result.exit_code = static_cast<int>(exit_code);
    if (exit_code == STILL_ACTIVE) {
      result.killed = true;
      result.exit_code = -1;
    }
  }
  result.started = true;
  if (impl_->job) CloseHandle(impl_->job.release());
  if (impl_->out_reader.worker.joinable()) impl_->out_reader.worker.join();
  if (impl_->err_reader.worker.joinable()) impl_->err_reader.worker.join();
  if (impl_->stdout_read) impl_->stdout_read.reset();
  if (impl_->stderr_read) impl_->stderr_read.reset();

  result.stdout_text = std::move(impl_->out_reader.data);
  result.stderr_text = std::move(impl_->err_reader.data);
  result.stdout_truncated = impl_->out_reader.truncated;
  result.stderr_truncated = impl_->err_reader.truncated;
  result.wall_millis = now_millis_monotonic() - impl_->started_at;

  impl_->finished = true;
  impl_->result = result;
  return result;
}

#else  // POSIX

struct ChildProcess::Impl {
  int pid = -1;
  int out_fd = -1;
  int err_fd = -1;
  std::thread out_thread;
  std::thread err_thread;
  std::string out_data;
  std::string err_data;
  bool out_truncated = false;
  bool err_truncated = false;
  std::uint64_t started_at = 0;
  bool finished = false;
  ProcessResult result;
};

namespace {

void read_fd_bounded(int fd, std::string* out, bool* truncated, std::uint64_t max_bytes) {
  char buffer[8192];
  for (;;) {
    const ssize_t count = read(fd, buffer, sizeof(buffer));
    if (count <= 0) break;
    if (out->size() < max_bytes) {
      const std::size_t room = static_cast<std::size_t>(max_bytes - out->size());
      const std::size_t take = std::min<std::size_t>(room, static_cast<std::size_t>(count));
      out->append(buffer, take);
      if (take < static_cast<std::size_t>(count)) *truncated = true;
    } else {
      *truncated = true;
    }
  }
  close(fd);
}

}  // namespace

ChildProcess::ChildProcess() : impl_(std::make_unique<Impl>()) {}

ChildProcess::~ChildProcess() {
  if (impl_ && impl_->pid > 0) terminate();
}

Result<std::unique_ptr<ChildProcess>> ChildProcess::start(const ProcessSpec& spec) {
  int out_pipe[2];
  int err_pipe[2];
  if (pipe(out_pipe) != 0) {
    return Result<std::unique_ptr<ChildProcess>>(Status::error(ErrorCode::IoError, "cannot create stdout pipe"));
  }
  if (pipe(err_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    return Result<std::unique_ptr<ChildProcess>>(Status::error(ErrorCode::IoError, "cannot create stderr pipe"));
  }

  std::vector<std::string> arguments;
  arguments.push_back(spec.executable.string());
  for (const auto& argument : spec.arguments) arguments.push_back(argument);
  std::vector<char*> argv;
  for (auto& argument : arguments) argv.push_back(argument.data());
  argv.push_back(nullptr);

  const pid_t pid = fork();
  if (pid < 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    return Result<std::unique_ptr<ChildProcess>>(Status::error(ErrorCode::IoError, "fork failed"));
  }
  if (pid == 0) {
    dup2(out_pipe[1], STDOUT_FILENO);
    dup2(err_pipe[1], STDERR_FILENO);
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (!spec.working_directory.empty()) {
      if (chdir(spec.working_directory.string().c_str()) != 0) _exit(127);
    }
    setpgid(0, 0);
    if (spec.inherit_environment) {
      execv(spec.executable.string().c_str(), argv.data());
    } else {
      std::vector<std::string> entries;
      entries.reserve(spec.environment.size());
      for (const auto& kv : spec.environment) entries.push_back(kv.first + "=" + kv.second);
      std::vector<char*> envp;
      for (auto& entry : entries) envp.push_back(entry.data());
      envp.push_back(nullptr);
      execve(spec.executable.string().c_str(), argv.data(), envp.data());
    }
    _exit(127);
  }

  close(out_pipe[1]);
  close(err_pipe[1]);
  setpgid(pid, pid);

  auto handle = std::unique_ptr<ChildProcess>(new ChildProcess());
  handle->impl_->pid = pid;
  handle->impl_->out_fd = out_pipe[0];
  handle->impl_->err_fd = err_pipe[0];
  handle->impl_->started_at = now_millis_monotonic();
  handle->impl_->out_thread = std::thread(read_fd_bounded, out_pipe[0], &handle->impl_->out_data,
                                          &handle->impl_->out_truncated, spec.max_output_bytes);
  handle->impl_->err_thread = std::thread(read_fd_bounded, err_pipe[0], &handle->impl_->err_data,
                                          &handle->impl_->err_truncated, spec.max_output_bytes);
  return Result<std::unique_ptr<ChildProcess>>(std::move(handle));
}

bool ChildProcess::running() const {
  if (!impl_ || impl_->pid <= 0 || impl_->finished) return false;
  int status = 0;
  return waitpid(impl_->pid, &status, WNOHANG) == 0;
}

Status ChildProcess::terminate() {
  if (!impl_ || impl_->pid <= 0) return Status::success();
  kill(-impl_->pid, SIGKILL);
  kill(impl_->pid, SIGKILL);
  return Status::success();
}

ProcessResult ChildProcess::wait(std::uint32_t timeout_millis) {
  ProcessResult result;
  if (!impl_ || impl_->pid <= 0) {
    result.error = ErrorCode::InvalidArgument;
    result.error_detail = "no child process";
    return result;
  }
  if (impl_->finished) return impl_->result;

  const std::uint64_t deadline = now_millis_monotonic() + timeout_millis;
  int status = 0;
  for (;;) {
    const pid_t done = waitpid(impl_->pid, &status, WNOHANG);
    if (done == impl_->pid) break;
    if (done < 0) break;
    if (now_millis_monotonic() >= deadline) {
      result.timed_out = true;
      terminate();
      waitpid(impl_->pid, &status, 0);
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  result.started = true;
  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    result.killed = true;
    result.exit_code = -1;
  }
  if (impl_->out_thread.joinable()) impl_->out_thread.join();
  if (impl_->err_thread.joinable()) impl_->err_thread.join();
  result.stdout_text = std::move(impl_->out_data);
  result.stderr_text = std::move(impl_->err_data);
  result.stdout_truncated = impl_->out_truncated;
  result.stderr_truncated = impl_->err_truncated;
  result.wall_millis = now_millis_monotonic() - impl_->started_at;
  impl_->finished = true;
  impl_->result = result;
  return result;
}

#endif

ProcessResult run_process(const ProcessSpec& spec) {
  auto started = ChildProcess::start(spec);
  if (!started.ok()) {
    ProcessResult result;
    result.error = started.code();
    result.error_detail = started.detail();
    return result;
  }
  return started.value()->wait(spec.timeout_millis);
}

// ---------------------------------------------------------------------------
// Workspace
// ---------------------------------------------------------------------------
std::string sanitize_token(std::string_view token) {
  if (token.empty() || token.size() > 128) return {};
  std::string out;
  out.reserve(token.size());
  for (char c : token) {
    const bool alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    if (alnum || c == '-' || c == '_') {
      out.push_back(c);
    } else {
      return {};
    }
  }
  if (out == "." || out == "..") return {};
  return out;
}

Workspace::Workspace() = default;
Workspace::~Workspace() = default;
Workspace::Workspace(Workspace&&) noexcept = default;
Workspace& Workspace::operator=(Workspace&&) noexcept = default;

Result<Workspace> Workspace::create(const std::filesystem::path& root, std::string_view token) {
  const std::string safe = sanitize_token(token);
  if (safe.empty()) {
    return Result<Workspace>(Status::error(ErrorCode::InvalidArgument, "workspace token is not safe"));
  }
  Workspace workspace;
  workspace.root_ = root;
  workspace.path_ = root / ("attempt-" + safe);
  Status dir_status = ensure_directory(workspace.path_);
  if (!dir_status.ok()) return Result<Workspace>(dir_status);
  if (!path_is_within(workspace.path_, root)) {
    return Result<Workspace>(Status::error(ErrorCode::InvalidArgument, "workspace escaped its root"));
  }
  return Result<Workspace>(std::move(workspace));
}

Result<std::filesystem::path> Workspace::resolve(std::string_view relative) const {
  if (path_.empty()) {
    return Result<std::filesystem::path>(Status::error(ErrorCode::InvalidArgument, "workspace is not open"));
  }
  if (relative.empty()) {
    return Result<std::filesystem::path>(Status::error(ErrorCode::InvalidArgument, "empty workspace path"));
  }
  std::filesystem::path candidate(relative);
  if (candidate.is_absolute()) {
    return Result<std::filesystem::path>(
        Status::error(ErrorCode::InvalidArgument, "absolute path refused inside workspace"));
  }
  for (const auto& part : candidate) {
    if (part == "..") {
      return Result<std::filesystem::path>(
          Status::error(ErrorCode::InvalidArgument, "parent-directory component refused inside workspace"));
    }
    if (part == "." || part.empty()) continue;
  }
  std::filesystem::path resolved = path_ / candidate;
  if (!path_is_within(resolved, path_)) {
    return Result<std::filesystem::path>(
        Status::error(ErrorCode::InvalidArgument, "resolved path escapes the workspace"));
  }
  return Result<std::filesystem::path>(std::move(resolved));
}

Status Workspace::write_file(std::string_view relative, std::span<const std::byte> bytes) const {
  auto resolved = resolve(relative);
  if (!resolved.ok()) return resolved.status();
  return write_file_atomic(resolved.value(), bytes, false);
}

Status Workspace::read_file(std::string_view relative, std::uint64_t max_bytes,
                            std::vector<std::byte>& out) const {
  auto resolved = resolve(relative);
  if (!resolved.ok()) return resolved.status();
  return read_file_bounded(resolved.value(), max_bytes, out);
}

Status Workspace::cleanup() {
  if (path_.empty()) return Status::success();
  Status status = remove_tree_quiet(path_);
  path_.clear();
  return status;
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------
ValidationCheck run_smoke_test(const std::filesystem::path& executable, std::string_view expected_stdout,
                               std::uint32_t timeout_millis) {
  ValidationCheck check;
  check.check = "smoke_test";
  ProcessSpec spec;
  spec.executable = executable;
  spec.inherit_environment = true;
  spec.timeout_millis = timeout_millis;
  spec.max_output_bytes = 1u << 20;
  const ProcessResult result = run_process(spec);
  if (!result.started) {
    check.outcome = ValidationOutcome::Fail;
    check.detail = "smoke test process did not start: " + result.describe();
    return check;
  }
  if (result.timed_out) {
    check.outcome = ValidationOutcome::Fail;
    check.detail = "smoke test timed out";
    return check;
  }
  if (result.exit_code != 0) {
    check.outcome = ValidationOutcome::Fail;
    check.detail = "smoke test exited with " + std::to_string(result.exit_code) + ": " + result.describe();
    return check;
  }
  if (!expected_stdout.empty()) {
    std::string actual = result.stdout_text;
    while (!actual.empty() && (actual.back() == '\n' || actual.back() == '\r')) actual.pop_back();
    std::string expected(expected_stdout);
    while (!expected.empty() && (expected.back() == '\n' || expected.back() == '\r')) expected.pop_back();
    if (actual != expected) {
      check.outcome = ValidationOutcome::Fail;
      check.detail = "smoke test stdout mismatch";
      return check;
    }
  }
  check.outcome = ValidationOutcome::Pass;
  check.detail = "executed successfully in " + std::to_string(result.wall_millis) + " ms";
  return check;
}

}  // namespace dc
