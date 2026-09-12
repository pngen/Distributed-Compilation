// Distributed Compilation - toolchain discovery and compiler adapters.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// The core is vendor-neutral: everything compiler-specific lives behind the
// narrow CompilerAdapter interface. Real adapters invoke real compiler
// executables through structured process creation. Synthetic adapters produce
// clearly labelled synthetic artifacts and are never presented as compilation.
#ifndef DC_COMPILER_HPP
#define DC_COMPILER_HPP

#include <atomic>
#include <filesystem>
#include <string>
#include <vector>

#include "dc/coordinator.hpp"
#include "dc/model.hpp"
#include "dc/types.hpp"

namespace dc {

struct DiscoveryOptions {
  std::vector<std::filesystem::path> msvc_roots;
  std::vector<std::filesystem::path> cuda_roots;
  bool include_synthetic = false;
  std::vector<std::string> synthetic_profiles;      // "rocm", "level-zero", "alt-triple"
  std::vector<std::string> cuda_architectures;      // e.g. {"sm_120"}
  bool compute_binary_digests = true;
  std::uint64_t max_digest_bytes = 512ull * 1024 * 1024;
  std::uint32_t discovery_timeout_millis = 20000;
};

struct DiscoveryResult {
  std::vector<ToolchainIdentity> toolchains;
  std::vector<TargetIdentity> targets;
  std::vector<std::string> notes;
};

// Scans the host for compilers. Every returned identity states how it was
// established; a compiler whose binary digest could not be read is returned
// with BinaryIdState::Unknown rather than a fabricated digest.
DiscoveryResult discover_toolchains(const DiscoveryOptions& options);

// Standard install roots for this platform, in deterministic order.
std::vector<std::filesystem::path> default_msvc_roots();
std::vector<std::filesystem::path> default_cuda_roots();

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------
struct CompileRunResult {
  bool ok = false;
  ErrorCode code = ErrorCode::Ok;
  std::string detail;
  std::vector<std::byte> artifact;
  std::string invocation;
  std::string compiler_version;
  std::uint64_t wall_millis = 0;
  int exit_code = -1;
  std::string stdout_text;
  std::string stderr_text;
  ValidationReport worker_validation;
};

class CompilerAdapter {
 public:
  virtual ~CompilerAdapter() = default;
  virtual CompilerFamily family() const = 0;
  virtual const char* name() const = 0;
  // True when this adapter performs real compilation with a real toolchain.
  virtual bool real() const = 0;
  virtual Result<CompileRunResult> run(const Assignment& assignment, const ToolchainIdentity& toolchain,
                                       const std::filesystem::path& scratch_root,
                                       const std::atomic<bool>* cancel_flag) const = 0;
};

const CompilerAdapter* select_adapter(CompilerFamily family);

// Executes one assigned unit on this worker. This is the only place a compiler
// child process is created.
Result<CompileRunResult> run_compile_unit(const Assignment& assignment, const ToolchainIdentity& toolchain,
                                          const std::filesystem::path& scratch_root,
                                          const std::atomic<bool>* cancel_flag = nullptr);

// Deterministic environment for a compile child process, built from the
// toolchain's recorded configuration rather than the worker's ambient
// environment.
std::vector<std::pair<std::string, std::string>> build_compile_environment(
    const ToolchainIdentity& toolchain, const std::filesystem::path& workspace);

}  // namespace dc

#endif  // DC_COMPILER_HPP
