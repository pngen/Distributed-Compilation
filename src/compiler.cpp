// Distributed Compilation - toolchain discovery and compiler adapters.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/compiler.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>

#include "dc/persistence.hpp"
#include "dc/process.hpp"

namespace dc {
namespace {

std::string get_env(const char* name) {
  const char* value = std::getenv(name);
  return value == nullptr ? std::string() : std::string(value);
}

std::string lowercase(std::string text) {
  for (char& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return text;
}

bool file_exists(const std::filesystem::path& path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(path, ec) && !ec;
}

bool dir_exists(const std::filesystem::path& path) {
  std::error_code ec;
  return std::filesystem::is_directory(path, ec) && !ec;
}

std::vector<std::filesystem::path> directories_matching(const std::filesystem::path& root,
                                                        const std::string& pattern) {
  std::vector<std::filesystem::path> found;
  std::error_code ec;
  if (!dir_exists(root)) return found;
  for (std::filesystem::directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec)) {
    if (!it->is_directory()) continue;
    const std::string name = it->path().filename().string();
    if (pattern == "*" || name.rfind(pattern, 0) == 0) found.push_back(it->path());
  }
  std::sort(found.begin(), found.end());
  return found;
}

std::string parse_token_after(const std::string& text, const std::string& marker, std::size_t start = 0) {
  const std::size_t at = text.find(marker, start);
  if (at == std::string::npos) return {};
  std::size_t begin = at + marker.size();
  while (begin < text.size() && (text[begin] == ' ' || text[begin] == ':')) ++begin;
  std::size_t end = begin;
  while (end < text.size() && text[end] != ' ' && text[end] != '\r' && text[end] != '\n' && text[end] != ',') ++end;
  return text.substr(begin, end - begin);
}

void split_version(const std::string& text, std::uint32_t& major, std::uint32_t& minor, std::uint32_t& patch) {
  major = minor = patch = 0;
  std::size_t index = 0;
  std::uint32_t* slots[3] = {&major, &minor, &patch};
  for (int slot = 0; slot < 3; ++slot) {
    std::uint64_t value = 0;
    bool any = false;
    while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
      value = value * 10 + static_cast<std::uint64_t>(text[index] - '0');
      if (value > 0xFFFFFFFFull) value = 0xFFFFFFFFull;
      ++index;
      any = true;
    }
    if (any) *slots[slot] = static_cast<std::uint32_t>(value);
    if (index < text.size() && text[index] == '.') {
      ++index;
      continue;
    }
    break;
  }
}

BinaryIdentity make_binary_identity(const std::filesystem::path& path, bool compute_digest,
                                    std::uint64_t max_bytes) {
  BinaryIdentity identity;
  identity.path = path.string();
  if (!file_exists(path)) {
    identity.state = BinaryIdState::Unavailable;
    return identity;
  }
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  if (!ec) identity.size = static_cast<std::uint64_t>(size);
  if (!compute_digest || identity.size > max_bytes) {
    // The digest is deliberately left UNKNOWN rather than approximated.
    identity.state = BinaryIdState::Unknown;
    return identity;
  }
  std::vector<std::byte> bytes;
  Status read = read_file_bounded(path, max_bytes, bytes);
  if (!read.ok()) {
    identity.state = BinaryIdState::Unknown;
    return identity;
  }
  identity.digest = sha256(std::span<const std::byte>(bytes.data(), bytes.size()));
  identity.state = BinaryIdState::Known;
  return identity;
}

struct ProcessOutput {
  bool started = false;
  int exit_code = -1;
  std::string output;
};

ProcessOutput capture(const std::filesystem::path& executable, const std::vector<std::string>& arguments,
                      std::uint32_t timeout_millis) {
  ProcessSpec spec;
  spec.executable = executable;
  spec.arguments = arguments;
  spec.inherit_environment = true;
  spec.timeout_millis = timeout_millis;
  spec.max_output_bytes = 64u * 1024u;
  const ProcessResult result = run_process(spec);
  ProcessOutput output;
  output.started = result.started;
  output.exit_code = result.exit_code;
  output.output = result.stdout_text + result.stderr_text;
  return output;
}

std::string join_paths(const std::vector<std::string>& entries) {
  std::string joined;
  for (const auto& entry : entries) {
    if (entry.empty()) continue;
    if (!joined.empty()) joined.push_back(';');
    joined += entry;
  }
  return joined;
}

// ---------------------------------------------------------------------------
// MSVC discovery
// ---------------------------------------------------------------------------
struct MsvcInstallation {
  std::filesystem::path host_bin;
  std::filesystem::path msvc_root;
  std::string toolset_version;
  std::filesystem::path sdk_include;
  std::filesystem::path sdk_lib;
  std::string sdk_version;
};

std::vector<MsvcInstallation> find_msvc_installations(const DiscoveryOptions& options) {
  std::vector<MsvcInstallation> found;
  for (const auto& root : options.msvc_roots) {
    for (const auto& edition : directories_matching(root, "*")) {
      const auto tools_root = edition / "VC" / "Tools" / "MSVC";
      for (const auto& toolset : directories_matching(tools_root, "*")) {
        const auto host_bin = toolset / "bin" / "Hostx64" / "x64";
        if (!file_exists(host_bin / "cl.exe")) continue;
        MsvcInstallation installation;
        installation.host_bin = host_bin;
        installation.msvc_root = toolset;
        installation.toolset_version = toolset.filename().string();
        found.push_back(std::move(installation));
      }
    }
  }

  // Windows SDK: pick the newest version that has both Include and Lib.
  const std::vector<std::filesystem::path> kit_roots = {
      std::filesystem::path("C:/Program Files (x86)/Windows Kits/10"),
      std::filesystem::path("C:/Program Files/Windows Kits/10"),
  };
  for (const auto& kits : kit_roots) {
    for (const auto& version_dir : directories_matching(kits / "Include", "*")) {
      const std::string version = version_dir.filename().string();
      const auto lib_dir = kits / "Lib" / version;
      if (!dir_exists(lib_dir)) continue;
      if (!dir_exists(version_dir / "ucrt") || !dir_exists(lib_dir / "ucrt")) continue;
      for (auto& installation : found) {
        if (installation.sdk_version.empty() || version > installation.sdk_version) {
          installation.sdk_include = version_dir;
          installation.sdk_lib = lib_dir;
          installation.sdk_version = version;
        }
      }
    }
  }
  std::sort(found.begin(), found.end(), [](const MsvcInstallation& a, const MsvcInstallation& b) {
    if (a.host_bin != b.host_bin) return a.host_bin.string() < b.host_bin.string();
    return a.toolset_version < b.toolset_version;
  });
  return found;
}

ToolchainIdentity make_msvc_toolchain(const MsvcInstallation& installation, const DiscoveryOptions& options) {
  ToolchainIdentity toolchain;
  toolchain.family = CompilerFamily::Msvc;
  toolchain.compiler = make_binary_identity(installation.host_bin / "cl.exe", options.compute_binary_digests,
                                            options.max_digest_bytes);
  toolchain.linker = make_binary_identity(installation.host_bin / "link.exe", options.compute_binary_digests,
                                          options.max_digest_bytes);
  toolchain.assembler = make_binary_identity(installation.host_bin / "ml64.exe", options.compute_binary_digests,
                                             options.max_digest_bytes);
  toolchain.runtime_library = make_binary_identity(installation.msvc_root / "lib" / "x64" / "msvcprt.lib",
                                                   false, options.max_digest_bytes);
  toolchain.evidence = toolchain.compiler.state == BinaryIdState::Known ? EvidenceClass::Real
                                                                       : EvidenceClass::Unknown;

  const ProcessOutput version = capture(installation.host_bin / "cl.exe", {}, options.discovery_timeout_millis);
  std::string version_string = parse_token_after(version.output, "Version");
  if (version_string.empty()) version_string = installation.toolset_version;
  toolchain.version_string = version_string;
  split_version(version_string, toolchain.version_major, toolchain.version_minor, toolchain.version_patch);
  toolchain.compiler.version_string = version_string;

  if (!installation.sdk_version.empty()) {
    SdkComponent sdk;
    sdk.name = "windows-sdk";
    sdk.version = installation.sdk_version;
    sdk.root = installation.sdk_include.parent_path().string();
    toolchain.sdk.push_back(sdk);
  }
  {
    SdkComponent toolset;
    toolset.name = "msvc-toolset";
    toolset.version = installation.toolset_version;
    toolset.root = installation.msvc_root.string();
    toolchain.sdk.push_back(toolset);
  }

  std::vector<std::string> include_dirs;
  include_dirs.push_back((installation.msvc_root / "include").string());
  if (!installation.sdk_version.empty()) {
    include_dirs.push_back((installation.sdk_include / "ucrt").string());
    include_dirs.push_back((installation.sdk_include / "um").string());
    include_dirs.push_back((installation.sdk_include / "shared").string());
    include_dirs.push_back((installation.sdk_include / "winrt").string());
    include_dirs.push_back((installation.sdk_include / "cppwinrt").string());
  }
  std::vector<std::string> lib_dirs;
  lib_dirs.push_back((installation.msvc_root / "lib" / "x64").string());
  if (!installation.sdk_version.empty()) {
    lib_dirs.push_back((installation.sdk_lib / "ucrt" / "x64").string());
    lib_dirs.push_back((installation.sdk_lib / "um" / "x64").string());
  }

  toolchain.configuration.push_back({"HOST_BIN", installation.host_bin.string()});
  toolchain.configuration.push_back({"INCLUDE", join_paths(include_dirs)});
  toolchain.configuration.push_back({"LIB", join_paths(lib_dirs)});
  toolchain.configuration.push_back({"TOOLSET_ROOT", installation.msvc_root.string()});
  toolchain.target_libraries.push_back("msvcprt");
  toolchain.target_libraries.push_back("libcmt");
  toolchain.target_libraries.push_back("kernel32");
  canonicalize(toolchain);
  return toolchain;
}

std::vector<TargetIdentity> msvc_targets() {
  TargetIdentity target;
  target.os = OsKind::Windows;
  target.arch = ArchKind::X86_64;
  target.abi = AbiKind::Msvc;
  target.triple = "x86_64-pc-windows-msvc";
  target.object_format = ObjectFormat::Coff;
  target.stdlib = StdlibKind::MsvcStl;
  target.runtime_abi = "msvc-14.4";
  target.accelerator.vendor = AcceleratorVendor::None;
  target.evidence = EvidenceClass::Real;
  target.identity_digest = compute_target_identity(target);
  target.id = derive_target_id(target);
  return {target};
}

// ---------------------------------------------------------------------------
// CUDA discovery
// ---------------------------------------------------------------------------
ToolchainIdentity make_cuda_toolchain(const std::filesystem::path& toolkit_root, const MsvcInstallation* host,
                                      const DiscoveryOptions& options) {
  ToolchainIdentity toolchain;
  toolchain.family = CompilerFamily::NvidiaNvcc;
  const auto nvcc = toolkit_root / "bin" / "nvcc.exe";
  toolchain.compiler = make_binary_identity(nvcc, options.compute_binary_digests, options.max_digest_bytes);
  toolchain.evidence = toolchain.compiler.state == BinaryIdState::Known ? EvidenceClass::Real
                                                                       : EvidenceClass::Unknown;
  const ProcessOutput version = capture(nvcc, {"--version"}, options.discovery_timeout_millis);
  std::string release = parse_token_after(version.output, "release");
  if (release.empty()) release = toolkit_root.filename().string();
  toolchain.version_string = release;
  split_version(release, toolchain.version_major, toolchain.version_minor, toolchain.version_patch);
  toolchain.compiler.version_string = release;

  SdkComponent toolkit;
  toolkit.name = "cuda-toolkit";
  toolkit.version = release;
  toolkit.root = toolkit_root.string();
  toolchain.sdk.push_back(toolkit);
  if (host != nullptr) {
    SdkComponent host_component;
    host_component.name = "msvc-toolset";
    host_component.version = host->toolset_version;
    host_component.root = host->msvc_root.string();
    toolchain.sdk.push_back(host_component);
    toolchain.configuration.push_back({"HOST_BIN", host->host_bin.string()});
    std::vector<std::string> include_dirs;
    include_dirs.push_back((host->msvc_root / "include").string());
    if (!host->sdk_version.empty()) {
      include_dirs.push_back((host->sdk_include / "ucrt").string());
      include_dirs.push_back((host->sdk_include / "um").string());
      include_dirs.push_back((host->sdk_include / "shared").string());
    }
    std::vector<std::string> lib_dirs;
    lib_dirs.push_back((host->msvc_root / "lib" / "x64").string());
    if (!host->sdk_version.empty()) {
      lib_dirs.push_back((host->sdk_lib / "ucrt" / "x64").string());
      lib_dirs.push_back((host->sdk_lib / "um" / "x64").string());
    }
    toolchain.configuration.push_back({"HOST_INCLUDE", join_paths(include_dirs)});
    toolchain.configuration.push_back({"HOST_LIB", join_paths(lib_dirs)});
  }
  toolchain.configuration.push_back({"CUDA_ROOT", toolkit_root.string()});
  toolchain.configuration.push_back({"CUDA_BIN", (toolkit_root / "bin").string()});
  canonicalize(toolchain);
  return toolchain;
}

TargetIdentity make_cuda_target(const std::string& architecture, const std::string& toolkit_version,
                                std::uint32_t compute_major, std::uint32_t compute_minor) {
  TargetIdentity target;
  target.os = OsKind::Windows;
  target.arch = ArchKind::X86_64;
  target.abi = AbiKind::Msvc;
  target.triple = "x86_64-pc-windows-msvc";
  target.object_format = ObjectFormat::Cubin;
  target.stdlib = StdlibKind::None;
  target.runtime_abi = "cuda-driver";
  target.accelerator.vendor = AcceleratorVendor::Nvidia;
  target.accelerator.architecture = architecture;
  target.accelerator.compute_major = compute_major;
  target.accelerator.compute_minor = compute_minor;
  target.accelerator.isa = architecture;
  target.accelerator.device_runtime = "cuda-" + toolkit_version;
  target.evidence = EvidenceClass::Real;
  target.identity_digest = compute_target_identity(target);
  target.id = derive_target_id(target);
  return target;
}

// ---------------------------------------------------------------------------
// Synthetic profiles
// ---------------------------------------------------------------------------
std::vector<ToolchainIdentity> make_synthetic_toolchains(const DiscoveryOptions& options) {
  struct Profile {
    std::string name;
    CompilerFamily family;
    std::string version;
    std::string sdk;
  };
  static const Profile kProfiles[] = {
      {"rocm", CompilerFamily::SyntheticRocm, "6.2.0", "rocm-6.2"},
      {"level-zero", CompilerFamily::SyntheticLevelZero, "1.10.0", "level-zero-1.10"},
      {"alt-triple", CompilerFamily::SyntheticGeneric, "1.0.0", "synthetic-sdk-1"},
  };

  std::vector<ToolchainIdentity> toolchains;
  for (const auto& profile : kProfiles) {
    bool requested = options.synthetic_profiles.empty();
    for (const auto& wanted : options.synthetic_profiles) {
      if (wanted == profile.name) requested = true;
    }
    if (!requested) continue;
    ToolchainIdentity toolchain;
    toolchain.family = profile.family;
    toolchain.version_string = profile.version;
    split_version(profile.version, toolchain.version_major, toolchain.version_minor, toolchain.version_patch);
    toolchain.compiler.state = BinaryIdState::Unknown;
    toolchain.compiler.path = "synthetic://" + profile.name + "/compiler";
    toolchain.compiler.version_string = profile.version;
    toolchain.evidence = EvidenceClass::Synthetic;
    SdkComponent sdk;
    sdk.name = profile.sdk;
    sdk.version = profile.version;
    sdk.root = "synthetic://" + profile.name;
    toolchain.sdk.push_back(sdk);
    toolchain.configuration.push_back({"SYNTHETIC_PROFILE", profile.name});
    canonicalize(toolchain);
    toolchains.push_back(std::move(toolchain));
  }
  return toolchains;
}

std::vector<TargetIdentity> make_synthetic_targets() {
  std::vector<TargetIdentity> targets;
  {
    TargetIdentity target;
    target.os = OsKind::Linux;
    target.arch = ArchKind::X86_64;
    target.abi = AbiKind::Gnu;
    target.triple = "x86_64-unknown-linux-gnu";
    target.object_format = ObjectFormat::Elf;
    target.stdlib = StdlibKind::Libstdcxx;
    target.runtime_abi = "gnu";
    target.accelerator.vendor = AcceleratorVendor::Amd;
    target.accelerator.architecture = "gfx942";
    target.accelerator.isa = "sramecc+xnack-";
    target.accelerator.device_runtime = "rocm-6.2";
    target.evidence = EvidenceClass::Synthetic;
    target.identity_digest = compute_target_identity(target);
    target.id = derive_target_id(target);
    targets.push_back(target);
  }
  {
    TargetIdentity target;
    target.os = OsKind::Linux;
    target.arch = ArchKind::X86_64;
    target.abi = AbiKind::Gnu;
    target.triple = "x86_64-unknown-linux-gnu";
    target.object_format = ObjectFormat::Elf;
    target.stdlib = StdlibKind::Libstdcxx;
    target.runtime_abi = "gnu";
    target.accelerator.vendor = AcceleratorVendor::Intel;
    target.accelerator.architecture = "xe-hpc";
    target.accelerator.device_runtime = "level-zero-1.10";
    target.evidence = EvidenceClass::Synthetic;
    target.identity_digest = compute_target_identity(target);
    target.id = derive_target_id(target);
    targets.push_back(target);
  }
  {
    TargetIdentity target;
    target.os = OsKind::Linux;
    target.arch = ArchKind::Aarch64;
    target.abi = AbiKind::Gnu;
    target.triple = "aarch64-unknown-linux-gnu";
    target.object_format = ObjectFormat::Elf;
    target.stdlib = StdlibKind::Libstdcxx;
    target.runtime_abi = "gnu";
    target.accelerator.vendor = AcceleratorVendor::None;
    target.evidence = EvidenceClass::Synthetic;
    target.identity_digest = compute_target_identity(target);
    target.id = derive_target_id(target);
    targets.push_back(target);
  }
  return targets;
}

}  // namespace

std::vector<std::filesystem::path> default_msvc_roots() {
  std::vector<std::filesystem::path> roots;
  const std::string program_files = get_env("ProgramFiles");
  const std::string program_files_x86 = get_env("ProgramFiles(x86)");
  if (!program_files.empty()) {
    roots.push_back(std::filesystem::path(program_files) / "Microsoft Visual Studio" / "2022");
  }
  if (!program_files_x86.empty()) {
    roots.push_back(std::filesystem::path(program_files_x86) / "Microsoft Visual Studio" / "2022");
  }
  return roots;
}

std::vector<std::filesystem::path> default_cuda_roots() {
  std::vector<std::filesystem::path> roots;
  const std::string program_files = get_env("ProgramFiles");
  const std::string cuda_path = get_env("CUDA_PATH");
  if (!cuda_path.empty()) roots.push_back(std::filesystem::path(cuda_path));
  if (!program_files.empty()) {
    const auto base = std::filesystem::path(program_files) / "NVIDIA GPU Computing Toolkit" / "CUDA";
    for (const auto& candidate : directories_matching(base, "v")) roots.push_back(candidate);
  }
  std::sort(roots.begin(), roots.end());
  roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
  return roots;
}

DiscoveryResult discover_toolchains(const DiscoveryOptions& options) {
  DiscoveryResult result;
  const std::vector<MsvcInstallation> msvc = find_msvc_installations(options);
  for (const auto& installation : msvc) {
    ToolchainIdentity toolchain = make_msvc_toolchain(installation, options);
    result.notes.push_back("MSVC toolchain " + toolchain.version_string + " at " +
                           installation.host_bin.string() + " digest " +
                           std::string(to_string(toolchain.compiler.state)));
    result.toolchains.push_back(std::move(toolchain));
  }
  if (!msvc.empty()) {
    for (auto& target : msvc_targets()) result.targets.push_back(std::move(target));
  }

  const MsvcInstallation* host = msvc.empty() ? nullptr : &msvc.front();
  std::vector<std::filesystem::path> cuda_roots = options.cuda_roots;
  if (cuda_roots.empty()) cuda_roots = default_cuda_roots();
  for (const auto& toolkit_root : cuda_roots) {
    if (!file_exists(toolkit_root / "bin" / "nvcc.exe")) continue;
    ToolchainIdentity toolchain = make_cuda_toolchain(toolkit_root, host, options);
    result.notes.push_back("CUDA toolchain " + toolchain.version_string + " at " + toolkit_root.string());
    result.toolchains.push_back(std::move(toolchain));
  }
  if (!cuda_roots.empty()) {
    for (const auto& architecture : options.cuda_architectures) {
      std::uint32_t major = 0;
      std::uint32_t minor = 0;
      const std::size_t underscore = architecture.find('_');
      if (underscore != std::string::npos) {
        split_version(architecture.substr(underscore + 1), major, minor, minor);
      }
      for (const auto& toolchain : result.toolchains) {
        if (toolchain.family != CompilerFamily::NvidiaNvcc) continue;
        result.targets.push_back(
            make_cuda_target(architecture, toolchain.version_string, major, minor));
      }
    }
  }

  if (options.include_synthetic) {
    for (auto& toolchain : make_synthetic_toolchains(options)) {
      result.notes.push_back("SYNTHETIC toolchain profile " + toolchain.compiler.path);
      result.toolchains.push_back(std::move(toolchain));
    }
    for (auto& target : make_synthetic_targets()) result.targets.push_back(std::move(target));
  }

  std::sort(result.toolchains.begin(), result.toolchains.end(),
            [](const ToolchainIdentity& a, const ToolchainIdentity& b) {
              if (a.identity_digest != b.identity_digest) return a.identity_digest < b.identity_digest;
              return a.id < b.id;
            });
  std::sort(result.targets.begin(), result.targets.end(),
            [](const TargetIdentity& a, const TargetIdentity& b) {
              return a.identity_digest < b.identity_digest;
            });
  return result;
}

// ---------------------------------------------------------------------------
// Environment construction
// ---------------------------------------------------------------------------
std::vector<std::pair<std::string, std::string>> build_compile_environment(
    const ToolchainIdentity& toolchain, const std::filesystem::path& workspace) {
  std::map<std::string, std::string> values;
  const auto find = [&toolchain](const std::string& key) -> std::string {
    for (const auto& kv : toolchain.configuration) {
      if (kv.first == key) return kv.second;
    }
    return {};
  };

  values["TMP"] = workspace.string();
  values["TEMP"] = workspace.string();
  values["SOURCE_DATE_EPOCH"] = "315532800";   // 1980-01-01, the ZIP epoch
  values["PATH"] = get_env("PATH");
  values["SystemRoot"] = get_env("SystemRoot");

  const std::string host_bin = find("HOST_BIN");
  std::string path = host_bin;
  const std::string cuda_bin = find("CUDA_BIN");
  if (!cuda_bin.empty()) path = cuda_bin + (path.empty() ? "" : ";" + path);
  const std::string system_path = get_env("PATH");
  if (!system_path.empty()) path += (path.empty() ? "" : ";") + system_path;
  values["PATH"] = path;

  const std::string include_dirs = find("INCLUDE");
  if (!include_dirs.empty()) values["INCLUDE"] = include_dirs;
  const std::string lib_dirs = find("LIB");
  if (!lib_dirs.empty()) values["LIB"] = lib_dirs;
  const std::string host_include = find("HOST_INCLUDE");
  if (!host_include.empty()) values["INCLUDE"] = host_include;
  const std::string host_lib = find("HOST_LIB");
  if (!host_lib.empty()) values["LIB"] = host_lib;
  values["CUDA_PATH"] = find("CUDA_ROOT");
  values["VSLANG"] = "1033";

  std::vector<std::pair<std::string, std::string>> out;
  out.reserve(values.size());
  for (auto& kv : values) {
    if (kv.second.empty()) continue;
    out.push_back(kv);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Real MSVC adapter
// ---------------------------------------------------------------------------
namespace {

class MsvcAdapter final : public CompilerAdapter {
 public:
  CompilerFamily family() const override { return CompilerFamily::Msvc; }
  const char* name() const override { return "msvc"; }
  bool real() const override { return true; }

  Result<CompileRunResult> run(const Assignment& assignment, const ToolchainIdentity& toolchain,
                               const std::filesystem::path& scratch_root,
                               const std::atomic<bool>* cancel_flag) const override {
    CompileRunResult result;
    if (toolchain.compiler.state != BinaryIdState::Known) {
      result.code = ErrorCode::Unknown;
      result.detail = "toolchain binary identity is UNKNOWN; refusing to invoke an unproven compiler";
      return Result<CompileRunResult>(result);
    }
    std::string host_bin;
    for (const auto& kv : toolchain.configuration) {
      if (kv.first == "HOST_BIN") host_bin = kv.second;
    }
    if (host_bin.empty()) {
      result.code = ErrorCode::Unknown;
      result.detail = "toolchain configuration has no HOST_BIN";
      return Result<CompileRunResult>(result);
    }

    const std::string token = std::to_string(assignment.attempt.value());
    auto workspace_result = Workspace::create(scratch_root, "a" + token);
    if (!workspace_result.ok()) {
      result.code = workspace_result.code();
      result.detail = workspace_result.detail();
      return Result<CompileRunResult>(result);
    }
    Workspace workspace = std::move(workspace_result.value());

    std::vector<std::string> written_inputs;
    for (const auto& source : assignment.sources) {
      const std::string name = sanitize_input_name(source.logical_name);
      Status written = workspace.write_file(name, std::span<const std::byte>(source.bytes.data(),
                                                                            source.bytes.size()));
      if (!written.ok()) {
        result.code = written.code();
        result.detail = written.detail();
        (void)workspace.cleanup();
        return Result<CompileRunResult>(result);
      }
      written_inputs.push_back(name);
    }
    std::vector<std::string> include_dirs;
    for (const auto& dep : assignment.dependencies) {
      const std::string name = sanitize_input_name(dep.name);
      Status written = workspace.write_file(name, std::span<const std::byte>(dep.bytes.data(), dep.bytes.size()));
      if (!written.ok()) {
        result.code = written.code();
        result.detail = written.detail();
        (void)workspace.cleanup();
        return Result<CompileRunResult>(result);
      }
      const std::string parent = std::filesystem::path(name).parent_path().string();
      if (!parent.empty() && std::find(include_dirs.begin(), include_dirs.end(), parent) == include_dirs.end()) {
        include_dirs.push_back(parent);
      }
      written_inputs.push_back(name);
    }
    std::vector<std::string> child_names;
    for (std::size_t i = 0; i < assignment.children.size(); ++i) {
      const auto& child = assignment.children[i];
      const std::string name = sanitize_input_name(child.logical_name) + "-" + std::to_string(i) + ".obj";
      Status written = workspace.write_file(name, std::span<const std::byte>(child.bytes.data(),
                                                                            child.bytes.size()));
      if (!written.ok()) {
        result.code = written.code();
        result.detail = written.detail();
        (void)workspace.cleanup();
        return Result<CompileRunResult>(result);
      }
      child_names.push_back(name);
    }

    std::vector<std::string> arguments;
    std::filesystem::path executable;
    std::string output_name;
    if (assignment.kind == UnitKind::Link) {
      executable = std::filesystem::path(host_bin) / "link.exe";
      arguments.push_back("/nologo");
      arguments.push_back("/Brepro");
      arguments.push_back("/INCREMENTAL:NO");
      output_name = "artifact.exe";
      arguments.push_back("/OUT:" + output_name);
      arguments.push_back("/SUBSYSTEM:CONSOLE");
      for (const auto& name : child_names) arguments.push_back(name);
      for (const auto& fl : assignment.flags) arguments.push_back(fl);
    } else {
      executable = std::filesystem::path(host_bin) / "cl.exe";
      arguments.push_back("/nologo");
      arguments.push_back("/c");
      arguments.push_back("/Brepro");
      arguments.push_back("/Z7");
      arguments.push_back("/EHsc");
      arguments.push_back("/permissive-");
      arguments.push_back("/std:c++20");
      arguments.push_back("/D_CRT_SECURE_NO_WARNINGS");
      for (const auto& dir : include_dirs) arguments.push_back("/I" + dir);
      switch (assignment.output_kind) {
        case OutputKind::PreprocessedSource:
          output_name = "artifact.i";
          arguments.push_back("/P");
          arguments.push_back("/Fi" + output_name);
          break;
        case OutputKind::Assembly:
          output_name = "artifact.asm";
          arguments.push_back("/Fa" + output_name);
          break;
        default:
          output_name = "artifact.obj";
          arguments.push_back("/Fo" + output_name);
          break;
      }
      for (const auto& fl : assignment.flags) arguments.push_back(fl);
      for (const auto& name : written_inputs) {
        if (name.size() > 4 && name.compare(name.size() - 4, 4, ".cpp") == 0) arguments.push_back(name);
      }
      if (assignment.sources.empty()) {
        result.code = ErrorCode::InvalidArgument;
        result.detail = "compile unit has no sources";
        (void)workspace.cleanup();
        return Result<CompileRunResult>(result);
      }
      bool has_translation_unit = false;
      for (const auto& name : written_inputs) {
        if (name.size() > 4 && (name.compare(name.size() - 4, 4, ".cpp") == 0 ||
                                name.compare(name.size() - 2, 2, ".c") == 0)) {
          has_translation_unit = true;
        }
      }
      if (!has_translation_unit) {
        arguments.push_back(written_inputs.front());
      }
    }

    ProcessSpec spec;
    spec.executable = executable;
    spec.arguments = arguments;
    spec.working_directory = workspace.path();
    spec.environment = build_compile_environment(toolchain, workspace.path());
    spec.inherit_environment = false;
    spec.timeout_millis = static_cast<std::uint32_t>(std::min<std::uint64_t>(assignment.max_compile_millis, 3600000));
    spec.max_output_bytes = 512u * 1024u;
    spec.cancel_flag = cancel_flag;
    const ProcessResult process = run_process(spec);

    result.exit_code = process.exit_code;
    result.stdout_text = process.stdout_text;
    result.stderr_text = process.stderr_text;
    result.wall_millis = process.wall_millis;
    result.invocation = build_command_line(executable, arguments);
    result.compiler_version = toolchain.version_string;

    if (!process.started) {
      result.code = process.error == ErrorCode::Ok ? ErrorCode::IoError : process.error;
      result.detail = "compiler process did not start: " + process.describe();
      (void)workspace.cleanup();
      return Result<CompileRunResult>(result);
    }
    if (process.timed_out) {
      result.code = ErrorCode::Timeout;
      result.detail = "compiler exceeded the assigned time budget";
      (void)workspace.cleanup();
      return Result<CompileRunResult>(result);
    }
    if (process.exit_code != 0) {
      result.code = ErrorCode::ValidationFailure;
      // The compiler's own diagnosis is the only useful root cause here, so it
      // is carried into the failure detail (bounded) rather than discarded.
      std::string diagnosis = process.stderr_text.empty() ? process.stdout_text : process.stderr_text;
      if (diagnosis.size() > 1024) diagnosis.resize(1024);
      for (char& c : diagnosis) {
        if (c == '\r' || c == '\n') c = ' ';
      }
      result.detail = "compiler exited with " + std::to_string(process.exit_code) + ": " + diagnosis;
      (void)workspace.cleanup();
      return Result<CompileRunResult>(result);
    }

    std::vector<std::byte> artifact;
    Status read = workspace.read_file(output_name, 512ull * 1024 * 1024, artifact);
    if (!read.ok()) {
      result.code = ErrorCode::ArtifactMissing;
      result.detail = "compiler reported success but produced no artifact: " + read.detail();
      (void)workspace.cleanup();
      return Result<CompileRunResult>(result);
    }
    result.artifact = std::move(artifact);
    result.ok = true;
    (void)workspace.cleanup();
    return Result<CompileRunResult>(result);
  }

 private:
  static std::string sanitize_input_name(const std::string& logical_name) {
    std::string cleaned;
    cleaned.reserve(logical_name.size());
    for (char c : logical_name) {
      if (c == '\\') {
        cleaned.push_back('/');
        continue;
      }
      cleaned.push_back(c);
    }
    while (!cleaned.empty() && (cleaned.front() == '/' || cleaned.front() == '.')) cleaned.erase(cleaned.begin());
    if (cleaned.empty()) cleaned = "input";
    return cleaned;
  }
};

class SyntheticAdapter final : public CompilerAdapter {
 public:
  CompilerFamily family() const override { return CompilerFamily::SyntheticGeneric; }
  const char* name() const override { return "synthetic"; }
  bool real() const override { return false; }

  Result<CompileRunResult> run(const Assignment& assignment, const ToolchainIdentity& toolchain,
                               const std::filesystem::path& scratch_root,
                               const std::atomic<bool>* cancel_flag) const override {
    (void)scratch_root;
    (void)cancel_flag;
    CompileRunResult result;
    CanonicalWriter w;
    w.domain("dc.synthetic-artifact.v1");
    w.str("SYNTHETIC ARTIFACT - NOT A COMPILATION RESULT");
    w.str(std::string(to_string(toolchain.family)));
    w.str(toolchain.version_string);
    w.str(assignment.logical_name);
    w.u8(static_cast<std::uint8_t>(assignment.kind));
    w.u8(static_cast<std::uint8_t>(assignment.output_kind));
    w.digest(assignment.claim.unit_identity);
    w.digest(assignment.claim.request_identity);
    w.u32(static_cast<std::uint32_t>(assignment.sources.size()));
    for (const auto& source : assignment.sources) {
      w.str(source.logical_name);
      w.u64(source.bytes.size());
      w.digest(sha256(std::span<const std::byte>(source.bytes.data(), source.bytes.size())));
    }
    w.u32(static_cast<std::uint32_t>(assignment.dependencies.size()));
    for (const auto& dep : assignment.dependencies) {
      w.str(dep.name);
      w.u64(dep.bytes.size());
      w.digest(sha256(std::span<const std::byte>(dep.bytes.data(), dep.bytes.size())));
    }
    const std::string body = "// SYNTHETIC ARTIFACT generated by Distributed Compilation synthetic adapter\n"
                             "// evidence=SYNTHETIC toolchain=" +
                             std::string(to_string(toolchain.family)) + " version=" + toolchain.version_string +
                             " unit=" + assignment.claim.unit_identity.hex() + "\n" +
                             "// payload-digest=" + w.hash().hex() + "\n";
    result.artifact.assign(reinterpret_cast<const std::byte*>(body.data()),
                           reinterpret_cast<const std::byte*>(body.data()) + body.size());
    result.ok = true;
    result.invocation = "synthetic-adapter(" + std::string(to_string(toolchain.family)) + ")";
    result.compiler_version = toolchain.version_string;
    result.exit_code = 0;
    return Result<CompileRunResult>(result);
  }
};

class NvccAdapter final : public CompilerAdapter {
 public:
  CompilerFamily family() const override { return CompilerFamily::NvidiaNvcc; }
  const char* name() const override { return "nvcc"; }
  bool real() const override { return true; }

  Result<CompileRunResult> run(const Assignment& assignment, const ToolchainIdentity& toolchain,
                               const std::filesystem::path& scratch_root,
                               const std::atomic<bool>* cancel_flag) const override {
    CompileRunResult result;
    if (toolchain.compiler.state != BinaryIdState::Known) {
      result.code = ErrorCode::Unknown;
      result.detail = "CUDA toolchain binary identity is UNKNOWN; refusing to invoke an unproven compiler";
      return Result<CompileRunResult>(result);
    }
    std::string cuda_bin;
    for (const auto& kv : toolchain.configuration) {
      if (kv.first == "CUDA_BIN") cuda_bin = kv.second;
    }
    if (cuda_bin.empty()) {
      result.code = ErrorCode::Unknown;
      result.detail = "CUDA toolchain configuration has no CUDA_BIN";
      return Result<CompileRunResult>(result);
    }

    auto workspace_result = Workspace::create(scratch_root, "c" + std::to_string(assignment.attempt.value()));
    if (!workspace_result.ok()) {
      result.code = workspace_result.code();
      result.detail = workspace_result.detail();
      return Result<CompileRunResult>(result);
    }
    Workspace workspace = std::move(workspace_result.value());

    std::vector<std::string> names;
    for (const auto& source : assignment.sources) {
      std::string name = source.logical_name;
      while (!name.empty() && (name.front() == '/' || name.front() == '.')) name.erase(name.begin());
      if (name.empty()) name = "kernel.cu";
      Status written = workspace.write_file(name, std::span<const std::byte>(source.bytes.data(),
                                                                            source.bytes.size()));
      if (!written.ok()) {
        result.code = written.code();
        result.detail = written.detail();
        (void)workspace.cleanup();
        return Result<CompileRunResult>(result);
      }
      names.push_back(name);
    }

    const std::string architecture_unused = "";
    (void)architecture_unused;
    const std::string architecture = assignment.target.accelerator.architecture.empty()
                                         ? "sm_" + std::to_string(assignment.target.accelerator.compute_major) +
                                               std::to_string(assignment.target.accelerator.compute_minor)
                                         : assignment.target.accelerator.architecture;
    const std::filesystem::path nvcc = std::filesystem::path(cuda_bin) / "nvcc.exe";
    std::string output_name;
    std::vector<std::string> arguments;
    switch (assignment.output_kind) {
      case OutputKind::Cubin:
        arguments.push_back("--cubin");
        output_name = "artifact.cubin";
        break;
      case OutputKind::Ptx:
        arguments.push_back("--ptx");
        output_name = "artifact.ptx";
        break;
      case OutputKind::Object:
        arguments.push_back("-c");
        output_name = "artifact.obj";
        break;
      case OutputKind::Executable:
        output_name = "artifact.exe";
        break;
      default:
        result.code = ErrorCode::Unsupported;
        result.detail = "the CUDA adapter does not produce " +
                        std::string(to_string(assignment.output_kind)) + " output";
        (void)workspace.cleanup();
        return Result<CompileRunResult>(result);
    }
    arguments.push_back("-arch=" + architecture);
    arguments.push_back("-o");
    arguments.push_back(output_name);
    for (const auto& fl : assignment.flags) arguments.push_back(fl);
    for (const auto& name : names) arguments.push_back(name);

    ProcessSpec spec;
    spec.executable = nvcc;
    spec.arguments = arguments;
    spec.working_directory = workspace.path();
    spec.environment = build_compile_environment(toolchain, workspace.path());
    spec.inherit_environment = false;
    spec.timeout_millis = static_cast<std::uint32_t>(std::min<std::uint64_t>(assignment.max_compile_millis, 3600000));
    spec.max_output_bytes = 512u * 1024u;
    spec.cancel_flag = cancel_flag;
    const ProcessResult process = run_process(spec);

    result.exit_code = process.exit_code;
    result.stdout_text = process.stdout_text;
    result.stderr_text = process.stderr_text;
    result.wall_millis = process.wall_millis;
    result.invocation = build_command_line(nvcc, arguments);
    result.compiler_version = toolchain.version_string;
    if (!process.started || process.exit_code != 0) {
      result.code = process.started ? ErrorCode::ValidationFailure : process.error;
      std::string diagnosis = process.stderr_text.empty() ? process.stdout_text : process.stderr_text;
      if (diagnosis.size() > 1024) diagnosis.resize(1024);
      for (char& c : diagnosis) {
        if (c == '\r' || c == '\n') c = ' ';
      }
      result.detail = "nvcc exited with " + std::to_string(process.exit_code) + ": " + diagnosis;
      (void)workspace.cleanup();
      return Result<CompileRunResult>(result);
    }
    std::vector<std::byte> artifact;
    Status read = workspace.read_file(output_name, 512ull * 1024 * 1024, artifact);
    if (!read.ok()) {
      result.code = ErrorCode::ArtifactMissing;
      result.detail = "nvcc reported success but produced no artifact";
      (void)workspace.cleanup();
      return Result<CompileRunResult>(result);
    }
    result.artifact = std::move(artifact);
    result.ok = true;
    (void)workspace.cleanup();
    return Result<CompileRunResult>(result);
  }
};

MsvcAdapter& msvc_adapter() {
  static MsvcAdapter adapter;
  return adapter;
}
NvccAdapter& nvcc_adapter() {
  static NvccAdapter adapter;
  return adapter;
}
SyntheticAdapter& synthetic_adapter() {
  static SyntheticAdapter adapter;
  return adapter;
}

}  // namespace

const CompilerAdapter* select_adapter(CompilerFamily family) {
  switch (family) {
    case CompilerFamily::Msvc: return &msvc_adapter();
    case CompilerFamily::NvidiaNvcc: return &nvcc_adapter();
    case CompilerFamily::SyntheticRocm:
    case CompilerFamily::SyntheticLevelZero:
    case CompilerFamily::SyntheticGeneric: return &synthetic_adapter();
    default: return nullptr;
  }
}

Result<CompileRunResult> run_compile_unit(const Assignment& assignment, const ToolchainIdentity& toolchain,
                                          const std::filesystem::path& scratch_root,
                                          const std::atomic<bool>* cancel_flag) {
  const CompilerAdapter* adapter = select_adapter(toolchain.family);
  if (adapter == nullptr) {
    CompileRunResult result;
    result.code = ErrorCode::Unsupported;
    result.detail = std::string("no compiler adapter for family ") + std::string(to_string(toolchain.family));
    return Result<CompileRunResult>(result);
  }
  if (adapter->family() != toolchain.family && toolchain.family != CompilerFamily::SyntheticRocm &&
      toolchain.family != CompilerFamily::SyntheticLevelZero) {
    return Result<CompileRunResult>(
        Status::error(ErrorCode::InvalidArgument, "adapter/toolchain family mismatch"));
  }
  Result<CompileRunResult> outcome = adapter->run(assignment, toolchain, scratch_root, cancel_flag);
  // An adapter reports its own outcome in CompileRunResult::ok as well as in the
  // returned Status. A run that did not produce an artifact must never surface
  // as a success, so the two are reconciled here in one place.
  if (outcome.ok() && !outcome.value().ok) {
    const ErrorCode code = outcome.value().code == ErrorCode::Ok ? ErrorCode::Internal : outcome.value().code;
    return Result<CompileRunResult>(Status::error(code, outcome.value().detail));
  }
  if (outcome.ok() && outcome.value().artifact.empty()) {
    return Result<CompileRunResult>(
        Status::error(ErrorCode::ArtifactMissing, "adapter reported success but produced no artifact bytes"));
  }
  return outcome;
}

}  // namespace dc
