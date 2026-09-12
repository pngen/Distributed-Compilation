// Distributed Compilation - domain model canonicalization and identity derivation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/model.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace dc {

// Derives a 64-bit handle from the leading bytes of a digest. Handles are never
// used for content comparison, only as registry keys and record identifiers.
std::uint64_t handle_from_digest64(const Digest256& digest) noexcept {
  std::uint64_t raw = 0;
  std::memcpy(&raw, digest.data(), sizeof(raw));
  return raw;
}

namespace {

inline std::uint64_t handle_from_digest(const Digest256& digest) { return handle_from_digest64(digest); }

std::string trim(std::string_view text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && std::isspace(static_cast<unsigned char>(text[begin])) != 0) ++begin;
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) --end;
  return std::string(text.substr(begin, end - begin));
}

bool contains_control(std::string_view text) {
  for (char c : text) {
    const auto value = static_cast<unsigned char>(c);
    if (value < 0x20 && value != '\t') return true;
    if (value == 0x7F) return true;
  }
  return false;
}

bool compare_sdk(const SdkComponent& a, const SdkComponent& b) { return a.name < b.name; }
bool compare_plugin(const PluginIdentity& a, const PluginIdentity& b) { return a.id < b.id; }
bool compare_config(const std::pair<std::string, std::string>& a, const std::pair<std::string, std::string>& b) {
  return a.first < b.first;
}

void write_binary_identity(CanonicalWriter& w, const BinaryIdentity& binary) {
  w.u8(static_cast<std::uint8_t>(binary.state));
  w.digest(binary.digest);
  w.u64(binary.size);
  w.str(binary.version_string);
  // The path is identity-bearing only when no digest could be established: an
  // identical binary reached through two paths is one toolchain, but two
  // unknown binaries at one path are not provably the same thing.
  if (binary.state != BinaryIdState::Known) {
    w.present(true);
    w.str(binary.path);
  } else {
    w.present(false);
  }
}

void write_spec_field(CanonicalWriter& w, const SpecField& field) {
  w.str(field.name);
  w.u8(static_cast<std::uint8_t>(field.kind));
  switch (field.kind) {
    case SpecValueKind::Signed: w.i64(field.signed_value); break;
    case SpecValueKind::Unsigned: w.u64(field.unsigned_value); break;
    case SpecValueKind::Floating: w.f64(field.floating_value); break;
    case SpecValueKind::Text: w.str(field.text_value); break;
    case SpecValueKind::Boolean: w.boolean(field.boolean_value); break;
  }
}

void write_dependency_entry(CanonicalWriter& w, const DependencyEntry& entry) {
  w.str(entry.name);
  w.u8(static_cast<std::uint8_t>(entry.kind));
  write_content_ref(w, entry.content);
}

void write_accelerator(CanonicalWriter& w, const AcceleratorTarget& accel) {
  w.u8(static_cast<std::uint8_t>(accel.vendor));
  w.str(accel.architecture);
  w.u32(accel.compute_major);
  w.u32(accel.compute_minor);
  w.str(accel.isa);
  w.str(accel.device_runtime);
}

bool compare_dependency(const DependencyEntry& a, const DependencyEntry& b) {
  if (a.kind != b.kind) return static_cast<int>(a.kind) < static_cast<int>(b.kind);
  if (a.name != b.name) return a.name < b.name;
  if (a.content.digest != b.content.digest) return a.content.digest < b.content.digest;
  return a.content.size < b.content.size;
}

bool compare_source(const UnitSource& a, const UnitSource& b) { return a.logical_name < b.logical_name; }

}  // namespace

// ---------------------------------------------------------------------------
// Enum rendering
// ---------------------------------------------------------------------------
std::string_view to_string(EvidenceClass value) noexcept {
  switch (value) {
    case EvidenceClass::Unknown: return "UNKNOWN";
    case EvidenceClass::Real: return "REAL";
    case EvidenceClass::Synthetic: return "SYNTHETIC";
    case EvidenceClass::Unsupported: return "UNSUPPORTED";
  }
  return "UNKNOWN";
}

bool parse_evidence_class(std::string_view text, EvidenceClass& out) noexcept {
  if (text == "UNKNOWN" || text == "unknown") { out = EvidenceClass::Unknown; return true; }
  if (text == "REAL" || text == "real") { out = EvidenceClass::Real; return true; }
  if (text == "SYNTHETIC" || text == "synthetic") { out = EvidenceClass::Synthetic; return true; }
  if (text == "UNSUPPORTED" || text == "unsupported") { out = EvidenceClass::Unsupported; return true; }
  return false;
}

std::string_view to_string(InputFormat value) noexcept {
  switch (value) {
    case InputFormat::Unknown: return "UNKNOWN";
    case InputFormat::Source: return "SOURCE";
    case InputFormat::PreprocessedSource: return "PREPROCESSED_SOURCE";
    case InputFormat::LlvmIr: return "LLVM_IR";
    case InputFormat::Ptx: return "PTX";
    case InputFormat::SpirV: return "SPIRV";
    case InputFormat::VendorIr: return "VENDOR_IR";
    case InputFormat::Object: return "OBJECT";
    case InputFormat::Cubin: return "CUBIN";
    case InputFormat::Assembly: return "ASSEMBLY";
    case InputFormat::Other: return "OTHER";
  }
  return "UNKNOWN";
}

bool parse_input_format(std::string_view text, InputFormat& out) noexcept {
  struct Entry { std::string_view name; InputFormat value; };
  static const Entry kEntries[] = {
      {"SOURCE", InputFormat::Source},
      {"PREPROCESSED_SOURCE", InputFormat::PreprocessedSource},
      {"LLVM_IR", InputFormat::LlvmIr},
      {"PTX", InputFormat::Ptx},
      {"SPIRV", InputFormat::SpirV},
      {"VENDOR_IR", InputFormat::VendorIr},
      {"OBJECT", InputFormat::Object},
      {"CUBIN", InputFormat::Cubin},
      {"ASSEMBLY", InputFormat::Assembly},
      {"OTHER", InputFormat::Other},
      {"UNKNOWN", InputFormat::Unknown},
  };
  for (const auto& entry : kEntries) {
    if (text == entry.name) { out = entry.value; return true; }
  }
  return false;
}

InputFormat input_format_from_extension(std::string_view name) noexcept {
  const auto dot = name.find_last_of('.');
  if (dot == std::string_view::npos) return InputFormat::Unknown;
  std::string ext(name.substr(dot));
  for (char& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (ext == ".cpp" || ext == ".cc" || ext == ".cxx" || ext == ".c") return InputFormat::Source;
  if (ext == ".cu") return InputFormat::Source;
  if (ext == ".i" || ext == ".ii") return InputFormat::PreprocessedSource;
  if (ext == ".ll") return InputFormat::LlvmIr;
  if (ext == ".bc") return InputFormat::LlvmIr;
  if (ext == ".ptx") return InputFormat::Ptx;
  if (ext == ".spv") return InputFormat::SpirV;
  if (ext == ".o" || ext == ".obj") return InputFormat::Object;
  if (ext == ".cubin") return InputFormat::Cubin;
  if (ext == ".s" || ext == ".asm") return InputFormat::Assembly;
  return InputFormat::Unknown;
}

std::string_view to_string(DependencyKind value) noexcept {
  switch (value) {
    case DependencyKind::Header: return "HEADER";
    case DependencyKind::Module: return "MODULE";
    case DependencyKind::GeneratedCode: return "GENERATED_CODE";
    case DependencyKind::Library: return "LIBRARY";
    case DependencyKind::DeviceLibrary: return "DEVICE_LIBRARY";
    case DependencyKind::RuntimeLibrary: return "RUNTIME_LIBRARY";
    case DependencyKind::CompilerPlugin: return "COMPILER_PLUGIN";
    case DependencyKind::Configuration: return "CONFIGURATION";
    case DependencyKind::ModelMetadata: return "MODEL_METADATA";
    case DependencyKind::ToolchainFile: return "TOOLCHAIN_FILE";
    case DependencyKind::Other: return "OTHER";
  }
  return "OTHER";
}

bool parse_dependency_kind(std::string_view text, DependencyKind& out) noexcept {
  struct Entry { std::string_view name; DependencyKind value; };
  static const Entry kEntries[] = {
      {"HEADER", DependencyKind::Header},
      {"MODULE", DependencyKind::Module},
      {"GENERATED_CODE", DependencyKind::GeneratedCode},
      {"LIBRARY", DependencyKind::Library},
      {"DEVICE_LIBRARY", DependencyKind::DeviceLibrary},
      {"RUNTIME_LIBRARY", DependencyKind::RuntimeLibrary},
      {"COMPILER_PLUGIN", DependencyKind::CompilerPlugin},
      {"CONFIGURATION", DependencyKind::Configuration},
      {"MODEL_METADATA", DependencyKind::ModelMetadata},
      {"TOOLCHAIN_FILE", DependencyKind::ToolchainFile},
      {"OTHER", DependencyKind::Other},
  };
  for (const auto& entry : kEntries) {
    if (text == entry.name) { out = entry.value; return true; }
  }
  return false;
}

std::string_view to_string(OsKind value) noexcept {
  switch (value) {
    case OsKind::Unknown: return "UNKNOWN";
    case OsKind::Windows: return "WINDOWS";
    case OsKind::Linux: return "LINUX";
    case OsKind::MacOs: return "MACOS";
    case OsKind::Bsd: return "BSD";
    case OsKind::BareMetal: return "BAREMETAL";
  }
  return "UNKNOWN";
}

std::string_view to_string(ArchKind value) noexcept {
  switch (value) {
    case ArchKind::Unknown: return "UNKNOWN";
    case ArchKind::X86_64: return "X86_64";
    case ArchKind::Aarch64: return "AARCH64";
    case ArchKind::X86: return "X86";
    case ArchKind::Arm32: return "ARM32";
    case ArchKind::RiscV64: return "RISCV64";
  }
  return "UNKNOWN";
}

std::string_view to_string(AbiKind value) noexcept {
  switch (value) {
    case AbiKind::Unknown: return "UNKNOWN";
    case AbiKind::Msvc: return "MSVC";
    case AbiKind::Itanium: return "ITANIUM";
    case AbiKind::Gnu: return "GNU";
  }
  return "UNKNOWN";
}

std::string_view to_string(ObjectFormat value) noexcept {
  switch (value) {
    case ObjectFormat::Unknown: return "UNKNOWN";
    case ObjectFormat::Coff: return "COFF";
    case ObjectFormat::Elf: return "ELF";
    case ObjectFormat::MachO: return "MACHO";
    case ObjectFormat::Ptx: return "PTX";
    case ObjectFormat::Cubin: return "CUBIN";
    case ObjectFormat::Fatbin: return "FATBIN";
  }
  return "UNKNOWN";
}

std::string_view to_string(AcceleratorVendor value) noexcept {
  switch (value) {
    case AcceleratorVendor::None: return "NONE";
    case AcceleratorVendor::Nvidia: return "NVIDIA";
    case AcceleratorVendor::Amd: return "AMD";
    case AcceleratorVendor::Intel: return "INTEL";
    case AcceleratorVendor::Unknown: return "UNKNOWN";
  }
  return "UNKNOWN";
}

std::string_view to_string(StdlibKind value) noexcept {
  switch (value) {
    case StdlibKind::Unknown: return "UNKNOWN";
    case StdlibKind::MsvcStl: return "MSVC_STL";
    case StdlibKind::Libstdcxx: return "LIBSTDCXX";
    case StdlibKind::Libcxx: return "LIBCXX";
    case StdlibKind::None: return "NONE";
  }
  return "UNKNOWN";
}

bool parse_os_kind(std::string_view text, OsKind& out) noexcept {
  if (text == "WINDOWS") { out = OsKind::Windows; return true; }
  if (text == "LINUX") { out = OsKind::Linux; return true; }
  if (text == "MACOS") { out = OsKind::MacOs; return true; }
  if (text == "BSD") { out = OsKind::Bsd; return true; }
  if (text == "BAREMETAL") { out = OsKind::BareMetal; return true; }
  return false;
}

bool parse_arch_kind(std::string_view text, ArchKind& out) noexcept {
  if (text == "X86_64" || text == "X64" || text == "AMD64") { out = ArchKind::X86_64; return true; }
  if (text == "AARCH64" || text == "ARM64") { out = ArchKind::Aarch64; return true; }
  if (text == "X86" || text == "I386") { out = ArchKind::X86; return true; }
  if (text == "ARM32") { out = ArchKind::Arm32; return true; }
  if (text == "RISCV64") { out = ArchKind::RiscV64; return true; }
  return false;
}

bool parse_object_format(std::string_view text, ObjectFormat& out) noexcept {
  if (text == "COFF") { out = ObjectFormat::Coff; return true; }
  if (text == "ELF") { out = ObjectFormat::Elf; return true; }
  if (text == "MACHO") { out = ObjectFormat::MachO; return true; }
  if (text == "PTX") { out = ObjectFormat::Ptx; return true; }
  if (text == "CUBIN") { out = ObjectFormat::Cubin; return true; }
  if (text == "FATBIN") { out = ObjectFormat::Fatbin; return true; }
  return false;
}

bool parse_accelerator_vendor(std::string_view text, AcceleratorVendor& out) noexcept {
  if (text == "NONE") { out = AcceleratorVendor::None; return true; }
  if (text == "NVIDIA") { out = AcceleratorVendor::Nvidia; return true; }
  if (text == "AMD") { out = AcceleratorVendor::Amd; return true; }
  if (text == "INTEL") { out = AcceleratorVendor::Intel; return true; }
  return false;
}

bool parse_stdlib_kind(std::string_view text, StdlibKind& out) noexcept {
  if (text == "MSVC_STL") { out = StdlibKind::MsvcStl; return true; }
  if (text == "LIBSTDCXX") { out = StdlibKind::Libstdcxx; return true; }
  if (text == "LIBCXX") { out = StdlibKind::Libcxx; return true; }
  if (text == "NONE") { out = StdlibKind::None; return true; }
  return false;
}

std::string_view to_string(CompilerFamily value) noexcept {
  switch (value) {
    case CompilerFamily::Unknown: return "UNKNOWN";
    case CompilerFamily::Msvc: return "MSVC";
    case CompilerFamily::Clang: return "CLANG";
    case CompilerFamily::Gnu: return "GNU";
    case CompilerFamily::NvidiaNvcc: return "NVIDIA_NVCC";
    case CompilerFamily::SyntheticRocm: return "SYNTHETIC_ROCM";
    case CompilerFamily::SyntheticLevelZero: return "SYNTHETIC_LEVEL_ZERO";
    case CompilerFamily::SyntheticGeneric: return "SYNTHETIC_GENERIC";
    case CompilerFamily::MsvcLinker: return "MSVC_LINKER";
  }
  return "UNKNOWN";
}

bool parse_compiler_family(std::string_view text, CompilerFamily& out) noexcept {
  struct Entry { std::string_view name; CompilerFamily value; };
  static const Entry kEntries[] = {
      {"MSVC", CompilerFamily::Msvc},
      {"CLANG", CompilerFamily::Clang},
      {"GNU", CompilerFamily::Gnu},
      {"NVIDIA_NVCC", CompilerFamily::NvidiaNvcc},
      {"SYNTHETIC_ROCM", CompilerFamily::SyntheticRocm},
      {"SYNTHETIC_LEVEL_ZERO", CompilerFamily::SyntheticLevelZero},
      {"SYNTHETIC_GENERIC", CompilerFamily::SyntheticGeneric},
      {"MSVC_LINKER", CompilerFamily::MsvcLinker},
  };
  for (const auto& entry : kEntries) {
    if (text == entry.name) { out = entry.value; return true; }
  }
  return false;
}

std::string_view to_string(BinaryIdState value) noexcept {
  switch (value) {
    case BinaryIdState::Unknown: return "UNKNOWN";
    case BinaryIdState::Known: return "KNOWN";
    case BinaryIdState::Unavailable: return "UNAVAILABLE";
  }
  return "UNKNOWN";
}

std::string_view to_string(SpecValueKind value) noexcept {
  switch (value) {
    case SpecValueKind::Signed: return "SIGNED";
    case SpecValueKind::Unsigned: return "UNSIGNED";
    case SpecValueKind::Floating: return "FLOATING";
    case SpecValueKind::Text: return "TEXT";
    case SpecValueKind::Boolean: return "BOOLEAN";
  }
  return "SIGNED";
}

std::string_view to_string(ReproducibilityRequirement value) noexcept {
  switch (value) {
    case ReproducibilityRequirement::Required: return "REQUIRED";
    case ReproducibilityRequirement::Preferred: return "PREFERRED";
    case ReproducibilityRequirement::NotRequired: return "NOT_REQUIRED";
  }
  return "PREFERRED";
}

std::string_view to_string(CachePolicy value) noexcept {
  switch (value) {
    case CachePolicy::ReadWrite: return "READ_WRITE";
    case CachePolicy::ReadOnly: return "READ_ONLY";
    case CachePolicy::Bypass: return "BYPASS";
  }
  return "READ_WRITE";
}

std::string_view to_string(OutputKind value) noexcept {
  switch (value) {
    case OutputKind::Executable: return "EXECUTABLE";
    case OutputKind::Object: return "OBJECT";
    case OutputKind::StaticLibrary: return "STATIC_LIBRARY";
    case OutputKind::DynamicLibrary: return "DYNAMIC_LIBRARY";
    case OutputKind::Cubin: return "CUBIN";
    case OutputKind::Ptx: return "PTX";
    case OutputKind::Assembly: return "ASSEMBLY";
    case OutputKind::PreprocessedSource: return "PREPROCESSED_SOURCE";
  }
  return "OBJECT";
}

bool parse_reproducibility(std::string_view text, ReproducibilityRequirement& out) noexcept {
  if (text == "REQUIRED") { out = ReproducibilityRequirement::Required; return true; }
  if (text == "PREFERRED") { out = ReproducibilityRequirement::Preferred; return true; }
  if (text == "NOT_REQUIRED") { out = ReproducibilityRequirement::NotRequired; return true; }
  return false;
}

bool parse_cache_policy(std::string_view text, CachePolicy& out) noexcept {
  if (text == "READ_WRITE") { out = CachePolicy::ReadWrite; return true; }
  if (text == "READ_ONLY") { out = CachePolicy::ReadOnly; return true; }
  if (text == "BYPASS") { out = CachePolicy::Bypass; return true; }
  return false;
}

bool parse_output_kind(std::string_view text, OutputKind& out) noexcept {
  if (text == "EXECUTABLE") { out = OutputKind::Executable; return true; }
  if (text == "OBJECT") { out = OutputKind::Object; return true; }
  if (text == "STATIC_LIBRARY") { out = OutputKind::StaticLibrary; return true; }
  if (text == "DYNAMIC_LIBRARY") { out = OutputKind::DynamicLibrary; return true; }
  if (text == "CUBIN") { out = OutputKind::Cubin; return true; }
  if (text == "PTX") { out = OutputKind::Ptx; return true; }
  if (text == "ASSEMBLY") { out = OutputKind::Assembly; return true; }
  if (text == "PREPROCESSED_SOURCE") { out = OutputKind::PreprocessedSource; return true; }
  return false;
}

std::string_view to_string(UnitKind value) noexcept {
  switch (value) {
    case UnitKind::Compile: return "COMPILE";
    case UnitKind::Link: return "LINK";
  }
  return "COMPILE";
}

std::string_view to_string(ValidationOutcome value) noexcept {
  switch (value) {
    case ValidationOutcome::Pass: return "PASS";
    case ValidationOutcome::Fail: return "FAIL";
    case ValidationOutcome::Unknown: return "UNKNOWN";
  }
  return "UNKNOWN";
}

std::string_view to_string(CacheOutcome value) noexcept {
  switch (value) {
    case CacheOutcome::Reusable: return "REUSABLE";
    case CacheOutcome::Stale: return "STALE";
    case CacheOutcome::Incompatible: return "INCOMPATIBLE";
    case CacheOutcome::Corrupt: return "CORRUPT";
    case CacheOutcome::Unknown: return "UNKNOWN";
    case CacheOutcome::Miss: return "MISS";
  }
  return "UNKNOWN";
}

ErrorCode cache_outcome_error(CacheOutcome outcome) noexcept {
  switch (outcome) {
    case CacheOutcome::Reusable: return ErrorCode::Ok;
    case CacheOutcome::Stale: return ErrorCode::CacheStale;
    case CacheOutcome::Incompatible: return ErrorCode::CacheIncompatible;
    case CacheOutcome::Corrupt: return ErrorCode::CacheCorrupt;
    case CacheOutcome::Unknown: return ErrorCode::CacheUnknown;
    case CacheOutcome::Miss: return ErrorCode::CacheMiss;
  }
  return ErrorCode::Unknown;
}

std::string_view to_string(NegativeCacheReason value) noexcept {
  switch (value) {
    case NegativeCacheReason::UnsupportedTarget: return "UNSUPPORTED_TARGET";
    case NegativeCacheReason::DeterministicCompilerRejection: return "DETERMINISTIC_COMPILER_REJECTION";
    case NegativeCacheReason::IncompatibleSourceToolchain: return "INCOMPATIBLE_SOURCE_TOOLCHAIN";
    case NegativeCacheReason::PolicyRefusal: return "POLICY_REFUSAL";
  }
  return "UNKNOWN";
}

std::string_view to_string(IntermediateKind value) noexcept {
  switch (value) {
    case IntermediateKind::PreprocessedSource: return "PREPROCESSED_SOURCE";
    case IntermediateKind::GeneratedIr: return "GENERATED_IR";
    case IntermediateKind::OptimizedIr: return "OPTIMIZED_IR";
    case IntermediateKind::DeviceCode: return "DEVICE_CODE";
    case IntermediateKind::ObjectFile: return "OBJECT_FILE";
    case IntermediateKind::LinkInput: return "LINK_INPUT";
    case IntermediateKind::Metadata: return "METADATA";
  }
  return "METADATA";
}

// ---------------------------------------------------------------------------
// Content references
// ---------------------------------------------------------------------------
void write_content_ref(CanonicalWriter& w, const ContentRef& ref) {
  w.digest(ref.digest);
  w.u64(ref.size);
}

bool read_content_ref(CanonicalReader& r, ContentRef& out) {
  ContentRef ref;
  if (!r.read_digest(ref.digest)) return false;
  if (!r.read_u64(ref.size)) return false;
  out = ref;
  return true;
}

// ---------------------------------------------------------------------------
// SpecField
// ---------------------------------------------------------------------------
SpecField SpecField::make_signed(std::string name, std::int64_t value) {
  SpecField f;
  f.name = std::move(name);
  f.kind = SpecValueKind::Signed;
  f.signed_value = value;
  return f;
}

SpecField SpecField::make_unsigned(std::string name, std::uint64_t value) {
  SpecField f;
  f.name = std::move(name);
  f.kind = SpecValueKind::Unsigned;
  f.unsigned_value = value;
  return f;
}

SpecField SpecField::make_floating(std::string name, double value) {
  SpecField f;
  f.name = std::move(name);
  f.kind = SpecValueKind::Floating;
  f.floating_value = value;
  return f;
}

SpecField SpecField::make_text(std::string name, std::string value) {
  SpecField f;
  f.name = std::move(name);
  f.kind = SpecValueKind::Text;
  f.text_value = std::move(value);
  return f;
}

SpecField SpecField::make_boolean(std::string name, bool value) {
  SpecField f;
  f.name = std::move(name);
  f.kind = SpecValueKind::Boolean;
  f.boolean_value = value;
  return f;
}

std::string SpecField::render() const {
  switch (kind) {
    case SpecValueKind::Signed: return std::to_string(signed_value);
    case SpecValueKind::Unsigned: return std::to_string(unsigned_value);
    case SpecValueKind::Floating: {
      char buffer[64];
      std::snprintf(buffer, sizeof(buffer), "%.17g", floating_value);
      return std::string(buffer);
    }
    case SpecValueKind::Text: return text_value;
    case SpecValueKind::Boolean: return boolean_value ? "true" : "false";
  }
  return {};
}

Status canonicalize(SpecializationSpec& spec) {
  std::sort(spec.fields.begin(), spec.fields.end(),
            [](const SpecField& a, const SpecField& b) { return a.name < b.name; });
  for (std::size_t i = 1; i < spec.fields.size(); ++i) {
    if (spec.fields[i].name == spec.fields[i - 1].name) {
      return Status::error(ErrorCode::Duplicate, "duplicate specialization field: " + spec.fields[i].name);
    }
  }
  for (auto& field : spec.fields) {
    field.name = trim(field.name);
    if (field.name.empty()) {
      return Status::error(ErrorCode::InvalidArgument, "empty specialization field name");
    }
    if (contains_control(field.name)) {
      return Status::error(ErrorCode::InvalidArgument, "control character in specialization field name");
    }
  }
  spec.identity_digest = compute_specialization_identity(spec);
  return Status::success();
}

void canonicalize(DependencySet& set) {
  std::sort(set.entries.begin(), set.entries.end(), compare_dependency);
  set.entries.erase(std::unique(set.entries.begin(), set.entries.end(),
                                [](const DependencyEntry& a, const DependencyEntry& b) {
                                  return a.name == b.name && a.kind == b.kind &&
                                         a.content.digest == b.content.digest && a.content.size == b.content.size;
                                }),
                    set.entries.end());
  for (auto& entry : set.entries) entry.identity_digest = compute_dependency_entry_identity(entry);
  set.id = derive_dependency_set_id(set);
  set.identity_digest = compute_dependency_set_identity(set);
}

void canonicalize(EnvironmentContract& env) {
  std::sort(env.variables.begin(), env.variables.end(), compare_config);
  for (auto& kv : env.variables) kv.first = trim(kv.first);
  env.variables.erase(std::unique(env.variables.begin(), env.variables.end(),
                                  [](const auto& a, const auto& b) { return a.first == b.first; }),
                      env.variables.end());
}

void canonicalize(ToolchainIdentity& toolchain) {
  std::sort(toolchain.sdk.begin(), toolchain.sdk.end(), compare_sdk);
  std::sort(toolchain.plugins.begin(), toolchain.plugins.end(), compare_plugin);
  std::sort(toolchain.target_libraries.begin(), toolchain.target_libraries.end());
  toolchain.target_libraries.erase(
      std::unique(toolchain.target_libraries.begin(), toolchain.target_libraries.end()),
      toolchain.target_libraries.end());
  std::sort(toolchain.configuration.begin(), toolchain.configuration.end(), compare_config);
  toolchain.configuration.erase(
      std::unique(toolchain.configuration.begin(), toolchain.configuration.end(),
                  [](const auto& a, const auto& b) { return a.first == b.first; }),
      toolchain.configuration.end());
  toolchain.id = derive_toolchain_id(toolchain);
  toolchain.identity_digest = compute_toolchain_identity(toolchain);
}

bool toolchain_identity_is_provable(const ToolchainIdentity& toolchain) noexcept {
  if (toolchain.evidence != EvidenceClass::Real) return false;
  if (toolchain.compiler.state != BinaryIdState::Known) return false;
  if (toolchain.family == CompilerFamily::Unknown) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Identity derivation
// ---------------------------------------------------------------------------
Digest256 compute_dependency_entry_identity(const DependencyEntry& entry) {
  CanonicalWriter w;
  w.domain("dc.dependency-entry.v1");
  w.str(entry.name);
  w.u8(static_cast<std::uint8_t>(entry.kind));
  write_content_ref(w, entry.content);
  return w.hash();
}

Digest256 compute_dependency_set_identity(const DependencySet& set) {
  CanonicalWriter w;
  w.domain("dc.dependency-set.v1");
  w.list(static_cast<std::uint32_t>(set.entries.size()));
  for (const auto& entry : set.entries) write_dependency_entry(w, entry);
  return w.hash();
}

DependencySetId derive_dependency_set_id(const DependencySet& set) {
  CanonicalWriter w;
  w.domain("dc.dependency-set-id.v1");
  // The id is derived from the *names and kinds* only, so that a content change
  // to an existing member is observable as a generation change on the same id.
  w.list(static_cast<std::uint32_t>(set.entries.size()));
  for (const auto& entry : set.entries) {
    w.str(entry.name);
    w.u8(static_cast<std::uint8_t>(entry.kind));
  }
  return DependencySetId(mix64(handle_from_digest(w.hash())));
}

SourceId derive_source_id(std::string_view logical_name) {
  CanonicalWriter w;
  w.domain("dc.source-id.v1");
  w.str(logical_name);
  return SourceId(mix64(handle_from_digest(w.hash())));
}

IRId derive_ir_id(std::string_view logical_name, InputFormat format) {
  CanonicalWriter w;
  w.domain("dc.ir-id.v1");
  w.str(logical_name);
  w.u8(static_cast<std::uint8_t>(format));
  return IRId(mix64(handle_from_digest(w.hash())));
}

SpecializationId derive_specialization_id(const SpecializationSpec& spec) {
  CanonicalWriter w;
  w.domain("dc.specialization-id.v1");
  w.list(static_cast<std::uint32_t>(spec.fields.size()));
  for (const auto& field : spec.fields) {
    w.str(field.name);
    w.u8(static_cast<std::uint8_t>(field.kind));
  }
  return SpecializationId(mix64(handle_from_digest(w.hash())));
}

CompilePolicyId derive_policy_id(const CompilePolicy& policy) {
  CanonicalWriter w;
  w.domain("dc.policy-id.v1");
  w.str(policy.profile);
  return CompilePolicyId(mix64(handle_from_digest(w.hash())));
}

ToolchainId derive_toolchain_id(const ToolchainIdentity& toolchain) {
  CanonicalWriter w;
  w.domain("dc.toolchain-id.v1");
  w.u8(static_cast<std::uint8_t>(toolchain.family));
  w.str(toolchain.version_string);
  // The logical install name is the compiler path's parent chain, not the full
  // path: two builds sharing an install root are the same logical toolchain.
  w.str(toolchain.compiler.path);
  return ToolchainId(mix64(handle_from_digest(w.hash())));
}

TargetId derive_target_id(const TargetIdentity& target) {
  CanonicalWriter w;
  w.domain("dc.target-id.v1");
  w.str(target.triple);
  w.u8(static_cast<std::uint8_t>(target.object_format));
  w.u8(static_cast<std::uint8_t>(target.accelerator.vendor));
  w.str(target.accelerator.architecture);
  return TargetId(mix64(handle_from_digest(w.hash())));
}

Digest256 compute_specialization_identity(const SpecializationSpec& spec) {
  CanonicalWriter w;
  w.domain("dc.specialization.v1");
  w.list(static_cast<std::uint32_t>(spec.fields.size()));
  for (const auto& field : spec.fields) write_spec_field(w, field);
  return w.hash();
}

Digest256 compute_policy_identity(const CompilePolicy& policy) {
  CanonicalWriter w;
  w.domain("dc.policy.v1");
  w.str(policy.profile);
  w.u8(static_cast<std::uint8_t>(policy.reproducibility));
  w.u8(static_cast<std::uint8_t>(policy.cache));
  w.boolean(policy.flag_order_significant);
  w.boolean(policy.require_exact_generation);
  w.boolean(policy.negative_cache_enabled);
  w.u32(policy.negative_cache_max_entries);
  w.boolean(policy.allow_speculative_duplication);
  w.u32(policy.max_attempts_per_unit);
  w.boolean(policy.require_trusted_workers);
  w.boolean(policy.require_provable_toolchain);
  return w.hash();
}

Digest256 compute_environment_identity(const EnvironmentContract& env) {
  CanonicalWriter w;
  w.domain("dc.environment.v1");
  w.boolean(env.deterministic);
  w.boolean(env.inherit_process_environment);
  w.list(static_cast<std::uint32_t>(env.variables.size()));
  for (const auto& kv : env.variables) {
    w.str(kv.first);
    w.str(kv.second);
  }
  return w.hash();
}

Digest256 compute_unit_source_identity(const UnitSource& source) {
  CanonicalWriter w;
  w.domain("dc.unit-source.v1");
  w.str(source.logical_name);
  w.u8(static_cast<std::uint8_t>(source.format));
  w.str(source.language_mode);
  write_content_ref(w, source.content);
  return w.hash();
}

Digest256 compute_target_identity(const TargetIdentity& target) {
  CanonicalWriter w;
  w.domain("dc.target.v1");
  w.u8(static_cast<std::uint8_t>(target.os));
  w.u8(static_cast<std::uint8_t>(target.arch));
  w.u8(static_cast<std::uint8_t>(target.abi));
  w.str(target.triple);
  w.u8(static_cast<std::uint8_t>(target.object_format));
  w.u8(static_cast<std::uint8_t>(target.stdlib));
  w.str(target.runtime_abi);
  write_accelerator(w, target.accelerator);
  return w.hash();
}

Digest256 compute_toolchain_identity(const ToolchainIdentity& toolchain) {
  CanonicalWriter w;
  w.domain("dc.toolchain.v1");
  w.u8(static_cast<std::uint8_t>(toolchain.family));
  w.str(toolchain.version_string);
  w.u32(toolchain.version_major);
  w.u32(toolchain.version_minor);
  w.u32(toolchain.version_patch);
  write_binary_identity(w, toolchain.compiler);
  write_binary_identity(w, toolchain.linker);
  write_binary_identity(w, toolchain.assembler);
  write_binary_identity(w, toolchain.runtime_library);
  w.list(static_cast<std::uint32_t>(toolchain.sdk.size()));
  for (const auto& component : toolchain.sdk) {
    w.str(component.name);
    w.str(component.version);
  }
  w.list(static_cast<std::uint32_t>(toolchain.plugins.size()));
  for (const auto& plugin : toolchain.plugins) {
    w.str(plugin.id);
    w.str(plugin.version);
    w.digest(plugin.digest);
  }
  write_string_list(w, toolchain.target_libraries);
  w.list(static_cast<std::uint32_t>(toolchain.configuration.size()));
  for (const auto& kv : toolchain.configuration) {
    w.str(kv.first);
    w.str(kv.second);
  }
  w.u8(static_cast<std::uint8_t>(toolchain.evidence));
  return w.hash();
}

CompilationId derive_compilation_id(const Digest256& unit_identity) {
  CanonicalWriter w;
  w.domain("dc.compilation-id.v1");
  w.digest(unit_identity);
  return CompilationId(mix64(handle_from_digest64(w.hash())));
}

CompilationUnitId derive_unit_handle(const Digest256& unit_identity) {
  CanonicalWriter w;
  w.domain("dc.unit-handle.v1");
  w.digest(unit_identity);
  return CompilationUnitId(mix64(handle_from_digest64(w.hash())));
}

// ---------------------------------------------------------------------------
// Unit and request identity
// ---------------------------------------------------------------------------
namespace {

void write_unit_identity_body(CanonicalWriter& w, const CompilationRequest& request,
                              const CompilationUnitSpec& unit) {
  w.digest(request.toolchain.identity_digest);
  w.digest(request.target.identity_digest);
  w.digest(request.specialization.identity_digest);
  w.digest(request.policy.identity_digest);
  w.digest(request.dependencies.identity_digest);
  w.digest(compute_environment_identity(request.environment));
  w.u8(static_cast<std::uint8_t>(unit.kind));
  w.str(unit.logical_name);
  w.u8(static_cast<std::uint8_t>(unit.output_kind));
  w.list(static_cast<std::uint32_t>(unit.sources.size()));
  for (const auto& source : unit.sources) {
    w.str(source.logical_name);
    w.u8(static_cast<std::uint8_t>(source.format));
    w.str(source.language_mode);
    write_content_ref(w, source.content);
  }
  w.list(static_cast<std::uint32_t>(unit.dependencies.size()));
  for (const auto& dep : unit.dependencies) write_dependency_entry(w, dep);
  write_string_list(w, unit.flags);
  write_string_list(w, request.flags);
  w.list(static_cast<std::uint32_t>(unit.child_units.size()));
  for (std::uint32_t child : unit.child_units) w.u32(child);
  w.boolean(unit.mandatory);
}

Status canonicalize_unit(CompilationRequest& request, CompilationUnitSpec& unit) {
  for (auto& source : unit.sources) {
    source.logical_name = trim(source.logical_name);
    if (source.logical_name.empty()) {
      return Status::error(ErrorCode::InvalidArgument, "unit source with empty logical name");
    }
    if (source.content.digest.is_zero()) {
      return Status::error(ErrorCode::InvalidArgument,
                           "unit source '" + source.logical_name + "' has no content digest");
    }
    if (source.format == InputFormat::Unknown) {
      source.format = input_format_from_extension(source.logical_name);
    }
    if (source.format == InputFormat::Unknown) {
      return Status::error(ErrorCode::InvalidArgument,
                           "unit source '" + source.logical_name + "' has unknown input format");
    }
    if (source.language_mode.empty()) source.language_mode = "c++20";
    source.identity_digest = compute_unit_source_identity(source);
  }
  std::sort(unit.sources.begin(), unit.sources.end(), compare_source);
  for (std::size_t i = 1; i < unit.sources.size(); ++i) {
    if (unit.sources[i].logical_name == unit.sources[i - 1].logical_name) {
      return Status::error(ErrorCode::Duplicate, "duplicate unit source name: " + unit.sources[i].logical_name);
    }
  }
  if (unit.sources.empty()) {
    return Status::error(ErrorCode::InvalidArgument, "unit '" + unit.logical_name + "' has no sources");
  }

  for (auto& dep : unit.dependencies) {
    dep.name = trim(dep.name);
    if (dep.name.empty()) {
      return Status::error(ErrorCode::InvalidArgument, "unit dependency with empty name");
    }
    if (dep.content.digest.is_zero()) {
      return Status::error(ErrorCode::InvalidArgument, "unit dependency '" + dep.name + "' has no content digest");
    }
    dep.identity_digest = compute_dependency_entry_identity(dep);
  }
  std::sort(unit.dependencies.begin(), unit.dependencies.end(), compare_dependency);

  std::vector<std::string> flags;
  flags.reserve(unit.flags.size());
  for (const auto& flag : unit.flags) {
    std::string cleaned = trim(flag);
    if (cleaned.empty()) {
      return Status::error(ErrorCode::InvalidArgument, "empty compiler flag in unit '" + unit.logical_name + "'");
    }
    if (contains_control(cleaned)) {
      return Status::error(ErrorCode::InvalidArgument, "control character in compiler flag");
    }
    flags.push_back(std::move(cleaned));
  }
  if (!request.policy.flag_order_significant) std::sort(flags.begin(), flags.end());
  unit.flags = std::move(flags);

  std::sort(unit.child_units.begin(), unit.child_units.end());
  unit.child_units.erase(std::unique(unit.child_units.begin(), unit.child_units.end()), unit.child_units.end());

  unit.logical_name = trim(unit.logical_name);
  if (unit.logical_name.empty()) {
    return Status::error(ErrorCode::InvalidArgument, "unit with empty logical name");
  }
  if (unit.kind == UnitKind::Link && unit.child_units.empty()) {
    return Status::error(ErrorCode::InvalidArgument, "link unit '" + unit.logical_name + "' has no inputs");
  }
  return Status::success();
}

}  // namespace

Digest256 derive_unit_identity(const CompilationRequest& request, const CompilationUnitSpec& unit) {
  CanonicalWriter w;
  w.domain("dc.unit.v1");
  write_unit_identity_body(w, request, unit);
  return w.hash();
}

Digest256 derive_request_identity(const CompilationRequest& request) {
  CanonicalWriter w;
  w.domain("dc.request.v1");
  w.digest(request.toolchain.identity_digest);
  w.digest(request.target.identity_digest);
  w.digest(request.specialization.identity_digest);
  w.digest(request.policy.identity_digest);
  w.digest(request.dependencies.identity_digest);
  w.digest(compute_environment_identity(request.environment));
  write_string_list(w, request.flags);
  w.digest(request.authority_generation);
  w.boolean(request.validation.require_format_check);
  w.boolean(request.validation.require_digest_check);
  w.boolean(request.validation.require_target_metadata);
  w.boolean(request.validation.require_dependency_metadata);
  w.boolean(request.validation.require_smoke_test);
  w.str(request.validation.smoke_expected_stdout);
  w.u32(request.validation.smoke_timeout_ms);
  w.list(static_cast<std::uint32_t>(request.units.size()));
  for (const auto& unit : request.units) w.digest(unit.identity_digest);
  return w.hash();
}

Digest256 derive_single_unit_identity(const CompilationRequest& request) {
  CanonicalWriter w;
  w.domain("dc.single-unit.v1");
  w.digest(request.request_identity);
  return w.hash();
}

Status canonicalize(CompilationRequest& request) {
  canonicalize(request.toolchain);
  if (request.toolchain.family == CompilerFamily::Unknown) {
    return Status::error(ErrorCode::InvalidArgument, "compilation request requires an identified toolchain");
  }
  if (request.toolchain.identity_digest.is_zero()) {
    return Status::error(ErrorCode::InvalidArgument, "compilation request requires a toolchain identity");
  }

  request.target.identity_digest = compute_target_identity(request.target);
  if (request.target.identity_digest.is_zero() || request.target.arch == ArchKind::Unknown) {
    return Status::error(ErrorCode::InvalidArgument, "compilation request requires a concrete target");
  }
  request.target.id = derive_target_id(request.target);

  Status spec_status = canonicalize(request.specialization);
  if (!spec_status.ok()) return spec_status;

  canonicalize(request.dependencies);

  canonicalize(request.environment);

  std::vector<std::string> job_flags;
  job_flags.reserve(request.flags.size());
  for (const auto& flag : request.flags) {
    std::string cleaned = trim(flag);
    if (cleaned.empty()) {
      return Status::error(ErrorCode::InvalidArgument, "empty job-level compiler flag");
    }
    if (contains_control(cleaned)) {
      return Status::error(ErrorCode::InvalidArgument, "control character in job-level compiler flag");
    }
    job_flags.push_back(std::move(cleaned));
  }
  if (!request.policy.flag_order_significant) std::sort(job_flags.begin(), job_flags.end());
  request.flags = std::move(job_flags);

  if (request.units.empty()) {
    return Status::error(ErrorCode::InvalidArgument, "compilation request has no units");
  }

  std::sort(request.units.begin(), request.units.end(),
            [](const CompilationUnitSpec& a, const CompilationUnitSpec& b) { return a.index < b.index; });
  for (std::size_t i = 0; i < request.units.size(); ++i) {
    if (request.units[i].index != i) {
      return Status::error(ErrorCode::InvalidArgument, "unit indices must be dense and zero-based");
    }
    Status unit_status = canonicalize_unit(request, request.units[i]);
    if (!unit_status.ok()) return unit_status;
  }
  for (const auto& unit : request.units) {
    for (std::uint32_t child : unit.child_units) {
      if (child >= request.units.size()) {
        return Status::error(ErrorCode::InvalidArgument, "unit child index out of range");
      }
      if (child == unit.index) {
        return Status::error(ErrorCode::InvalidArgument, "unit cannot depend on itself");
      }
    }
  }

  request.policy.id = derive_policy_id(request.policy);
  request.policy.identity_digest = compute_policy_identity(request.policy);

  for (auto& unit : request.units) unit.identity_digest = derive_unit_identity(request, unit);
  request.request_identity = derive_request_identity(request);
  return Status::success();
}

const CompilationUnitSpec* CompilationRequest::find_unit(std::uint32_t index) const {
  for (const auto& unit : units) {
    if (unit.index == index) return &unit;
  }
  return nullptr;
}

}  // namespace dc
