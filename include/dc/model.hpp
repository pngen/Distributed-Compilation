// Distributed Compilation - compilation request, environment and result domain model.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Identity doctrine implemented in this header:
//
//   * CONTENT identity answers "is this the same compilation work?". It is
//     derived only from content-derived fields (digests, formats, flags,
//     identities) and never from handles, paths, timestamps or counters.
//   * AUTHORITY identity answers "is this work still allowed to become
//     authoritative right now?". It is derived from coordinator-assigned
//     generations and is bound into authority claims and commit records.
//
//   A cache lookup is validated on content identity; a commit is validated on
//   both. Neither alone is sufficient.
#ifndef DC_MODEL_HPP
#define DC_MODEL_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dc/canonical.hpp"
#include "dc/digest.hpp"
#include "dc/identity.hpp"
#include "dc/types.hpp"

namespace dc {

// ---------------------------------------------------------------------------
// Evidence classification. Every identity, capability and validation record
// states how it was established. Nothing synthetic may be presented as real.
// ---------------------------------------------------------------------------
enum class EvidenceClass : std::uint8_t {
  Unknown = 0,      // not established; fails closed for hard requirements
  Real = 1,         // observed from a real process, file, device or network
  Synthetic = 2,    // constructed profile used to exercise generic logic only
  Unsupported = 3,  // explicitly not available in this deployment
};

std::string_view to_string(EvidenceClass value) noexcept;
bool parse_evidence_class(std::string_view text, EvidenceClass& out) noexcept;

struct Evidence {
  EvidenceId id;
  EvidenceGeneration generation;
  EvidenceClass klass = EvidenceClass::Unknown;
  std::string source;   // "msvc-discovery", "worker-advertisement", ...
  std::string detail;
};

// ---------------------------------------------------------------------------
// Content references and blobs
// ---------------------------------------------------------------------------
struct ContentRef {
  Digest256 digest;
  std::uint64_t size = 0;

  bool is_set() const noexcept { return !digest.is_zero(); }

  friend bool operator==(const ContentRef& a, const ContentRef& b) noexcept {
    return a.digest == b.digest && a.size == b.size;
  }
  friend bool operator!=(const ContentRef& a, const ContentRef& b) noexcept { return !(a == b); }
};

// A blob is content-addressed: its digest is verified on ingest, on store and
// on load. A blob whose bytes do not hash to its declared digest is rejected.
struct Blob {
  Digest256 digest;
  std::vector<std::byte> bytes;
};

void write_content_ref(CanonicalWriter& w, const ContentRef& ref);
bool read_content_ref(CanonicalReader& r, ContentRef& out);

// ---------------------------------------------------------------------------
// Source / IR input model
// ---------------------------------------------------------------------------
enum class InputFormat : std::uint8_t {
  Unknown = 0,
  Source = 1,
  PreprocessedSource = 2,
  LlvmIr = 3,
  Ptx = 4,
  SpirV = 5,
  VendorIr = 6,
  Object = 7,
  Cubin = 8,
  Assembly = 9,
  Other = 10,
};

std::string_view to_string(InputFormat value) noexcept;
bool parse_input_format(std::string_view text, InputFormat& out) noexcept;
InputFormat input_format_from_extension(std::string_view name) noexcept;

struct SourceInput {
  SourceId id;                     // derived from logical name (stable across content edits)
  SourceGeneration generation;     // coordinator-assigned content version
  std::string logical_name;        // declared path inside the compilation, e.g. "src/math.cpp"
  InputFormat format = InputFormat::Unknown;
  std::string language_mode;       // "c++20", "cuda-c++17", ...
  ContentRef content;
  Digest256 identity_digest;       // content identity of this input
};

struct IRInput {
  IRId id;
  IRGeneration generation;
  InputFormat format = InputFormat::Unknown;
  std::string producer;            // e.g. "clang-18 -emit-llvm"
  ContentRef content;
  Digest256 identity_digest;
};

// ---------------------------------------------------------------------------
// Dependency model
// ---------------------------------------------------------------------------
enum class DependencyKind : std::uint8_t {
  Header = 0,
  Module = 1,
  GeneratedCode = 2,
  Library = 3,
  DeviceLibrary = 4,
  RuntimeLibrary = 5,
  CompilerPlugin = 6,
  Configuration = 7,
  ModelMetadata = 8,
  ToolchainFile = 9,
  Other = 10,
};

std::string_view to_string(DependencyKind value) noexcept;
bool parse_dependency_kind(std::string_view text, DependencyKind& out) noexcept;

struct DependencyEntry {
  std::string name;                // stable declared name, e.g. "include/math.hpp"
  DependencyKind kind = DependencyKind::Other;
  ContentRef content;
  Digest256 identity_digest;
};

// A dependency set is identified by the sorted multiset of (name, kind) pairs,
// and versioned by the sorted multiset of content digests. Reordering the same
// members never changes identity; changing any member content always does.
struct DependencySet {
  DependencySetId id;
  DependencyGeneration generation;
  std::vector<DependencyEntry> entries;   // canonically sorted
  Digest256 identity_digest;

  bool empty() const noexcept { return entries.empty(); }
};

void canonicalize(DependencySet& set);

// ---------------------------------------------------------------------------
// Target model
// ---------------------------------------------------------------------------
enum class OsKind : std::uint8_t { Unknown = 0, Windows = 1, Linux = 2, MacOs = 3, Bsd = 4, BareMetal = 5 };
enum class ArchKind : std::uint8_t { Unknown = 0, X86_64 = 1, Aarch64 = 2, X86 = 3, Arm32 = 4, RiscV64 = 5 };
enum class AbiKind : std::uint8_t { Unknown = 0, Msvc = 1, Itanium = 2, Gnu = 3 };
enum class ObjectFormat : std::uint8_t { Unknown = 0, Coff = 1, Elf = 2, MachO = 3, Ptx = 4, Cubin = 5, Fatbin = 6 };
enum class AcceleratorVendor : std::uint8_t { None = 0, Nvidia = 1, Amd = 2, Intel = 3, Unknown = 4 };
enum class StdlibKind : std::uint8_t { Unknown = 0, MsvcStl = 1, Libstdcxx = 2, Libcxx = 3, None = 4 };

std::string_view to_string(OsKind value) noexcept;
std::string_view to_string(ArchKind value) noexcept;
std::string_view to_string(AbiKind value) noexcept;
std::string_view to_string(ObjectFormat value) noexcept;
std::string_view to_string(AcceleratorVendor value) noexcept;
std::string_view to_string(StdlibKind value) noexcept;
bool parse_os_kind(std::string_view text, OsKind& out) noexcept;
bool parse_arch_kind(std::string_view text, ArchKind& out) noexcept;
bool parse_object_format(std::string_view text, ObjectFormat& out) noexcept;
bool parse_accelerator_vendor(std::string_view text, AcceleratorVendor& out) noexcept;
bool parse_stdlib_kind(std::string_view text, StdlibKind& out) noexcept;

struct AcceleratorTarget {
  AcceleratorVendor vendor = AcceleratorVendor::None;
  std::string architecture;          // "sm_120", "gfx942", ...
  std::uint32_t compute_major = 0;
  std::uint32_t compute_minor = 0;
  std::string isa;                   // "sm_120a", "sramecc+xnack-", ...
  std::string device_runtime;        // "cuda-12.9", "rocm-6.2", "level-zero-1.10"
};

struct TargetIdentity {
  TargetId id;
  TargetGeneration generation;
  OsKind os = OsKind::Unknown;
  ArchKind arch = ArchKind::Unknown;
  AbiKind abi = AbiKind::Unknown;
  std::string triple;                // "x86_64-pc-windows-msvc"
  ObjectFormat object_format = ObjectFormat::Unknown;
  StdlibKind stdlib = StdlibKind::Unknown;
  std::string runtime_abi;
  AcceleratorTarget accelerator;
  EvidenceClass evidence = EvidenceClass::Unknown;
  Digest256 identity_digest;
};

// ---------------------------------------------------------------------------
// Toolchain identity
// ---------------------------------------------------------------------------
enum class CompilerFamily : std::uint8_t {
  Unknown = 0,
  Msvc = 1,
  Clang = 2,
  Gnu = 3,
  NvidiaNvcc = 4,
  SyntheticRocm = 5,
  SyntheticLevelZero = 6,
  SyntheticGeneric = 7,
  MsvcLinker = 8,
};

std::string_view to_string(CompilerFamily value) noexcept;
bool parse_compiler_family(std::string_view text, CompilerFamily& out) noexcept;

// A compiler executable's identity is either its binary digest (strong), or an
// explicitly labelled UNKNOWN. Path is only evidence of identity when no digest
// could be obtained, and that fact is recorded rather than hidden.
enum class BinaryIdState : std::uint8_t { Unknown = 0, Known = 1, Unavailable = 2 };

std::string_view to_string(BinaryIdState value) noexcept;

struct BinaryIdentity {
  BinaryIdState state = BinaryIdState::Unknown;
  Digest256 digest;
  std::uint64_t size = 0;
  std::string path;             // diagnostic; part of identity only when state != Known
  std::string version_string;
};

struct PluginIdentity {
  std::string id;
  std::string version;
  Digest256 digest;
};

struct SdkComponent {
  std::string name;
  std::string version;
  std::string root;   // diagnostic path, never part of identity
};

struct ToolchainIdentity {
  ToolchainId id;
  ToolchainGeneration generation;
  CompilerFamily family = CompilerFamily::Unknown;
  std::string version_string;
  std::uint32_t version_major = 0;
  std::uint32_t version_minor = 0;
  std::uint32_t version_patch = 0;
  BinaryIdentity compiler;
  BinaryIdentity linker;
  BinaryIdentity assembler;
  BinaryIdentity runtime_library;
  std::vector<SdkComponent> sdk;                              // sorted by name
  std::vector<PluginIdentity> plugins;                        // sorted by id
  std::vector<std::string> target_libraries;                  // sorted
  std::vector<std::pair<std::string, std::string>> configuration;  // sorted by key
  EvidenceClass evidence = EvidenceClass::Unknown;
  EvidenceId evidence_id;
  EvidenceGeneration evidence_generation;
  Digest256 identity_digest;
};

void canonicalize(ToolchainIdentity& toolchain);
// True when the toolchain is usable for reproducible-cache reuse. A toolchain
// whose compiler binary identity is UNKNOWN, or whose evidence class is
// UNKNOWN/UNSUPPORTED, cannot satisfy a reproducible cache requirement.
bool toolchain_identity_is_provable(const ToolchainIdentity& toolchain) noexcept;

// ---------------------------------------------------------------------------
// Specialization model
// ---------------------------------------------------------------------------
enum class SpecValueKind : std::uint8_t { Signed = 0, Unsigned = 1, Floating = 2, Text = 3, Boolean = 4 };

std::string_view to_string(SpecValueKind value) noexcept;

struct SpecField {
  std::string name;
  SpecValueKind kind = SpecValueKind::Signed;
  std::int64_t signed_value = 0;
  std::uint64_t unsigned_value = 0;
  double floating_value = 0.0;
  bool boolean_value = false;
  std::string text_value;

  static SpecField make_signed(std::string name, std::int64_t value);
  static SpecField make_unsigned(std::string name, std::uint64_t value);
  static SpecField make_floating(std::string name, double value);
  static SpecField make_text(std::string name, std::string value);
  static SpecField make_boolean(std::string name, bool value);

  std::string render() const;
};

struct SpecializationSpec {
  SpecializationId id;
  SpecializationGeneration generation;
  std::vector<SpecField> fields;   // sorted by name, names unique
  Digest256 identity_digest;
};

// Returns a failure when duplicate field names are present. Sorting is applied
// in place so that unordered map iteration order can never leak into identity.
Status canonicalize(SpecializationSpec& spec);

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------
enum class ReproducibilityRequirement : std::uint8_t { Required = 0, Preferred = 1, NotRequired = 2 };
enum class CachePolicy : std::uint8_t { ReadWrite = 0, ReadOnly = 1, Bypass = 2 };
enum class OutputKind : std::uint8_t {
  Executable = 0,
  Object = 1,
  StaticLibrary = 2,
  DynamicLibrary = 3,
  Cubin = 4,
  Ptx = 5,
  Assembly = 6,
  PreprocessedSource = 7,
};

std::string_view to_string(ReproducibilityRequirement value) noexcept;
std::string_view to_string(CachePolicy value) noexcept;
std::string_view to_string(OutputKind value) noexcept;
bool parse_reproducibility(std::string_view text, ReproducibilityRequirement& out) noexcept;
bool parse_cache_policy(std::string_view text, CachePolicy& out) noexcept;
bool parse_output_kind(std::string_view text, OutputKind& out) noexcept;

struct ValidationRequirements {
  bool require_format_check = true;
  bool require_digest_check = true;
  bool require_target_metadata = true;
  bool require_dependency_metadata = false;
  bool require_smoke_test = false;
  std::string smoke_expected_stdout;
  std::uint32_t smoke_timeout_ms = 30000;
};

struct CompilePolicy {
  CompilePolicyId id;
  CompilePolicyGeneration generation;
  std::string profile = "default";   // logical policy profile name
  ReproducibilityRequirement reproducibility = ReproducibilityRequirement::Preferred;
  CachePolicy cache = CachePolicy::ReadWrite;
  bool flag_order_significant = true;
  bool require_exact_generation = false;
  bool negative_cache_enabled = false;
  std::uint32_t negative_cache_max_entries = 64;
  bool allow_speculative_duplication = false;
  std::uint32_t max_attempts_per_unit = 3;
  bool require_trusted_workers = false;
  bool require_provable_toolchain = true;
  Digest256 identity_digest;
};

struct EnvironmentContract {
  std::vector<std::pair<std::string, std::string>> variables;  // sorted by key
  bool deterministic = true;        // timestamps/paths normalized where possible
  bool inherit_process_environment = false;
};

void canonicalize(EnvironmentContract& env);

// ---------------------------------------------------------------------------
// Compilation units and request
// ---------------------------------------------------------------------------
enum class UnitKind : std::uint8_t { Compile = 0, Link = 1 };

std::string_view to_string(UnitKind value) noexcept;

// A unit source carries its content by digest reference into a submission
// bundle, so identical content shared by several units is transferred once.
struct UnitSource {
  std::string logical_name;
  InputFormat format = InputFormat::Unknown;
  std::string language_mode;
  ContentRef content;
  Digest256 identity_digest;
};

struct CompilationUnitSpec {
  std::uint32_t index = 0;           // canonical position, dense from zero
  std::string logical_name;          // "src/math.cpp", "link:app"
  UnitKind kind = UnitKind::Compile;
  std::vector<UnitSource> sources;   // canonically sorted by logical_name
  std::vector<DependencyEntry> dependencies;  // canonically sorted
  std::vector<std::string> flags;
  OutputKind output_kind = OutputKind::Object;
  std::vector<std::uint32_t> child_units;     // link inputs, ascending
  bool mandatory = true;                       // required for parent fan-in
  Digest256 identity_digest;
};

struct CompilationRequest {
  RequestId request_id;                     // client idempotency key; not content
  RequestGeneration request_generation;      // authority domain
  ToolchainIdentity toolchain;               // required toolchain (pinned identity)
  TargetIdentity target;                     // required target
  SpecializationSpec specialization;
  CompilePolicy policy;
  DependencySet dependencies;                // union dependency set for the job
  EnvironmentContract environment;
  std::vector<std::string> flags;            // job-level flags applied to every unit
  ValidationRequirements validation;
  std::vector<CompilationUnitSpec> units;    // dense canonical order
  Digest256 authority_generation;            // opaque external authority token
  Digest256 request_identity;                // derived: content identity of the job

  const CompilationUnitSpec* find_unit(std::uint32_t index) const;
};

// Canonicalizes every identity-bearing collection, then recomputes identity
// digests bottom-up and the job-level request identity.
Status canonicalize(CompilationRequest& request);

// Content identity of one unit within a job. Two requests that differ only in
// unit ordering derive the same per-unit identities.
Digest256 derive_unit_identity(const CompilationRequest& request, const CompilationUnitSpec& unit);

// Content identity of a whole job.
Digest256 derive_request_identity(const CompilationRequest& request);

// Content identity of a single-unit job, used by the common non-fan-out path.
Digest256 derive_single_unit_identity(const CompilationRequest& request);

// ---------------------------------------------------------------------------
// Identity derivation.
//
// Logical ids are derived from a stable *name* (a logical path, a target triple,
// a policy profile, a toolchain install name) so that a change of content for
// the same name is observable as a generation change on the same id. Content
// digests are derived from the full descriptor and are what cache and commit
// validation compare.
// ---------------------------------------------------------------------------
ToolchainId derive_toolchain_id(const ToolchainIdentity& toolchain);
TargetId derive_target_id(const TargetIdentity& target);
SpecializationId derive_specialization_id(const SpecializationSpec& spec);
DependencySetId derive_dependency_set_id(const DependencySet& set);
SourceId derive_source_id(std::string_view logical_name);
IRId derive_ir_id(std::string_view logical_name, InputFormat format);
CompilePolicyId derive_policy_id(const CompilePolicy& policy);

Digest256 compute_toolchain_identity(const ToolchainIdentity& toolchain);
Digest256 compute_target_identity(const TargetIdentity& target);
Digest256 compute_specialization_identity(const SpecializationSpec& spec);
Digest256 compute_dependency_set_identity(const DependencySet& set);
Digest256 compute_policy_identity(const CompilePolicy& policy);
Digest256 compute_environment_identity(const EnvironmentContract& env);
Digest256 compute_unit_source_identity(const UnitSource& source);
Digest256 compute_dependency_entry_identity(const DependencyEntry& entry);

// ---------------------------------------------------------------------------
// Artifacts, validation and provenance
// ---------------------------------------------------------------------------
struct ArtifactDescriptor {
  ArtifactId id;
  ArtifactGeneration generation;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  CompilationUnitId unit;
  OutputKind kind = OutputKind::Object;
  ContentRef content;
  std::string logical_name;
  Digest256 target_identity;
  Digest256 toolchain_identity;
  Digest256 dependency_identity;
  Digest256 specialization_identity;
};

enum class ValidationOutcome : std::uint8_t { Pass = 0, Fail = 1, Unknown = 2 };

std::string_view to_string(ValidationOutcome value) noexcept;

struct ValidationCheck {
  std::string check;
  ValidationOutcome outcome = ValidationOutcome::Unknown;
  std::string detail;
};

struct ValidationReport {
  ValidationId id;
  std::vector<ValidationCheck> checks;   // deterministic order
  ValidationOutcome aggregate = ValidationOutcome::Unknown;
  std::string summary;

  bool passed() const noexcept { return aggregate == ValidationOutcome::Pass; }
};

// Provenance states what was actually observed, and how.
struct Provenance {
  ProvenanceId id;
  ProvenanceGeneration generation;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  CompilationUnitId unit;
  CompilationAttemptId attempt;
  CompilationAttemptGeneration attempt_generation;
  CoordinatorEpoch epoch;
  WorkerId worker;
  WorkerBootId worker_boot;
  WorkerGeneration worker_generation;
  LeaseId lease;
  LeaseGeneration lease_generation;
  RequestId request_id;
  Digest256 request_identity;
  Digest256 unit_identity;
  ContentRef artifact;
  Digest256 source_identity;
  Digest256 ir_identity;
  Digest256 dependency_identity;
  Digest256 toolchain_identity;
  Digest256 target_identity;
  Digest256 specialization_identity;
  Digest256 policy_identity;
  ValidationId validation;
  EvidenceClass evidence = EvidenceClass::Unknown;
  std::string compiler_invocation;
  std::string compiler_version_string;
  std::uint64_t compiler_wall_millis = 0;
  UnixMillis produced_at = 0;
};

struct ArtifactCommit {
  ArtifactCommitId id;
  ArtifactCommitGeneration generation;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  CompilationUnitId unit;
  ArtifactId artifact;
  ArtifactGeneration artifact_generation;
  Digest256 artifact_digest;
  ProvenanceId provenance;
  ValidationId validation;
  CoordinatorEpoch epoch;
  WorkerId worker;
  WorkerBootId worker_boot;
  CompilationAttemptId attempt;
  UnixMillis committed_at = 0;
  bool deduplicated = false;      // a redundant equivalent candidate converged here
};

// ---------------------------------------------------------------------------
// Cache model
// ---------------------------------------------------------------------------
struct CacheEntry {
  CacheEntryId id;
  CacheGeneration generation;
  Digest256 unit_identity;          // content identity the entry was produced for
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  ContentRef artifact;
  ArtifactId artifact_id;
  ProvenanceId provenance;
  ValidationId validation;
  Digest256 source_identity;
  Digest256 dependency_identity;
  Digest256 toolchain_identity;
  ToolchainGeneration toolchain_generation;
  Digest256 target_identity;
  TargetGeneration target_generation;
  Digest256 specialization_identity;
  Digest256 policy_identity;
  Digest256 environment_identity;
  ArtifactCommitId commit;
  UnixMillis created_at = 0;
  bool invalidated = false;
  std::string invalidation_reason;
  std::uint32_t hit_count = 0;
};

enum class CacheOutcome : std::uint8_t {
  Reusable = 0,
  Stale = 1,
  Incompatible = 2,
  Corrupt = 3,
  Unknown = 4,
  Miss = 5,
};

std::string_view to_string(CacheOutcome value) noexcept;
ErrorCode cache_outcome_error(CacheOutcome outcome) noexcept;

struct CacheMismatch {
  std::string dimension;
  std::string expected;
  std::string actual;
};

struct CacheDecision {
  CacheOutcome outcome = CacheOutcome::Miss;
  std::string reason;
  std::vector<CacheMismatch> mismatches;
  CacheEntryId entry;
  bool generation_drift = false;

  bool reusable() const noexcept { return outcome == CacheOutcome::Reusable; }
};

// Negative cache records a deterministic failure bound to the generations that
// justify it. Transient causes are never admitted here.
enum class NegativeCacheReason : std::uint8_t {
  UnsupportedTarget = 0,
  DeterministicCompilerRejection = 1,
  IncompatibleSourceToolchain = 2,
  PolicyRefusal = 3,
};

std::string_view to_string(NegativeCacheReason value) noexcept;

struct NegativeCacheEntry {
  CacheEntryId id;
  Digest256 unit_identity;
  NegativeCacheReason reason = NegativeCacheReason::DeterministicCompilerRejection;
  ErrorCode failure = ErrorCode::ValidationFailure;
  std::string diagnostic;
  Digest256 toolchain_identity;
  ToolchainGeneration toolchain_generation;
  Digest256 target_identity;
  TargetGeneration target_generation;
  Digest256 specialization_identity;
  Digest256 policy_identity;
  UnixMillis created_at = 0;
};

// ---------------------------------------------------------------------------
// Intermediate artifacts
// ---------------------------------------------------------------------------
enum class IntermediateKind : std::uint8_t {
  PreprocessedSource = 0,
  GeneratedIr = 1,
  OptimizedIr = 2,
  DeviceCode = 3,
  ObjectFile = 4,
  LinkInput = 5,
  Metadata = 6,
};

std::string_view to_string(IntermediateKind value) noexcept;

struct IntermediateArtifact {
  IntermediateId id;
  IntermediateGeneration generation;
  IntermediateKind kind = IntermediateKind::Metadata;
  ContentRef content;
  Digest256 provenance_identity;
  Digest256 toolchain_identity;
  Digest256 target_identity;
  Digest256 dependency_identity;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  bool authoritative = false;
};

// ---------------------------------------------------------------------------
// Content-addressed store interface
// ---------------------------------------------------------------------------
class BlobStore {
 public:
  virtual ~BlobStore() = default;

  // Stores bytes under their digest. Returns the digest. Idempotent: storing
  // identical content twice is not an error and does not create a second copy.
  virtual Result<Digest256> put(std::span<const std::byte> bytes) = 0;
  virtual Status get(const Digest256& digest, std::vector<std::byte>& out) const = 0;
  virtual bool contains(const Digest256& digest) const = 0;
  virtual Status remove(const Digest256& digest) = 0;
  virtual std::uint64_t stored_bytes() const = 0;
};

}  // namespace dc

#endif  // DC_MODEL_HPP
