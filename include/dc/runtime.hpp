// Distributed Compilation - workers, eligibility, leases, authority and attempt lifecycle.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_RUNTIME_HPP
#define DC_RUNTIME_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dc/canonical.hpp"
#include "dc/identity.hpp"
#include "dc/model.hpp"
#include "dc/types.hpp"

namespace dc {

// ---------------------------------------------------------------------------
// Worker capability model. Capabilities are evidence-backed: a capability that
// was never advertised is UNKNOWN, and UNKNOWN fails closed for hard
// requirements. A capability whose evidence has gone stale is treated the same
// way until it is refreshed.
// ---------------------------------------------------------------------------
struct WorkerCapabilities {
  std::vector<ToolchainIdentity> toolchains;      // sorted by identity digest
  std::vector<TargetIdentity> targets;            // sorted by identity digest
  std::vector<InputFormat> input_formats;         // sorted, unique
  std::vector<PluginIdentity> plugins;            // sorted by id
  std::vector<SdkComponent> sdks;                 // sorted by name
  std::uint32_t logical_cores = 0;
  std::uint64_t memory_bytes = 0;
  std::uint64_t scratch_bytes = 0;
  std::uint64_t max_artifact_bytes = 0;
  bool filesystem_isolation = false;
  bool sandbox = false;
  bool deterministic_build = false;
  bool remote_cache_access = false;
  bool artifact_store_access = false;
  bool trusted = false;
  EvidenceClass evidence = EvidenceClass::Unknown;
  std::string host;
  Digest256 digest;                                // identity of the capability set
};

void canonicalize(WorkerCapabilities& caps);

const ToolchainIdentity* find_toolchain(const WorkerCapabilities& caps, const Digest256& identity) noexcept;
const TargetIdentity* find_target(const WorkerCapabilities& caps, const Digest256& identity) noexcept;
bool supports_format(const WorkerCapabilities& caps, InputFormat format) noexcept;

// ---------------------------------------------------------------------------
// Worker record
// ---------------------------------------------------------------------------
enum class WorkerHealth : std::uint8_t {
  Unknown = 0,
  Healthy = 1,
  Suspect = 2,
  Dead = 3,
  Fenced = 4,
  Draining = 5,
};

std::string_view to_string(WorkerHealth value) noexcept;

struct WorkerRecord {
  WorkerId id;
  WorkerBootId boot;
  WorkerGeneration generation;
  SessionId session;
  std::string endpoint;
  std::string host;
  WorkerCapabilities capabilities;
  WorkerHealth health = WorkerHealth::Unknown;
  bool ready = false;
  bool fenced = false;
  bool trusted_evidence_fresh = false;
  std::uint32_t queue_depth = 0;
  std::uint32_t in_flight = 0;
  std::uint64_t completed_units = 0;
  std::uint64_t failed_units = 0;
  std::uint64_t total_compile_millis = 0;
  std::uint64_t cache_affinity_hits = 0;
  UnixMillis registered_at = 0;
  UnixMillis last_seen = 0;
  std::vector<LeaseId> active_leases;
};

// ---------------------------------------------------------------------------
// Hard requirements: eligibility inputs. These are the constraints that decide
// whether a worker MAY run a unit. Ranking is only ever applied afterwards.
// ---------------------------------------------------------------------------
struct HardRequirements {
  std::optional<Digest256> toolchain_identity;
  std::optional<Digest256> target_identity;
  std::vector<InputFormat> required_formats;
  std::vector<std::string> required_plugins;      // "id@version" or "id"
  std::vector<SdkComponent> required_sdks;        // name (+ optional exact version)
  std::uint32_t min_logical_cores = 0;
  std::uint64_t min_memory_bytes = 0;
  std::uint64_t min_scratch_bytes = 0;
  std::uint64_t min_max_artifact_bytes = 0;
  bool require_sandbox = false;
  bool require_filesystem_isolation = false;
  bool require_deterministic_build = false;
  bool require_trusted = false;
  bool require_remote_cache = false;
  bool require_artifact_store = false;
  bool require_provable_toolchain = true;
  std::string locality_host;                      // empty = no locality constraint
  bool require_locality = false;
};

enum class IneligibilityReason : std::uint8_t {
  None = 0,
  WorkerUnknown,
  WorkerNotReady,
  WorkerFenced,
  WorkerUnhealthy,
  CapabilityUnknown,
  ToolchainMissing,
  ToolchainUnproven,
  TargetMissing,
  FormatUnsupported,
  PluginMissing,
  SdkMissing,
  InsufficientCores,
  InsufficientMemory,
  InsufficientScratch,
  ArtifactSizeLimit,
  SandboxRequired,
  IsolationRequired,
  DeterminismRequired,
  TrustRequired,
  RemoteCacheRequired,
  ArtifactStoreRequired,
  LocalityRequired,
};

std::string_view to_string(IneligibilityReason value) noexcept;

struct EligibilityDecision {
  bool eligible = false;
  IneligibilityReason reason = IneligibilityReason::None;
  std::string detail;

  explicit operator bool() const noexcept { return eligible; }
};

EligibilityDecision evaluate_eligibility(const WorkerRecord& worker, const HardRequirements& req);

// ---------------------------------------------------------------------------
// Ranking. Ranking produces an order; it confers no authority whatsoever.
// ---------------------------------------------------------------------------
struct RankFactor {
  std::string name;
  std::int64_t value = 0;
};

struct RankedWorker {
  WorkerId id;
  WorkerBootId boot;
  WorkerGeneration generation;
  std::int64_t score = 0;
  std::vector<RankFactor> factors;
};

// Deterministic: identical inputs and identical eligible sets always produce
// the same order, independent of registration order, pointer values or timing.
std::vector<RankedWorker> rank_workers(const std::vector<WorkerRecord>& eligible,
                                       const HardRequirements& req,
                                       std::uint64_t estimated_cost_millis);

// ---------------------------------------------------------------------------
// Leases
// ---------------------------------------------------------------------------
struct CompileLease {
  LeaseId id;
  LeaseGeneration generation;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  CompilationUnitId unit;
  CompilationAttemptId attempt;
  WorkerId worker;
  WorkerBootId worker_boot;
  WorkerGeneration worker_generation;
  CoordinatorEpoch epoch;
  UnixMillis issued_at = 0;
  bool revoked = false;
  std::string revocation_reason;
};

// ---------------------------------------------------------------------------
// Compile authority
// ---------------------------------------------------------------------------
// A claim is what a worker asserts when it reports progress or a result. The
// expectation is what the coordinator currently believes. Every field of the
// claim is compared; the first mismatch is reported as a typed stale failure.
struct AuthorityClaim {
  CoordinatorEpoch epoch;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  CompilationUnitId unit;
  UnitGeneration unit_generation;
  CompilationAttemptId attempt;
  CompilationAttemptGeneration attempt_generation;
  WorkerId worker;
  WorkerBootId worker_boot;
  WorkerGeneration worker_generation;
  LeaseId lease;
  LeaseGeneration lease_generation;
  SourceGeneration source_generation;
  IRGeneration ir_generation;
  DependencyGeneration dependency_generation;
  ToolchainGeneration toolchain_generation;
  TargetGeneration target_generation;
  SpecializationGeneration specialization_generation;
  CompilePolicyGeneration policy_generation;
  CacheGeneration cache_generation;
  Digest256 request_identity;
  Digest256 unit_identity;
};

struct AuthorityExpectation {
  CoordinatorEpoch epoch;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  CompilationUnitId unit;
  UnitGeneration unit_generation;
  CompilationAttemptId attempt;
  CompilationAttemptGeneration attempt_generation;
  WorkerId worker;
  WorkerBootId worker_boot;
  WorkerGeneration worker_generation;
  LeaseId lease;
  LeaseGeneration lease_generation;
  SourceGeneration source_generation;
  IRGeneration ir_generation;
  DependencyGeneration dependency_generation;
  ToolchainGeneration toolchain_generation;
  TargetGeneration target_generation;
  SpecializationGeneration specialization_generation;
  CompilePolicyGeneration policy_generation;
  CacheGeneration cache_generation;
  Digest256 request_identity;
  Digest256 unit_identity;
};

Status validate_authority(const AuthorityClaim& claim, const AuthorityExpectation& expected);

void write_authority_claim(CanonicalWriter& w, const AuthorityClaim& claim);
bool read_authority_claim(CanonicalReader& r, AuthorityClaim& out);

// ---------------------------------------------------------------------------
// Attempt lifecycle
// ---------------------------------------------------------------------------
enum class AttemptState : std::uint8_t {
  Created = 0,
  Eligible = 1,
  Assigned = 2,
  Preparing = 3,
  Running = 4,
  Produced = 5,
  Validating = 6,
  CommitReady = 7,
  Committed = 8,
  Failed = 9,
  Cancelled = 10,
  Fenced = 11,
  Ambiguous = 12,
  Retired = 13,
};

std::string_view to_string(AttemptState value) noexcept;
bool parse_attempt_state(std::string_view text, AttemptState& out) noexcept;

// The transition relation is closed: anything not listed is refused with
// ErrorCode::IllegalTransition instead of being silently accepted.
bool is_legal_transition(AttemptState from, AttemptState to) noexcept;
bool is_terminal_state(AttemptState state) noexcept;
bool holds_commit_authority(AttemptState state) noexcept;

enum class FailureClass : std::uint8_t { Retryable = 0, NonRetryable = 1, Ambiguous = 2 };

std::string_view to_string(FailureClass value) noexcept;
FailureClass classify_failure(ErrorCode code) noexcept;

struct CompilationAttempt {
  CompilationAttemptId id;
  CompilationAttemptGeneration generation;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  CompilationUnitId unit;
  WorkerId worker;
  WorkerBootId worker_boot;
  WorkerGeneration worker_generation;
  LeaseId lease;
  LeaseGeneration lease_generation;
  CoordinatorEpoch epoch;
  AttemptState state = AttemptState::Created;
  std::uint32_t ordinal = 0;
  bool speculative = false;
  UnixMillis created_at = 0;
  UnixMillis started_at = 0;
  UnixMillis finished_at = 0;
  ErrorCode failure = ErrorCode::Ok;
  std::string failure_detail;
  ValidationReport validation;
  ContentRef candidate;
  Digest256 candidate_digest;
  ArtifactId artifact;
  std::uint64_t compiler_wall_millis = 0;
  std::string compiler_invocation;
  std::string compiler_version_string;
};

// ---------------------------------------------------------------------------
// Compilation record: one logical unit of compilation work.
// ---------------------------------------------------------------------------
enum class CompilationState : std::uint8_t {
  Pending = 0,
  CacheHit = 1,
  Eligible = 2,
  Assigned = 3,
  Running = 4,
  Producing = 5,
  Validating = 6,
  CommitReady = 7,
  Committed = 8,
  Failed = 9,
  Cancelled = 10,
  Fenced = 11,
  Ambiguous = 12,
  Retired = 13,
};

std::string_view to_string(CompilationState value) noexcept;

struct CompilationRecord {
  CompilationId id;
  CompilationGeneration generation;
  CompilationUnitId unit;
  UnitGeneration unit_generation;
  Digest256 unit_identity;
  RequestId request_id;
  RequestGeneration request_generation;
  Digest256 request_identity;
  Digest256 source_identity;
  Digest256 dependency_identity;
  Digest256 toolchain_identity;
  Digest256 target_identity;
  Digest256 specialization_identity;
  Digest256 policy_identity;
  Digest256 environment_identity;
  SourceGeneration source_generation;
  IRGeneration ir_generation;
  DependencyGeneration dependency_generation;
  ToolchainGeneration toolchain_generation;
  TargetGeneration target_generation;
  SpecializationGeneration specialization_generation;
  CompilePolicyGeneration policy_generation;
  OutputKind output_kind = OutputKind::Object;
  ReproducibilityRequirement reproducibility = ReproducibilityRequirement::Preferred;
  CompilationState state = CompilationState::Pending;
  std::vector<CompilationAttemptId> attempts;
  CompilationAttemptId current_attempt;
  std::uint32_t attempt_ordinal_counter = 0;
  std::optional<ArtifactCommit> commit;
  std::vector<ContentRef> divergent_candidates;   // retained for diagnostics
  bool reproducibility_violation = false;
  std::string failure_detail;
  ErrorCode failure = ErrorCode::Ok;
  bool cache_hit = false;
  UnixMillis created_at = 0;
  UnixMillis updated_at = 0;
  std::uint32_t unit_index = 0;
  std::uint32_t parent_unit_index = 0;
  bool is_root = true;
};

// Job record: the fan-out/fan-in grouping of one submitted request.
struct JobRecord {
  RequestId request_id;
  RequestGeneration request_generation;
  Digest256 request_identity;
  std::vector<CompilationId> units;      // indexed by unit index
  std::uint32_t root_index = 0;
  std::vector<std::uint32_t> mandatory_units;
  bool committed = false;
  CompilationId committed_unit;
  ErrorCode failure = ErrorCode::Ok;
  std::string failure_detail;
  UnixMillis created_at = 0;
};

// ---------------------------------------------------------------------------
// Content-to-generation registry.
//
// Generation is a pure function of (identity, content history): identical
// content always resolves to the same generation, and changed content always
// resolves to a strictly greater one. This removes generation drift, so a
// cache entry keyed on generation can never be invalidated merely because an
// unrelated earlier submission happened in between.
//
// The history is bounded. If an old content is evicted its generation is
// forgotten, and re-submitting that content assigns a fresh (higher)
// generation; cache entries recorded against the forgotten generation then
// fail closed as STALE. Fail-closed is the intended behaviour.
// ---------------------------------------------------------------------------
template <class IdT, class GenT>
class GenerationRegistry {
 public:
  struct Slot {
    std::map<Digest256, GenT> by_content;
    GenT current;
    std::vector<Digest256> order;   // insertion order for bounded eviction
  };

  explicit GenerationRegistry(std::size_t per_id_history = 64) : history_limit_(per_id_history) {}

  // Resolves the generation for (id, content). created=true when this content
  // was not previously known for that id.
  GenT resolve(const IdT& id, const Digest256& content, bool& created) {
    Slot& slot = slots_[id];
    auto it = slot.by_content.find(content);
    if (it != slot.by_content.end()) {
      created = false;
      slot.current = it->second;
      return it->second;
    }
    created = true;
    GenT next = slot.current.is_zero() ? GenT(1) : slot.current.next();
    slot.by_content.emplace(content, next);
    slot.order.push_back(content);
    slot.current = next;
    while (slot.order.size() > history_limit_) {
      const Digest256 oldest = slot.order.front();
      slot.order.erase(slot.order.begin());
      slot.by_content.erase(oldest);
    }
    return next;
  }

  bool lookup(const IdT& id, const Digest256& content, GenT& out) const {
    auto slot = slots_.find(id);
    if (slot == slots_.end()) return false;
    auto it = slot->second.by_content.find(content);
    if (it == slot->second.by_content.end()) return false;
    out = it->second;
    return true;
  }

  bool current(const IdT& id, GenT& generation, Digest256& content) const {
    auto slot = slots_.find(id);
    if (slot == slots_.end() || slot->second.current.is_zero()) return false;
    generation = slot->second.current;
    for (const auto& kv : slot->second.by_content) {
      if (kv.second == generation) {
        content = kv.first;
        return true;
      }
    }
    return false;
  }

  // Returns true when content is the current content for id.
  bool is_current(const IdT& id, const Digest256& content) const {
    GenT generation;
    Digest256 current_content;
    if (!current(id, generation, current_content)) return false;
    return current_content == content;
  }

  const std::map<IdT, Slot>& slots() const noexcept { return slots_; }
  void clear() { slots_.clear(); }

  // Restores a (content, generation) pair during recovery. The current
  // generation is advanced to the highest restored value.
  void restore(const IdT& id, const Digest256& content, GenT generation) {
    Slot& slot = slots_[id];
    if (!slot.by_content.count(content)) slot.order.push_back(content);
    slot.by_content[content] = generation;
    if (generation > slot.current) slot.current = generation;
  }

 private:
  std::size_t history_limit_;
  std::map<IdT, Slot> slots_;
};

using SourceRegistry = GenerationRegistry<SourceId, SourceGeneration>;
using IRRegistry = GenerationRegistry<IRId, IRGeneration>;
using DependencyRegistry = GenerationRegistry<DependencySetId, DependencyGeneration>;
using ToolchainRegistry = GenerationRegistry<ToolchainId, ToolchainGeneration>;
using TargetRegistry = GenerationRegistry<TargetId, TargetGeneration>;
using SpecializationRegistry = GenerationRegistry<SpecializationId, SpecializationGeneration>;
using PolicyRegistry = GenerationRegistry<CompilePolicyId, CompilePolicyGeneration>;

Digest256 compute_capability_identity(const WorkerCapabilities& caps);

}  // namespace dc

#endif  // DC_RUNTIME_HPP
