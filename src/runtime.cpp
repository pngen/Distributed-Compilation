// Distributed Compilation - worker eligibility, ranking, leases and authority validation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/runtime.hpp"

#include <algorithm>
#include <cstring>

namespace dc {

std::string_view to_string(WorkerHealth value) noexcept {
  switch (value) {
    case WorkerHealth::Unknown: return "UNKNOWN";
    case WorkerHealth::Healthy: return "HEALTHY";
    case WorkerHealth::Suspect: return "SUSPECT";
    case WorkerHealth::Dead: return "DEAD";
    case WorkerHealth::Fenced: return "FENCED";
    case WorkerHealth::Draining: return "DRAINING";
  }
  return "UNKNOWN";
}

std::string_view to_string(IneligibilityReason value) noexcept {
  switch (value) {
    case IneligibilityReason::None: return "NONE";
    case IneligibilityReason::WorkerUnknown: return "WORKER_UNKNOWN";
    case IneligibilityReason::WorkerNotReady: return "WORKER_NOT_READY";
    case IneligibilityReason::WorkerFenced: return "WORKER_FENCED";
    case IneligibilityReason::WorkerUnhealthy: return "WORKER_UNHEALTHY";
    case IneligibilityReason::CapabilityUnknown: return "CAPABILITY_UNKNOWN";
    case IneligibilityReason::ToolchainMissing: return "TOOLCHAIN_MISSING";
    case IneligibilityReason::ToolchainUnproven: return "TOOLCHAIN_UNPROVEN";
    case IneligibilityReason::TargetMissing: return "TARGET_MISSING";
    case IneligibilityReason::FormatUnsupported: return "FORMAT_UNSUPPORTED";
    case IneligibilityReason::PluginMissing: return "PLUGIN_MISSING";
    case IneligibilityReason::SdkMissing: return "SDK_MISSING";
    case IneligibilityReason::InsufficientCores: return "INSUFFICIENT_CORES";
    case IneligibilityReason::InsufficientMemory: return "INSUFFICIENT_MEMORY";
    case IneligibilityReason::InsufficientScratch: return "INSUFFICIENT_SCRATCH";
    case IneligibilityReason::ArtifactSizeLimit: return "ARTIFACT_SIZE_LIMIT";
    case IneligibilityReason::SandboxRequired: return "SANDBOX_REQUIRED";
    case IneligibilityReason::IsolationRequired: return "ISOLATION_REQUIRED";
    case IneligibilityReason::DeterminismRequired: return "DETERMINISM_REQUIRED";
    case IneligibilityReason::TrustRequired: return "TRUST_REQUIRED";
    case IneligibilityReason::RemoteCacheRequired: return "REMOTE_CACHE_REQUIRED";
    case IneligibilityReason::ArtifactStoreRequired: return "ARTIFACT_STORE_REQUIRED";
    case IneligibilityReason::LocalityRequired: return "LOCALITY_REQUIRED";
  }
  return "NONE";
}

std::string_view to_string(AttemptState value) noexcept {
  switch (value) {
    case AttemptState::Created: return "Created";
    case AttemptState::Eligible: return "Eligible";
    case AttemptState::Assigned: return "Assigned";
    case AttemptState::Preparing: return "Preparing";
    case AttemptState::Running: return "Running";
    case AttemptState::Produced: return "Produced";
    case AttemptState::Validating: return "Validating";
    case AttemptState::CommitReady: return "CommitReady";
    case AttemptState::Committed: return "Committed";
    case AttemptState::Failed: return "Failed";
    case AttemptState::Cancelled: return "Cancelled";
    case AttemptState::Fenced: return "Fenced";
    case AttemptState::Ambiguous: return "Ambiguous";
    case AttemptState::Retired: return "Retired";
  }
  return "Created";
}

bool parse_attempt_state(std::string_view text, AttemptState& out) noexcept {
  struct Entry { std::string_view name; AttemptState value; };
  static const Entry kEntries[] = {
      {"Created", AttemptState::Created},         {"Eligible", AttemptState::Eligible},
      {"Assigned", AttemptState::Assigned},       {"Preparing", AttemptState::Preparing},
      {"Running", AttemptState::Running},         {"Produced", AttemptState::Produced},
      {"Validating", AttemptState::Validating},   {"CommitReady", AttemptState::CommitReady},
      {"Committed", AttemptState::Committed},     {"Failed", AttemptState::Failed},
      {"Cancelled", AttemptState::Cancelled},     {"Fenced", AttemptState::Fenced},
      {"Ambiguous", AttemptState::Ambiguous},     {"Retired", AttemptState::Retired},
  };
  for (const auto& entry : kEntries) {
    if (text == entry.name) { out = entry.value; return true; }
  }
  return false;
}

// The transition relation is closed. Anything absent is IllegalTransition.
bool is_legal_transition(AttemptState from, AttemptState to) noexcept {
  if (from == to) return false;
  switch (from) {
    case AttemptState::Created:
      return to == AttemptState::Eligible || to == AttemptState::Fenced || to == AttemptState::Cancelled;
    case AttemptState::Eligible:
      return to == AttemptState::Assigned || to == AttemptState::Failed || to == AttemptState::Fenced ||
             to == AttemptState::Cancelled;
    case AttemptState::Assigned:
      return to == AttemptState::Preparing || to == AttemptState::Failed || to == AttemptState::Fenced ||
             to == AttemptState::Cancelled || to == AttemptState::Ambiguous;
    case AttemptState::Preparing:
      // A compile may produce its result before the Running acknowledgement is
      // observed (very short compiles, or a fast worker), so Preparing must be
      // able to reach Produced directly.
      return to == AttemptState::Running || to == AttemptState::Produced || to == AttemptState::Failed ||
             to == AttemptState::Fenced || to == AttemptState::Cancelled || to == AttemptState::Ambiguous;
    case AttemptState::Running:
      return to == AttemptState::Produced || to == AttemptState::Failed || to == AttemptState::Fenced ||
             to == AttemptState::Cancelled || to == AttemptState::Ambiguous;
    case AttemptState::Produced:
      return to == AttemptState::Validating || to == AttemptState::Failed || to == AttemptState::Fenced ||
             to == AttemptState::Cancelled;
    case AttemptState::Validating:
      return to == AttemptState::CommitReady || to == AttemptState::Failed || to == AttemptState::Fenced ||
             to == AttemptState::Cancelled;
    case AttemptState::CommitReady:
      // CommitReady is the only state from which a commit may be attempted.
      return to == AttemptState::Committed || to == AttemptState::Failed || to == AttemptState::Fenced ||
             to == AttemptState::Cancelled || to == AttemptState::Ambiguous;
    case AttemptState::Committed:
      return to == AttemptState::Retired;   // terminal with respect to artifact identity
    case AttemptState::Failed:
      return to == AttemptState::Retired;
    case AttemptState::Cancelled:
      return to == AttemptState::Retired;
    case AttemptState::Fenced:
      return to == AttemptState::Retired;
    case AttemptState::Ambiguous:
      // An ambiguous attempt may only be retired: it can never be resurrected
      // into Produced/CommitReady, because its candidate can no longer be
      // proven to belong to the current authority.
      return to == AttemptState::Retired;
    case AttemptState::Retired:
      return false;
  }
  return false;
}

bool is_terminal_state(AttemptState state) noexcept {
  switch (state) {
    case AttemptState::Committed:
    case AttemptState::Failed:
    case AttemptState::Cancelled:
    case AttemptState::Fenced:
    case AttemptState::Retired:
      return true;
    default:
      return false;
  }
}

bool holds_commit_authority(AttemptState state) noexcept {
  return state == AttemptState::CommitReady || state == AttemptState::Validating ||
         state == AttemptState::Produced || state == AttemptState::Running || state == AttemptState::Preparing ||
         state == AttemptState::Assigned;
}

std::string_view to_string(FailureClass value) noexcept {
  switch (value) {
    case FailureClass::Retryable: return "RETRYABLE";
    case FailureClass::NonRetryable: return "NON_RETRYABLE";
    case FailureClass::Ambiguous: return "AMBIGUOUS";
  }
  return "NON_RETRYABLE";
}

FailureClass classify_failure(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::TransportFailure:
    case ErrorCode::ConnectionClosed:
    case ErrorCode::Timeout:
    case ErrorCode::IoError:
    case ErrorCode::Internal:
      return FailureClass::Retryable;
    case ErrorCode::Ambiguous:
    case ErrorCode::Shutdown:
      return FailureClass::Ambiguous;
    case ErrorCode::StaleEpoch:
    case ErrorCode::StaleWorkerBoot:
    case ErrorCode::StaleWorkerGeneration:
    case ErrorCode::StaleLease:
    case ErrorCode::StaleCompilation:
    case ErrorCode::StaleAttempt:
    case ErrorCode::StaleSource:
    case ErrorCode::StaleIR:
    case ErrorCode::StaleDependencies:
    case ErrorCode::StaleToolchain:
    case ErrorCode::StaleTarget:
    case ErrorCode::StaleSpecialization:
    case ErrorCode::StalePolicy:
    case ErrorCode::StaleCache:
    case ErrorCode::StaleRequest:
    case ErrorCode::StaleSession:
      return FailureClass::Retryable;   // re-issued under fresh authority, never resumed
    case ErrorCode::Unknown:
      return FailureClass::Ambiguous;
    default:
      return FailureClass::NonRetryable;
  }
}

std::string_view to_string(CompilationState value) noexcept {
  switch (value) {
    case CompilationState::Pending: return "Pending";
    case CompilationState::CacheHit: return "CacheHit";
    case CompilationState::Eligible: return "Eligible";
    case CompilationState::Assigned: return "Assigned";
    case CompilationState::Running: return "Running";
    case CompilationState::Producing: return "Producing";
    case CompilationState::Validating: return "Validating";
    case CompilationState::CommitReady: return "CommitReady";
    case CompilationState::Committed: return "Committed";
    case CompilationState::Failed: return "Failed";
    case CompilationState::Cancelled: return "Cancelled";
    case CompilationState::Fenced: return "Fenced";
    case CompilationState::Ambiguous: return "Ambiguous";
    case CompilationState::Retired: return "Retired";
  }
  return "Pending";
}

// ---------------------------------------------------------------------------
// Worker capabilities
// ---------------------------------------------------------------------------
namespace {

bool compare_toolchain(const ToolchainIdentity& a, const ToolchainIdentity& b) {
  return a.identity_digest < b.identity_digest;
}
bool compare_target(const TargetIdentity& a, const TargetIdentity& b) { return a.identity_digest < b.identity_digest; }
bool compare_plugin(const PluginIdentity& a, const PluginIdentity& b) { return a.id < b.id; }
bool compare_sdk(const SdkComponent& a, const SdkComponent& b) { return a.name < b.name; }

}  // namespace

void canonicalize(WorkerCapabilities& caps) {
  for (auto& toolchain : caps.toolchains) canonicalize(toolchain);
  for (auto& target : caps.targets) target.identity_digest = compute_target_identity(target);
  std::sort(caps.toolchains.begin(), caps.toolchains.end(), compare_toolchain);
  std::sort(caps.targets.begin(), caps.targets.end(), compare_target);
  std::sort(caps.input_formats.begin(), caps.input_formats.end());
  caps.input_formats.erase(std::unique(caps.input_formats.begin(), caps.input_formats.end()),
                           caps.input_formats.end());
  std::sort(caps.plugins.begin(), caps.plugins.end(), compare_plugin);
  std::sort(caps.sdks.begin(), caps.sdks.end(), compare_sdk);
  caps.digest = compute_capability_identity(caps);
}

Digest256 compute_capability_identity(const WorkerCapabilities& caps) {
  CanonicalWriter w;
  w.domain("dc.capabilities.v1");
  w.list(static_cast<std::uint32_t>(caps.toolchains.size()));
  for (const auto& toolchain : caps.toolchains) w.digest(toolchain.identity_digest);
  w.list(static_cast<std::uint32_t>(caps.targets.size()));
  for (const auto& target : caps.targets) w.digest(target.identity_digest);
  w.list(static_cast<std::uint32_t>(caps.input_formats.size()));
  for (InputFormat format : caps.input_formats) w.u8(static_cast<std::uint8_t>(format));
  w.list(static_cast<std::uint32_t>(caps.plugins.size()));
  for (const auto& plugin : caps.plugins) {
    w.str(plugin.id);
    w.str(plugin.version);
    w.digest(plugin.digest);
  }
  w.list(static_cast<std::uint32_t>(caps.sdks.size()));
  for (const auto& sdk : caps.sdks) {
    w.str(sdk.name);
    w.str(sdk.version);
  }
  w.u32(caps.logical_cores);
  w.u64(caps.memory_bytes);
  w.u64(caps.scratch_bytes);
  w.u64(caps.max_artifact_bytes);
  w.boolean(caps.filesystem_isolation);
  w.boolean(caps.sandbox);
  w.boolean(caps.deterministic_build);
  w.boolean(caps.remote_cache_access);
  w.boolean(caps.artifact_store_access);
  w.boolean(caps.trusted);
  w.u8(static_cast<std::uint8_t>(caps.evidence));
  return w.hash();
}

const ToolchainIdentity* find_toolchain(const WorkerCapabilities& caps, const Digest256& identity) noexcept {
  for (const auto& toolchain : caps.toolchains) {
    if (toolchain.identity_digest == identity) return &toolchain;
  }
  return nullptr;
}

const TargetIdentity* find_target(const WorkerCapabilities& caps, const Digest256& identity) noexcept {
  for (const auto& target : caps.targets) {
    if (target.identity_digest == identity) return &target;
  }
  return nullptr;
}

bool supports_format(const WorkerCapabilities& caps, InputFormat format) noexcept {
  for (InputFormat supported : caps.input_formats) {
    if (supported == format) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Eligibility. This runs BEFORE any ranking. A worker that fails any hard
// requirement is never ranked, never assigned, and never gains authority.
// ---------------------------------------------------------------------------
EligibilityDecision evaluate_eligibility(const WorkerRecord& worker, const HardRequirements& req) {
  EligibilityDecision decision;

  const auto reject = [&decision](IneligibilityReason reason, std::string detail) {
    decision.eligible = false;
    decision.reason = reason;
    decision.detail = std::move(detail);
    return decision;
  };

  if (worker.fenced || worker.health == WorkerHealth::Fenced) {
    return reject(IneligibilityReason::WorkerFenced, "worker is fenced");
  }
  if (worker.health == WorkerHealth::Dead) {
    return reject(IneligibilityReason::WorkerUnhealthy, "worker is dead");
  }
  if (worker.health == WorkerHealth::Unknown) {
    return reject(IneligibilityReason::WorkerUnknown, "worker health is unknown");
  }
  if (worker.health == WorkerHealth::Suspect) {
    return reject(IneligibilityReason::WorkerUnhealthy, "worker health is suspect");
  }
  if (worker.health == WorkerHealth::Draining) {
    return reject(IneligibilityReason::WorkerUnhealthy, "worker is draining");
  }
  if (!worker.ready) {
    return reject(IneligibilityReason::WorkerNotReady, "worker has not reported ready");
  }
  if (worker.capabilities.evidence == EvidenceClass::Unknown) {
    return reject(IneligibilityReason::CapabilityUnknown, "worker capability evidence is UNKNOWN");
  }
  if (worker.capabilities.evidence == EvidenceClass::Unsupported) {
    return reject(IneligibilityReason::CapabilityUnknown, "worker declared capability evidence UNSUPPORTED");
  }

  if (req.toolchain_identity.has_value()) {
    const ToolchainIdentity* toolchain = find_toolchain(worker.capabilities, *req.toolchain_identity);
    if (toolchain == nullptr) {
      return reject(IneligibilityReason::ToolchainMissing, "required toolchain identity not advertised");
    }
    if (req.require_provable_toolchain && !toolchain_identity_is_provable(*toolchain)) {
      return reject(IneligibilityReason::ToolchainUnproven,
                    "toolchain identity is not provable (evidence=" +
                        std::string(to_string(toolchain->evidence)) + ")");
    }
  }

  if (req.target_identity.has_value()) {
    if (find_target(worker.capabilities, *req.target_identity) == nullptr) {
      return reject(IneligibilityReason::TargetMissing, "required target identity not advertised");
    }
  }

  for (InputFormat format : req.required_formats) {
    if (!supports_format(worker.capabilities, format)) {
      return reject(IneligibilityReason::FormatUnsupported,
                    "input format not supported: " + std::string(to_string(format)));
    }
  }

  for (const auto& requirement : req.required_plugins) {
    bool found = false;
    for (const auto& plugin : worker.capabilities.plugins) {
      std::string candidate = plugin.id;
      if (!plugin.version.empty()) candidate += "@" + plugin.version;
      if (candidate == requirement || plugin.id == requirement) {
        found = true;
        break;
      }
    }
    if (!found) return reject(IneligibilityReason::PluginMissing, "compiler plugin not available: " + requirement);
  }

  for (const auto& requirement : req.required_sdks) {
    bool found = false;
    for (const auto& sdk : worker.capabilities.sdks) {
      if (sdk.name != requirement.name) continue;
      if (!requirement.version.empty() && sdk.version != requirement.version) continue;
      found = true;
      break;
    }
    if (!found) {
      std::string detail = "SDK component not available: " + requirement.name;
      if (!requirement.version.empty()) detail += "@" + requirement.version;
      return reject(IneligibilityReason::SdkMissing, std::move(detail));
    }
  }

  if (req.min_logical_cores > 0 && worker.capabilities.logical_cores < req.min_logical_cores) {
    return reject(IneligibilityReason::InsufficientCores, "logical cores below requirement");
  }
  if (req.min_memory_bytes > 0 && worker.capabilities.memory_bytes < req.min_memory_bytes) {
    return reject(IneligibilityReason::InsufficientMemory, "memory below requirement");
  }
  if (req.min_scratch_bytes > 0 && worker.capabilities.scratch_bytes < req.min_scratch_bytes) {
    return reject(IneligibilityReason::InsufficientScratch, "scratch space below requirement");
  }
  if (req.min_max_artifact_bytes > 0 && worker.capabilities.max_artifact_bytes < req.min_max_artifact_bytes) {
    return reject(IneligibilityReason::ArtifactSizeLimit, "artifact size limit below requirement");
  }

  if (req.require_sandbox && !worker.capabilities.sandbox) {
    return reject(IneligibilityReason::SandboxRequired, "worker does not provide sandboxing");
  }
  if (req.require_filesystem_isolation && !worker.capabilities.filesystem_isolation) {
    return reject(IneligibilityReason::IsolationRequired, "worker does not provide filesystem isolation");
  }
  if (req.require_deterministic_build && !worker.capabilities.deterministic_build) {
    return reject(IneligibilityReason::DeterminismRequired, "worker does not provide deterministic builds");
  }
  if (req.require_trusted && !worker.capabilities.trusted) {
    return reject(IneligibilityReason::TrustRequired, "worker is not trusted");
  }
  if (req.require_remote_cache && !worker.capabilities.remote_cache_access) {
    return reject(IneligibilityReason::RemoteCacheRequired, "worker has no remote cache access");
  }
  if (req.require_artifact_store && !worker.capabilities.artifact_store_access) {
    return reject(IneligibilityReason::ArtifactStoreRequired, "worker has no artifact store access");
  }
  if (req.require_locality && !req.locality_host.empty() && worker.host != req.locality_host) {
    return reject(IneligibilityReason::LocalityRequired, "worker is not on the required host");
  }

  decision.eligible = true;
  decision.reason = IneligibilityReason::None;
  decision.detail.clear();
  return decision;
}

// ---------------------------------------------------------------------------
// Ranking. Pure integer arithmetic over a fixed factor list, sorted with a
// deterministic tie-break, so identical inputs always produce identical orders.
// ---------------------------------------------------------------------------
std::vector<RankedWorker> rank_workers(const std::vector<WorkerRecord>& eligible,
                                       const HardRequirements& req,
                                       std::uint64_t estimated_cost_millis) {
  std::vector<RankedWorker> ranked;
  ranked.reserve(eligible.size());

  for (const auto& worker : eligible) {
    RankedWorker entry;
    entry.id = worker.id;
    entry.boot = worker.boot;
    entry.generation = worker.generation;

    const std::int64_t locality =
        (!req.locality_host.empty() && worker.host == req.locality_host) ? 10000 : 0;
    const std::int64_t cache_affinity = static_cast<std::int64_t>(std::min<std::uint64_t>(worker.cache_affinity_hits, 500)) * 4;
    const std::int64_t evidence_freshness = worker.trusted_evidence_fresh ? 250 : 0;
    const std::int64_t trust = worker.capabilities.trusted ? 100 : 0;

    const std::uint64_t completed = worker.completed_units == 0 ? 1 : worker.completed_units;
    const std::int64_t historical_cost =
        -static_cast<std::int64_t>(std::min<std::uint64_t>(worker.total_compile_millis / completed, 600000) / 100);
    const std::int64_t expected_cost = -static_cast<std::int64_t>(std::min<std::uint64_t>(estimated_cost_millis, 600000) / 100);

    const std::int64_t queue_penalty = -static_cast<std::int64_t>(worker.queue_depth) * 300;
    const std::int64_t inflight_penalty = -static_cast<std::int64_t>(worker.in_flight) * 600;
    const std::int64_t cores_bonus = static_cast<std::int64_t>(std::min<std::uint32_t>(worker.capabilities.logical_cores, 256)) * 5;
    const std::int64_t memory_bonus =
        static_cast<std::int64_t>(std::min<std::uint64_t>(worker.capabilities.memory_bytes >> 30, 1024));

    entry.factors.push_back({"locality", locality});
    entry.factors.push_back({"cache_affinity", cache_affinity});
    entry.factors.push_back({"evidence_freshness", evidence_freshness});
    entry.factors.push_back({"trust", trust});
    entry.factors.push_back({"historical_cost", historical_cost});
    entry.factors.push_back({"expected_cost", expected_cost});
    entry.factors.push_back({"queue_depth", queue_penalty});
    entry.factors.push_back({"in_flight", inflight_penalty});
    entry.factors.push_back({"logical_cores", cores_bonus});
    entry.factors.push_back({"memory_gib", memory_bonus});

    std::int64_t score = 0;
    for (const auto& factor : entry.factors) score += factor.value;
    entry.score = score;
    ranked.push_back(std::move(entry));
  }

  std::sort(ranked.begin(), ranked.end(), [](const RankedWorker& a, const RankedWorker& b) {
    if (a.score != b.score) return a.score > b.score;
    if (a.id != b.id) return a.id < b.id;
    if (a.boot != b.boot) return a.boot < b.boot;
    return a.generation < b.generation;
  });
  return ranked;
}

// ---------------------------------------------------------------------------
// Authority validation
// ---------------------------------------------------------------------------
Status validate_authority(const AuthorityClaim& claim, const AuthorityExpectation& expected) {
  if (claim.epoch != expected.epoch) {
    return Status::error(ErrorCode::StaleEpoch, "coordinator epoch moved from " +
                                                    std::to_string(claim.epoch.value()) + " to " +
                                                    std::to_string(expected.epoch.value()));
  }
  if (claim.compilation != expected.compilation) {
    return Status::error(ErrorCode::StaleCompilation, "compilation identity mismatch");
  }
  if (claim.compilation_generation != expected.compilation_generation) {
    return Status::error(ErrorCode::StaleCompilation, "compilation generation moved from " +
                                                          std::to_string(claim.compilation_generation.value()) +
                                                          " to " +
                                                          std::to_string(expected.compilation_generation.value()));
  }
  if (claim.unit != expected.unit) {
    return Status::error(ErrorCode::StaleCompilation, "compilation unit mismatch");
  }
  if (claim.unit_generation != expected.unit_generation) {
    return Status::error(ErrorCode::StaleCompilation, "compilation unit generation mismatch");
  }
  if (claim.attempt != expected.attempt) {
    return Status::error(ErrorCode::StaleAttempt, "attempt identity mismatch");
  }
  if (claim.attempt_generation != expected.attempt_generation) {
    return Status::error(ErrorCode::StaleAttempt, "attempt generation moved from " +
                                                      std::to_string(claim.attempt_generation.value()) + " to " +
                                                      std::to_string(expected.attempt_generation.value()));
  }
  if (claim.worker != expected.worker) {
    return Status::error(ErrorCode::StaleWorkerGeneration, "worker identity mismatch");
  }
  if (claim.worker_boot != expected.worker_boot) {
    return Status::error(ErrorCode::StaleWorkerBoot, "worker boot identity moved");
  }
  if (claim.worker_generation != expected.worker_generation) {
    return Status::error(ErrorCode::StaleWorkerGeneration, "worker generation moved from " +
                                                               std::to_string(claim.worker_generation.value()) +
                                                               " to " +
                                                               std::to_string(expected.worker_generation.value()));
  }
  if (claim.lease != expected.lease) {
    return Status::error(ErrorCode::StaleLease, "lease identity mismatch");
  }
  if (claim.lease_generation != expected.lease_generation) {
    return Status::error(ErrorCode::StaleLease, "lease generation moved from " +
                                                    std::to_string(claim.lease_generation.value()) + " to " +
                                                    std::to_string(expected.lease_generation.value()));
  }
  if (claim.source_generation != expected.source_generation) {
    return Status::error(ErrorCode::StaleSource, "source generation moved from " +
                                                     std::to_string(claim.source_generation.value()) + " to " +
                                                     std::to_string(expected.source_generation.value()));
  }
  if (claim.ir_generation != expected.ir_generation) {
    return Status::error(ErrorCode::StaleIR, "IR generation moved");
  }
  if (claim.dependency_generation != expected.dependency_generation) {
    return Status::error(ErrorCode::StaleDependencies,
                         "dependency generation moved from " +
                             std::to_string(claim.dependency_generation.value()) + " to " +
                             std::to_string(expected.dependency_generation.value()));
  }
  if (claim.toolchain_generation != expected.toolchain_generation) {
    return Status::error(ErrorCode::StaleToolchain, "toolchain generation moved from " +
                                                        std::to_string(claim.toolchain_generation.value()) +
                                                        " to " +
                                                        std::to_string(expected.toolchain_generation.value()));
  }
  if (claim.target_generation != expected.target_generation) {
    return Status::error(ErrorCode::StaleTarget, "target generation moved");
  }
  if (claim.specialization_generation != expected.specialization_generation) {
    return Status::error(ErrorCode::StaleSpecialization, "specialization generation moved");
  }
  if (claim.policy_generation != expected.policy_generation) {
    return Status::error(ErrorCode::StalePolicy, "policy generation moved");
  }
  if (claim.cache_generation != expected.cache_generation) {
    return Status::error(ErrorCode::StaleCache, "cache generation moved");
  }
  if (claim.request_identity != expected.request_identity) {
    return Status::error(ErrorCode::StaleRequest, "request identity mismatch");
  }
  if (claim.unit_identity != expected.unit_identity) {
    return Status::error(ErrorCode::StaleCompilation, "unit identity mismatch");
  }
  return Status::success();
}

void write_authority_claim(CanonicalWriter& w, const AuthorityClaim& claim) {
  w.domain("dc.authority-claim.v1");
  w.gen(claim.epoch);
  w.id(claim.compilation);
  w.gen(claim.compilation_generation);
  w.id(claim.unit);
  w.gen(claim.unit_generation);
  w.id(claim.attempt);
  w.gen(claim.attempt_generation);
  w.id(claim.worker);
  w.id(claim.worker_boot);
  w.gen(claim.worker_generation);
  w.id(claim.lease);
  w.gen(claim.lease_generation);
  w.gen(claim.source_generation);
  w.gen(claim.ir_generation);
  w.gen(claim.dependency_generation);
  w.gen(claim.toolchain_generation);
  w.gen(claim.target_generation);
  w.gen(claim.specialization_generation);
  w.gen(claim.policy_generation);
  w.gen(claim.cache_generation);
  w.digest(claim.request_identity);
  w.digest(claim.unit_identity);
}

bool read_authority_claim(CanonicalReader& r, AuthorityClaim& out) {
  AuthorityClaim claim;
  if (!r.read_domain("dc.authority-claim.v1")) return false;
  if (!r.read_gen(claim.epoch)) return false;
  if (!r.read_id(claim.compilation)) return false;
  if (!r.read_gen(claim.compilation_generation)) return false;
  if (!r.read_id(claim.unit)) return false;
  if (!r.read_gen(claim.unit_generation)) return false;
  if (!r.read_id(claim.attempt)) return false;
  if (!r.read_gen(claim.attempt_generation)) return false;
  if (!r.read_id(claim.worker)) return false;
  if (!r.read_id(claim.worker_boot)) return false;
  if (!r.read_gen(claim.worker_generation)) return false;
  if (!r.read_id(claim.lease)) return false;
  if (!r.read_gen(claim.lease_generation)) return false;
  if (!r.read_gen(claim.source_generation)) return false;
  if (!r.read_gen(claim.ir_generation)) return false;
  if (!r.read_gen(claim.dependency_generation)) return false;
  if (!r.read_gen(claim.toolchain_generation)) return false;
  if (!r.read_gen(claim.target_generation)) return false;
  if (!r.read_gen(claim.specialization_generation)) return false;
  if (!r.read_gen(claim.policy_generation)) return false;
  if (!r.read_gen(claim.cache_generation)) return false;
  if (!r.read_digest(claim.request_identity)) return false;
  if (!r.read_digest(claim.unit_identity)) return false;
  out = claim;
  return true;
}

}  // namespace dc
