// Distributed Compilation - coordinator: compilation authority and artifact commit authority.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// The coordinator is the only component that may decide that a compilation
// result is authoritative. It serialises every authority transition behind one
// mutex, so "exactly one authoritative commit" is a property of the state
// machine rather than of timing.
//
// I/O that must not run under the lock (artifact digesting, blob storage,
// smoke-test execution) is performed between a *reservation* and a
// *revalidation*: the attempt is moved to Produced under the lock, the work is
// done unlocked, and the full authority claim is re-checked before commit. A
// generation that moved during the unlocked window refuses the commit.
#ifndef DC_COORDINATOR_HPP
#define DC_COORDINATOR_HPP

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "dc/model.hpp"
#include "dc/persistence.hpp"
#include "dc/runtime.hpp"
#include "dc/types.hpp"

namespace dc {

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------
class Clock {
 public:
  virtual ~Clock() = default;
  virtual UnixMillis now() const = 0;
};

class SystemClock final : public Clock {
 public:
  UnixMillis now() const override;
};

// Deterministic clock used by tests and benchmarks so that time never
// influences an identity or a decision.
class ManualClock final : public Clock {
 public:
  explicit ManualClock(UnixMillis start = 1700000000000LL);
  UnixMillis now() const override;
  void advance(UnixMillis delta);
  void set(UnixMillis value);

 private:
  std::atomic<UnixMillis> value_;
};

// ---------------------------------------------------------------------------
// Configuration and transfer records
// ---------------------------------------------------------------------------
struct CoordinatorConfig {
  std::filesystem::path state_root;
  std::string host_name = "local";
  bool fsync_records = true;
  bool enable_persistence = true;
  std::uint64_t max_bundle_bytes = 256ull * 1024 * 1024;
  std::uint64_t max_blob_bytes = 128ull * 1024 * 1024;
  std::uint64_t max_artifact_bytes = 128ull * 1024 * 1024;
  std::uint32_t max_units = 4096;
  std::uint32_t max_workers = 4096;
  std::uint32_t max_inflight_per_worker = 8;
  std::uint32_t max_attempts_hard_cap = 16;
  std::uint64_t snapshot_every_records = 16384;
  std::uint64_t max_compile_millis = 600000;
  std::shared_ptr<Clock> clock;
};

struct SubmissionBundle {
  CompilationRequest request;
  std::vector<Blob> blobs;
  bool dry_run = false;
  bool force_rebuild = false;
  bool speculative = false;
};

struct UnitSubmission {
  std::uint32_t index = 0;
  CompilationId compilation;
  CompilationUnitId unit;
  UnitGeneration unit_generation;
  Digest256 unit_identity;
  CompilationState state = CompilationState::Pending;
  CacheDecision cache;
  bool committed = false;
  ArtifactCommit commit;
  bool scheduled = false;
  std::string detail;
};

struct SubmissionResult {
  RequestId request_id;
  Digest256 request_identity;
  std::vector<UnitSubmission> units;
  bool all_committed = false;
  bool served_from_cache = false;
  bool duplicate_request = false;
};

struct AssignmentSource {
  std::string logical_name;
  InputFormat format = InputFormat::Unknown;
  std::string language_mode;
  std::vector<std::byte> bytes;
};

struct AssignmentDependency {
  std::string name;
  DependencyKind kind = DependencyKind::Other;
  std::vector<std::byte> bytes;
};

struct AssignmentChild {
  std::string logical_name;
  OutputKind kind = OutputKind::Object;
  std::vector<std::byte> bytes;
};

struct Assignment {
  SessionId session;
  WorkerId worker;
  WorkerBootId worker_boot;
  WorkerGeneration worker_generation;
  CompileLease lease;
  AuthorityClaim claim;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  CompilationUnitId unit;
  UnitGeneration unit_generation;
  CompilationAttemptId attempt;
  CompilationAttemptGeneration attempt_generation;
  std::uint32_t unit_index = 0;
  UnitKind kind = UnitKind::Compile;
  OutputKind output_kind = OutputKind::Object;
  std::string logical_name;
  std::vector<AssignmentSource> sources;
  std::vector<AssignmentDependency> dependencies;
  std::vector<std::string> flags;
  std::vector<AssignmentChild> children;
  ToolchainIdentity toolchain;
  TargetIdentity target;
  SpecializationSpec specialization;
  CompilePolicy policy;
  EnvironmentContract environment;
  ValidationRequirements validation;
  std::uint64_t max_compile_millis = 600000;
  bool speculative = false;
};

struct ReportOutput {
  AuthorityClaim claim;
  OutputKind kind = OutputKind::Object;
  std::string logical_name;
  std::vector<std::byte> bytes;
  Digest256 declared_digest;
  ValidationReport worker_validation;
  std::string compiler_invocation;
  std::string compiler_version_string;
  std::uint64_t compiler_wall_millis = 0;
  int exit_code = 0;
};

enum class CommitOutcome : std::uint8_t {
  Committed = 0,
  Deduplicated = 1,
  Refused = 2,
  ReproducibilityViolation = 3,
};

std::string_view to_string(CommitOutcome value) noexcept;

struct CommitDecision {
  CommitOutcome outcome = CommitOutcome::Refused;
  ErrorCode error = ErrorCode::Ok;
  std::string detail;
  ArtifactCommit commit;
  ValidationReport validation;
  bool artifact_authoritative = false;
};

struct AttemptFailure {
  AuthorityClaim claim;
  ErrorCode code = ErrorCode::Internal;
  std::string detail;
  bool produced_candidate = false;
};

enum class ControlKind : std::uint8_t { CancelAttempt = 0, CommitNotification = 1, Shutdown = 2 };

std::string_view to_string(ControlKind value) noexcept;

struct ControlMessage {
  SessionId session;
  ControlKind kind = ControlKind::CancelAttempt;
  CompilationId compilation;
  CompilationGeneration compilation_generation;
  CompilationAttemptId attempt;
  CompilationAttemptGeneration attempt_generation;
  LeaseId lease;
  LeaseGeneration lease_generation;
  ArtifactCommitId commit;
  Digest256 artifact_digest;
  std::string reason;
};

struct WorkerRegistration {
  std::string endpoint;
  std::string host;
  WorkerId worker_id;
  WorkerBootId boot_id;
  WorkerCapabilities capabilities;
  std::uint32_t max_inflight = 4;
};

struct RegisteredWorker {
  SessionId session;
  WorkerId worker;
  WorkerBootId boot;
  WorkerGeneration generation;
  CoordinatorEpoch epoch;
  std::string detail;
};

struct WorkerIneligibility {
  WorkerId worker;
  std::string reason;
  std::string detail;
};

struct EligibilityReport {
  std::uint32_t total_workers = 0;
  std::uint32_t eligible_workers = 0;
  HardRequirements requirements;
  std::vector<WorkerIneligibility> ineligible;
  std::vector<RankedWorker> ranked;
};

struct AuthorityViolation {
  UnixMillis at = 0;
  std::string operation;
  ErrorCode code = ErrorCode::Ok;
  SessionId session;
  WorkerId worker;
  std::string detail;
};

struct AuditFinding {
  std::string invariant;
  std::string detail;
  CompilationId compilation;
};

struct AuditReport {
  std::uint64_t compilations = 0;
  std::uint64_t committed = 0;
  std::uint64_t attempts = 0;
  std::uint64_t workers = 0;
  std::uint64_t leases = 0;
  std::uint64_t cache_entries = 0;
  std::uint64_t provenances = 0;
  std::uint64_t violations = 0;
  std::vector<AuditFinding> findings;
  bool clean = false;

  std::string render() const;
};

struct ExplainReport {
  std::vector<std::string> lines;
  std::string render() const;
};

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------
class Coordinator {
 public:
  Coordinator();
  ~Coordinator();

  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;

  Status open(const CoordinatorConfig& config);
  void close();
  bool is_open() const noexcept;

  CoordinatorEpoch epoch() const;
  RecoveryReport recovery() const;
  const CoordinatorConfig& config() const noexcept;

  // --- client operations -------------------------------------------------
  Result<SubmissionResult> submit(const SubmissionBundle& bundle);
  Result<CacheDecision> cache_query(const Digest256& unit_identity) const;
  Result<CompilationRecord> compilation(CompilationId id) const;
  Result<ArtifactCommit> commit(CompilationId id) const;
  Result<Provenance> provenance(ProvenanceId id) const;
  Result<ValidationReport> validation(ValidationId id) const;
  Result<JobRecord> job(const Digest256& request_identity) const;
  Result<CompilationRequest> request(const Digest256& request_identity) const;
  Result<CompilationAttempt> attempt(CompilationAttemptId id) const;
  Result<std::vector<std::byte>> artifact_bytes(CompilationId id) const;
  EligibilityReport eligibility(const CompilationRequest& request) const;
  AuditReport audit() const;
  ExplainReport explain(CompilationId id) const;
  Status snapshot();
  Status cancel(CompilationId id, const std::string& reason);

  std::vector<WorkerRecord> workers() const;
  std::vector<CompilationRecord> compilations() const;
  std::vector<CompilationAttempt> attempts() const;
  std::vector<ArtifactCommit> commits() const;
  std::vector<Provenance> provenances() const;
  std::vector<CacheEntry> cache_entries() const;
  std::vector<NegativeCacheEntry> negative_cache_entries() const;
  std::vector<IntermediateArtifact> intermediates() const;
  std::vector<CompileLease> leases() const;
  std::vector<AuthorityViolation> violations() const;

  // --- worker operations -------------------------------------------------
  Result<RegisteredWorker> register_worker(const WorkerRegistration& registration);
  Status advertise_capabilities(SessionId session, const WorkerCapabilities& capabilities);
  Status mark_ready(SessionId session);
  Status heartbeat(SessionId session);
  Status begin_compile(const AuthorityClaim& claim);
  Result<CommitDecision> report_output(SessionId session, const ReportOutput& output);
  Status fail_attempt(SessionId session, const AttemptFailure& failure);
  Status disconnect_session(SessionId session, const std::string& reason);
  Status shutdown_sessions();

  // --- scheduling --------------------------------------------------------
  std::vector<Assignment> pump();
  std::vector<ControlMessage> drain_controls();
  const ArtifactCommit* authoritative_commit(CompilationId id) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Derives the hard requirements that decide eligibility for one unit.
HardRequirements derive_requirements(const CompilationRequest& request, const CompilationUnitSpec& unit,
                                     const CoordinatorConfig& config);

// Validates candidate artifact bytes against the expected kind and target.
// This never trusts a compiler exit code: it inspects the produced bytes.
// Smoke-test execution is performed separately by the caller, because it needs
// process management and must not run under the coordinator lock.
ValidationReport validate_artifact_bytes(std::span<const std::byte> bytes, OutputKind kind,
                                         const TargetIdentity& target,
                                         const ValidationRequirements& requirements,
                                         const Digest256& expected_digest);

// Executes a produced executable in a scratch directory and compares stdout.
// Used for the optional smoke-test requirement; never used to derive identity.
ValidationCheck run_smoke_test(const std::filesystem::path& executable, std::string_view expected_stdout,
                               std::uint32_t timeout_millis);

}  // namespace dc

#endif  // DC_COORDINATOR_HPP
