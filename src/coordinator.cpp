// Distributed Compilation - coordinator lifecycle, registries, cache and audit.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <algorithm>
#include <chrono>
#include <cstring>

#include "coordinator_impl.hpp"
#include "dc/codec.hpp"
#include "dc/process.hpp"

namespace dc {

void mark_capabilities_unknown(WorkerRecord& worker) {
  worker.capabilities.evidence = EvidenceClass::Unknown;
  canonicalize(worker.capabilities);
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------
UnixMillis SystemClock::now() const {
  using namespace std::chrono;
  return static_cast<UnixMillis>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

ManualClock::ManualClock(UnixMillis start) : value_(start) {}

UnixMillis ManualClock::now() const { return value_.load(); }
void ManualClock::advance(UnixMillis delta) { value_.fetch_add(delta); }
void ManualClock::set(UnixMillis value) { value_.store(value); }

std::string_view to_string(CommitOutcome value) noexcept {
  switch (value) {
    case CommitOutcome::Committed: return "COMMITTED";
    case CommitOutcome::Deduplicated: return "DEDUPLICATED";
    case CommitOutcome::Refused: return "REFUSED";
    case CommitOutcome::ReproducibilityViolation: return "REPRODUCIBILITY_VIOLATION";
  }
  return "REFUSED";
}

std::string_view to_string(ControlKind value) noexcept {
  switch (value) {
    case ControlKind::CancelAttempt: return "CANCEL_ATTEMPT";
    case ControlKind::CommitNotification: return "COMMIT_NOTIFICATION";
    case ControlKind::Shutdown: return "SHUTDOWN";
  }
  return "CANCEL_ATTEMPT";
}

std::string AuditReport::render() const {
  std::string out;
  out += "compilations=" + std::to_string(compilations) + "\n";
  out += "committed=" + std::to_string(committed) + "\n";
  out += "attempts=" + std::to_string(attempts) + "\n";
  out += "workers=" + std::to_string(workers) + "\n";
  out += "leases=" + std::to_string(leases) + "\n";
  out += "cache_entries=" + std::to_string(cache_entries) + "\n";
  out += "provenances=" + std::to_string(provenances) + "\n";
  out += "violations=" + std::to_string(violations) + "\n";
  out += "findings=" + std::to_string(findings.size()) + "\n";
  for (const auto& finding : findings) {
    out += "  [" + finding.invariant + "] " + finding.detail + "\n";
  }
  out += std::string("clean=") + (clean ? "true" : "false") + "\n";
  return out;
}

std::string ExplainReport::render() const {
  std::string out;
  for (const auto& line : lines) {
    out += line;
    out += "\n";
  }
  return out;
}

// ---------------------------------------------------------------------------
// Hard requirements
// ---------------------------------------------------------------------------
HardRequirements derive_requirements(const CompilationRequest& request, const CompilationUnitSpec& unit,
                                     const CoordinatorConfig& config) {
  HardRequirements requirements;
  requirements.toolchain_identity = request.toolchain.identity_digest;
  requirements.target_identity = request.target.identity_digest;
  requirements.require_provable_toolchain = request.policy.require_provable_toolchain;
  requirements.require_trusted = request.policy.require_trusted_workers;
  requirements.require_deterministic_build =
      request.policy.reproducibility == ReproducibilityRequirement::Required;

  for (const auto& source : unit.sources) requirements.required_formats.push_back(source.format);
  for (const auto& dep : unit.dependencies) {
    if (dep.kind == DependencyKind::CompilerPlugin) {
      requirements.required_plugins.push_back(dep.name);
    }
    if (dep.kind == DependencyKind::RuntimeLibrary || dep.kind == DependencyKind::DeviceLibrary) {
      requirements.required_formats.push_back(InputFormat::Object);
    }
  }
  std::sort(requirements.required_formats.begin(), requirements.required_formats.end());
  requirements.required_formats.erase(
      std::unique(requirements.required_formats.begin(), requirements.required_formats.end()),
      requirements.required_formats.end());

  // A worker must be able to hold the largest artifact this unit can produce.
  requirements.min_max_artifact_bytes = 0;
  (void)config;
  return requirements;
}

// ---------------------------------------------------------------------------
// Impl helpers
// ---------------------------------------------------------------------------
Status Coordinator::Impl::persist(RecordType type, const std::vector<std::byte>& payload) {
  if (!config.enable_persistence) return Status::success();
  Status status = store.append(type, std::span<const std::byte>(payload.data(), payload.size()));
  if (!status.ok()) return status;
  ++persisted_records;
  ++state.header.records_since_snapshot;
  return Status::success();
}

Status Coordinator::Impl::persist_entity(RecordType type, const std::vector<std::byte>& payload) {
  Status status = persist(type, payload);
  if (!status.ok()) return status;
  maybe_snapshot();
  return Status::success();
}

void Coordinator::Impl::maybe_snapshot() {
  if (!config.enable_persistence) return;
  if (config.snapshot_every_records == 0) return;
  if (state.header.records_since_snapshot < config.snapshot_every_records) return;
  std::vector<std::byte> encoded;
  if (!encode_state(state, encoded).ok()) return;
  if (!store.write_snapshot(std::span<const std::byte>(encoded.data(), encoded.size())).ok()) return;
  state.header.records_since_snapshot = 0;
}

Status Coordinator::Impl::store_blob(const std::vector<std::byte>& bytes) {
  const Digest256 digest = sha256(std::span<const std::byte>(bytes.data(), bytes.size()));
  if (bytes.size() > config.max_blob_bytes) {
    return Status::error(ErrorCode::LimitExceeded, "blob exceeds the configured bound");
  }
  if (config.enable_persistence && !store.has_blob(digest)) {
    Result<Digest256> put = store.put_blob(std::span<const std::byte>(bytes.data(), bytes.size()));
    if (!put.ok()) return put.status();
  }
  auto existing = blob_cache.find(digest);
  if (existing == blob_cache.end()) {
    if (bytes.size() <= blob_cache_limit) {
      blob_cache_order.push_back(digest);
      blob_cache.emplace(digest, bytes);
      blob_cache_bytes += bytes.size();
      while (blob_cache_bytes > blob_cache_limit && !blob_cache_order.empty()) {
        const Digest256 victim = blob_cache_order.front();
        blob_cache_order.pop_front();
        auto found = blob_cache.find(victim);
        if (found == blob_cache.end()) continue;
        blob_cache_bytes -= found->second.size();
        blob_cache.erase(found);
      }
    }
  }
  return Status::success();
}

Result<std::vector<std::byte>> Coordinator::Impl::load_blob(const Digest256& digest) {
  auto cached = blob_cache.find(digest);
  if (cached != blob_cache.end()) {
    return Result<std::vector<std::byte>>(cached->second);
  }
  if (!config.enable_persistence) {
    return Result<std::vector<std::byte>>(
        Status::error(ErrorCode::ArtifactMissing, "artifact is not present in memory"));
  }
  std::vector<std::byte> bytes;
  Status status = store.get_blob(digest, bytes);
  if (!status.ok()) return Result<std::vector<std::byte>>(status);
  if (bytes.size() > config.max_blob_bytes) {
    return Result<std::vector<std::byte>>(
        Status::error(ErrorCode::LimitExceeded, "stored blob exceeds the configured bound"));
  }
  if (bytes.size() <= blob_cache_limit) {
    blob_cache_order.push_back(digest);
    blob_cache_bytes += bytes.size();
    blob_cache.emplace(digest, bytes);
    while (blob_cache_bytes > blob_cache_limit && !blob_cache_order.empty()) {
      const Digest256 victim = blob_cache_order.front();
      blob_cache_order.pop_front();
      auto found = blob_cache.find(victim);
      if (found == blob_cache.end()) continue;
      blob_cache_bytes -= found->second.size();
      blob_cache.erase(found);
    }
  }
  return Result<std::vector<std::byte>>(std::move(bytes));
}

bool Coordinator::Impl::has_blob(const Digest256& digest) const {
  if (blob_cache.count(digest) != 0) return true;
  if (!config.enable_persistence) return false;
  return store.has_blob(digest);
}

const CompilationRequest* Coordinator::Impl::find_request(const Digest256& identity) const {
  auto found = state.requests.find(identity);
  if (found == state.requests.end()) return nullptr;
  return &found->second;
}

const detail::SessionRecord* Coordinator::Impl::find_session(SessionId id) const {
  auto found = state.sessions.find(id);
  if (found == state.sessions.end()) return nullptr;
  return &found->second;
}

WorkerRecord* Coordinator::Impl::find_worker(WorkerId id) {
  auto found = state.workers.find(id);
  if (found == state.workers.end()) return nullptr;
  return &found->second;
}

const WorkerRecord* Coordinator::Impl::find_worker(WorkerId id) const {
  auto found = state.workers.find(id);
  if (found == state.workers.end()) return nullptr;
  return &found->second;
}

void Coordinator::Impl::record_violation(std::string operation, ErrorCode code, SessionId session,
                                         WorkerId worker, std::string detail) {
  if (state.violations.size() > 4096) return;   // bounded: violations are diagnostic
  AuthorityViolation violation;
  violation.at = now();
  violation.operation = std::move(operation);
  violation.code = code;
  violation.session = session;
  violation.worker = worker;
  violation.detail = std::move(detail);
  state.violations.push_back(std::move(violation));
}

AuthorityExpectation Coordinator::Impl::expectation_for(const CompilationRecord& compilation,
                                                        const CompilationAttempt& attempt) const {
  AuthorityExpectation expected;
  expected.epoch = state.header.epoch;
  expected.compilation = compilation.id;
  expected.compilation_generation = compilation.generation;
  expected.unit = compilation.unit;
  expected.unit_generation = compilation.unit_generation;
  expected.attempt = attempt.id;
  expected.attempt_generation = attempt.generation;
  expected.worker = attempt.worker;
  expected.worker_boot = attempt.worker_boot;
  expected.worker_generation = attempt.worker_generation;
  expected.lease = attempt.lease;
  expected.lease_generation = attempt.lease_generation;
  expected.source_generation = compilation.source_generation;
  expected.ir_generation = compilation.ir_generation;
  expected.dependency_generation = compilation.dependency_generation;
  expected.toolchain_generation = compilation.toolchain_generation;
  expected.target_generation = compilation.target_generation;
  expected.specialization_generation = compilation.specialization_generation;
  expected.policy_generation = compilation.policy_generation;
  expected.cache_generation = state.header.cache_generation;
  expected.request_identity = compilation.request_identity;
  expected.unit_identity = compilation.unit_identity;
  return expected;
}

HardRequirements Coordinator::Impl::requirements_for(const CompilationRecord& compilation) const {
  HardRequirements requirements;
  requirements.toolchain_identity = compilation.toolchain_identity;
  requirements.target_identity = compilation.target_identity;
  const CompilationRequest* request = find_request(compilation.request_identity);
  if (request == nullptr) {
    requirements.require_provable_toolchain = true;
    return requirements;
  }
  const CompilationUnitSpec* unit = request->find_unit(compilation.unit_index);
  if (unit == nullptr) return requirements;
  HardRequirements derived = derive_requirements(*request, *unit, config);
  derived.toolchain_identity = compilation.toolchain_identity;
  derived.target_identity = compilation.target_identity;
  return derived;
}

std::vector<WorkerRecord> Coordinator::Impl::eligible_workers(const HardRequirements& requirements,
                                                              const std::vector<CompilationId>& busy) const {
  std::vector<WorkerRecord> eligible;
  for (const auto& kv : state.workers) {
    const WorkerRecord& worker = kv.second;
    if (worker.session.is_zero()) continue;
    const detail::SessionRecord* session = find_session(worker.session);
    if (session == nullptr || !session->open) continue;
    if (!busy.empty()) {
      // A worker already bound to one of the given compilations is not a
      // candidate for a speculative duplicate of the same work.
      bool conflict = false;
      for (CompilationId compilation : busy) {
        for (const auto& attempt_kv : state.attempts) {
          const CompilationAttempt& attempt = attempt_kv.second;
          if (attempt.compilation == compilation && attempt.worker == worker.id &&
              holds_commit_authority(attempt.state)) {
            conflict = true;
            break;
          }
        }
        if (conflict) break;
      }
      if (conflict) continue;
    }
    if (worker.in_flight >= session->max_inflight) continue;
    if (evaluate_eligibility(worker, requirements).eligible) eligible.push_back(worker);
  }
  return eligible;
}

void Coordinator::Impl::touch_cache_entry(CacheEntry& entry) {
  if (entry.hit_count < 0xFFFFFFFFu) ++entry.hit_count;
  std::vector<std::byte> payload;
  CanonicalWriter w;
  encode_cache_entry(w, entry);
  payload.assign(w.bytes().begin(), w.bytes().end());
  (void)persist(RecordType::CacheEntry, payload);
}

CacheDecision Coordinator::Impl::evaluate_cache_metadata(const CompilationRecord& compilation,
                                                         const CacheEntry& entry) const {
  CacheDecision decision;
  decision.entry = entry.id;
  const auto mismatch = [&decision](std::string dimension, std::string expected, std::string actual) {
    decision.mismatches.push_back(CacheMismatch{std::move(dimension), std::move(expected), std::move(actual)});
  };

  if (entry.invalidated) {
    decision.outcome = CacheOutcome::Stale;
    decision.reason = "cache entry was explicitly invalidated: " + entry.invalidation_reason;
    mismatch("invalidated", "false", "true");
    return decision;
  }
  if (entry.unit_identity != compilation.unit_identity) {
    decision.outcome = CacheOutcome::Incompatible;
    decision.reason = "cache entry belongs to a different unit identity";
    mismatch("unit_identity", compilation.unit_identity.hex(), entry.unit_identity.hex());
    return decision;
  }
  if (entry.source_identity != compilation.source_identity) {
    decision.outcome = CacheOutcome::Stale;
    decision.reason = "source generation content changed since this cache entry was produced";
    mismatch("source_identity", compilation.source_identity.hex(), entry.source_identity.hex());
    return decision;
  }
  if (entry.dependency_identity != compilation.dependency_identity) {
    decision.outcome = CacheOutcome::Stale;
    decision.reason = "dependency content changed since this cache entry was produced";
    mismatch("dependency_identity", compilation.dependency_identity.hex(), entry.dependency_identity.hex());
    return decision;
  }
  if (entry.toolchain_identity != compilation.toolchain_identity) {
    decision.outcome = CacheOutcome::Stale;
    decision.reason = "toolchain identity changed since this cache entry was produced";
    mismatch("toolchain_identity", compilation.toolchain_identity.hex(), entry.toolchain_identity.hex());
    return decision;
  }
  if (entry.target_identity != compilation.target_identity) {
    decision.outcome = CacheOutcome::Stale;
    decision.reason = "target identity changed since this cache entry was produced";
    mismatch("target_identity", compilation.target_identity.hex(), entry.target_identity.hex());
    return decision;
  }
  if (entry.specialization_identity != compilation.specialization_identity) {
    decision.outcome = CacheOutcome::Stale;
    decision.reason = "specialization changed since this cache entry was produced";
    mismatch("specialization_identity", compilation.specialization_identity.hex(),
             entry.specialization_identity.hex());
    return decision;
  }
  if (entry.policy_identity != compilation.policy_identity) {
    decision.outcome = CacheOutcome::Stale;
    decision.reason = "compile policy changed since this cache entry was produced";
    mismatch("policy_identity", compilation.policy_identity.hex(), entry.policy_identity.hex());
    return decision;
  }
  if (entry.environment_identity != compilation.environment_identity) {
    decision.outcome = CacheOutcome::Incompatible;
    decision.reason = "compile environment contract changed";
    mismatch("environment_identity", compilation.environment_identity.hex(), entry.environment_identity.hex());
    return decision;
  }
  if (entry.toolchain_generation != compilation.toolchain_generation) {
    decision.generation_drift = true;
  }
  if (entry.target_generation != compilation.target_generation) decision.generation_drift = true;
  decision.outcome = CacheOutcome::Reusable;
  decision.reason = "cache entry matches every identity dimension";
  return decision;
}

CacheDecision Coordinator::Impl::evaluate_cache_blob(const CompilationRecord& compilation,
                                                     const CacheEntry& entry, bool blob_ok) const {
  CacheDecision decision = evaluate_cache_metadata(compilation, entry);
  if (!decision.reusable()) return decision;
  if (!blob_ok) {
    decision.outcome = CacheOutcome::Corrupt;
    decision.reason = "cached artifact is missing or does not match its digest";
    decision.mismatches.push_back(CacheMismatch{"artifact", entry.artifact.digest.hex(), "missing"});
    return decision;
  }
  return decision;
}

void Coordinator::Impl::record_cache_entry(const CompilationRecord& compilation, const ArtifactCommit& commit,
                                           const Provenance& provenance, const ValidationReport& validation) {
  (void)validation;
  CacheEntry entry;
  entry.id = CacheEntryId(state.header.next_cache_entry_id++);
  entry.generation = state.header.cache_generation;
  entry.unit_identity = compilation.unit_identity;
  entry.compilation = compilation.id;
  entry.compilation_generation = compilation.generation;
  entry.artifact = provenance.artifact;
  entry.artifact_id = commit.artifact;
  entry.provenance = provenance.id;
  entry.validation = commit.validation;
  entry.source_identity = compilation.source_identity;
  entry.dependency_identity = compilation.dependency_identity;
  entry.toolchain_identity = compilation.toolchain_identity;
  entry.toolchain_generation = compilation.toolchain_generation;
  entry.target_identity = compilation.target_identity;
  entry.target_generation = compilation.target_generation;
  entry.specialization_identity = compilation.specialization_identity;
  entry.policy_identity = compilation.policy_identity;
  entry.environment_identity = compilation.environment_identity;
  entry.commit = commit.id;
  entry.created_at = now();

  auto existing = state.cache_index.find(entry.unit_identity);
  if (existing != state.cache_index.end()) {
    auto prior = state.cache_entries.find(existing->second);
    if (prior != state.cache_entries.end()) {
      prior->second.invalidated = true;
      prior->second.invalidation_reason = "superseded by a newer cache generation";
      CanonicalWriter w;
      encode_cache_entry(w, prior->second);
      std::vector<std::byte> payload(w.bytes().begin(), w.bytes().end());
      (void)persist(RecordType::CacheEntry, payload);
    }
  }
  state.cache_index[entry.unit_identity] = entry.id;
  state.cache_entries[entry.id] = entry;

  CanonicalWriter w;
  encode_cache_entry(w, entry);
  std::vector<std::byte> payload(w.bytes().begin(), w.bytes().end());
  (void)persist(RecordType::CacheEntry, payload);
}

void Coordinator::Impl::add_negative_cache_entry(const CompilationRecord& compilation,
                                                 NegativeCacheReason reason, ErrorCode failure,
                                                 std::string diagnostic) {
  const CompilationRequest* request = find_request(compilation.request_identity);
  NegativeCacheEntry entry;
  entry.id = CacheEntryId(state.header.next_cache_entry_id++);
  entry.unit_identity = compilation.unit_identity;
  entry.reason = reason;
  entry.failure = failure;
  entry.diagnostic = std::move(diagnostic);
  entry.toolchain_identity = compilation.toolchain_identity;
  entry.toolchain_generation = compilation.toolchain_generation;
  entry.target_identity = compilation.target_identity;
  entry.target_generation = compilation.target_generation;
  entry.specialization_identity = compilation.specialization_identity;
  entry.policy_identity = compilation.policy_identity;
  entry.created_at = now();
  if (request != nullptr && request->policy.negative_cache_max_entries > 0) {
    while (state.negative_cache.size() >= request->policy.negative_cache_max_entries) {
      state.negative_cache.pop_front();
    }
  }
  state.negative_cache.push_back(entry);
  CanonicalWriter w;
  encode_negative_cache(w, entry);
  std::vector<std::byte> payload(w.bytes().begin(), w.bytes().end());
  (void)persist(RecordType::NegativeCache, payload);
}

Status Coordinator::Impl::transition_attempt(CompilationAttempt& attempt, AttemptState next) {
  if (attempt.state == next) return Status::success();
  if (!is_legal_transition(attempt.state, next)) {
    return Status::error(ErrorCode::IllegalTransition,
                         std::string("attempt ") + std::to_string(attempt.id.value()) + " cannot move from " +
                             std::string(to_string(attempt.state)) + " to " + std::string(to_string(next)));
  }
  attempt.state = next;
  return Status::success();
}

void Coordinator::Impl::finish_attempt_bookkeeping(CompilationAttempt& attempt) {
  attempt.finished_at = now();
  WorkerRecord* worker = find_worker(attempt.worker);
  if (worker != nullptr) {
    if (worker->in_flight > 0) --worker->in_flight;
    if (attempt.state == AttemptState::Committed) {
      ++worker->completed_units;
      worker->total_compile_millis += attempt.compiler_wall_millis;
    } else {
      ++worker->failed_units;
    }
    worker->active_leases.erase(std::remove(worker->active_leases.begin(), worker->active_leases.end(),
                                            attempt.lease),
                                worker->active_leases.end());
    worker->last_seen = now();
  }
  auto lease = state.leases.find(attempt.lease);
  if (lease != state.leases.end()) {
    lease->second.revoked = true;
    if (lease->second.revocation_reason.empty()) {
      lease->second.revocation_reason = "attempt reached " + std::string(to_string(attempt.state));
    }
  }
}

void Coordinator::Impl::enqueue_cancel_losers(const CompilationRecord& compilation,
                                              CompilationAttemptId winner) {
  for (CompilationAttemptId id : compilation.attempts) {
    if (id == winner) continue;
    auto found = state.attempts.find(id);
    if (found == state.attempts.end()) continue;
    CompilationAttempt& other = found->second;
    if (!holds_commit_authority(other.state)) continue;
    ControlMessage control;
    control.session = WorkerRecord{}.session;
    const WorkerRecord* worker = find_worker(other.worker);
    if (worker != nullptr) control.session = worker->session;
    control.kind = ControlKind::CancelAttempt;
    control.compilation = compilation.id;
    control.compilation_generation = compilation.generation;
    control.attempt = other.id;
    control.attempt_generation = other.generation;
    control.lease = other.lease;
    control.lease_generation = other.lease_generation;
    control.reason = "logical compilation already committed by attempt " + std::to_string(winner.value());
    state.controls.push_back(control);
  }
}

void Coordinator::Impl::revoke_leases_for(WorkerId worker, std::string reason) {
  for (auto& kv : state.leases) {
    CompileLease& lease = kv.second;
    if (lease.worker != worker || lease.revoked) continue;
    lease.revoked = true;
    lease.revocation_reason = reason;
  }
}

void Coordinator::Impl::fence_worker(WorkerRecord& worker, std::string reason) {
  worker.fenced = true;
  worker.ready = false;
  worker.health = WorkerHealth::Fenced;
  worker.generation = worker.generation.next();
  worker.in_flight = 0;
  worker.session = SessionId(0);
  worker.active_leases.clear();
  worker.trusted_evidence_fresh = false;
  mark_capabilities_unknown(worker);
  revoke_leases_for(worker.id, reason);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
Coordinator::Coordinator() : impl_(std::make_unique<Impl>()) {}

Coordinator::~Coordinator() { close(); }

bool Coordinator::is_open() const noexcept { return impl_ && impl_->opened; }

const CoordinatorConfig& Coordinator::config() const noexcept { return impl_->config; }

Status Coordinator::open(const CoordinatorConfig& config) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (impl_->opened) return Status::success();
  impl_->config = config;
  impl_->clock = config.clock ? config.clock : std::make_shared<SystemClock>();

  detail::State recovered;
  if (config.enable_persistence) {
    PersistentStore::Options options;
    options.root = config.state_root;
    options.fsync_records = config.fsync_records;
    options.max_snapshot_bytes = 512ull * 1024 * 1024;
    std::vector<JournalRecord> records;
    std::vector<std::byte> snapshot;
    Result<RecoveryReport> opened = impl_->store.open(options, records, snapshot);
    if (!opened.ok()) return opened.status();
    impl_->recovery = opened.value();

    if (!snapshot.empty()) {
      Status decoded = detail::decode_state(std::span<const std::byte>(snapshot.data(), snapshot.size()),
                                            recovered);
      if (!decoded.ok()) {
        return Status::error(ErrorCode::PersistenceCorrupt,
                             "snapshot could not be decoded: " + decoded.detail());
      }
    }

    // Replay: last write wins per entity, applied in journal sequence order.
    for (const auto& record : records) {
      std::span<const std::byte> payload(record.payload.data(), record.payload.size());
      switch (record.type) {
        case RecordType::Worker: {
          WorkerRecord worker;
          CanonicalReader r(payload);
          if (!decode_worker(r, worker)) return Status::error(ErrorCode::PersistenceCorrupt, "journal worker");
          recovered.workers[worker.id] = std::move(worker);
          break;
        }
        case RecordType::Compilation: {
          CompilationRecord compilation;
          CanonicalReader r(payload);
          if (!decode_compilation(r, compilation))
            return Status::error(ErrorCode::PersistenceCorrupt, "journal compilation");
          recovered.compilations[compilation.id] = std::move(compilation);
          break;
        }
        case RecordType::Attempt: {
          CompilationAttempt attempt;
          CanonicalReader r(payload);
          if (!decode_attempt(r, attempt))
            return Status::error(ErrorCode::PersistenceCorrupt, "journal attempt");
          recovered.attempts[attempt.id] = std::move(attempt);
          break;
        }
        case RecordType::Commit: {
          ArtifactCommit commit;
          CanonicalReader r(payload);
          if (!decode_commit(r, commit)) return Status::error(ErrorCode::PersistenceCorrupt, "journal commit");
          recovered.commits[commit.id] = std::move(commit);
          recovered.authoritative[commit.compilation] = commit.id;
          break;
        }
        case RecordType::Provenance: {
          Provenance provenance;
          CanonicalReader r(payload);
          if (!decode_provenance(r, provenance))
            return Status::error(ErrorCode::PersistenceCorrupt, "journal provenance");
          recovered.provenances[provenance.id] = std::move(provenance);
          break;
        }
        case RecordType::Validation: {
          ValidationReport validation;
          CanonicalReader r(payload);
          if (!decode_validation_report(r, validation))
            return Status::error(ErrorCode::PersistenceCorrupt, "journal validation");
          recovered.validations[validation.id] = std::move(validation);
          break;
        }
        case RecordType::CacheEntry: {
          CacheEntry entry;
          CanonicalReader r(payload);
          if (!decode_cache_entry(r, entry)) return Status::error(ErrorCode::PersistenceCorrupt, "journal cache");
          recovered.cache_entries[entry.id] = entry;
          auto existing = recovered.cache_index.find(entry.unit_identity);
          if (existing == recovered.cache_index.end() ||
              entry.generation >= recovered.cache_entries[existing->second].generation) {
            recovered.cache_index[entry.unit_identity] = entry.id;
          }
          break;
        }
        case RecordType::NegativeCache: {
          NegativeCacheEntry entry;
          CanonicalReader r(payload);
          if (!decode_negative_cache(r, entry))
            return Status::error(ErrorCode::PersistenceCorrupt, "journal negative cache");
          recovered.negative_cache.push_back(std::move(entry));
          break;
        }
        case RecordType::Job: {
          JobRecord job;
          if (!detail::decode_job_record(payload, job))
            return Status::error(ErrorCode::PersistenceCorrupt, "journal job");
          recovered.jobs[job.request_identity] = std::move(job);
          break;
        }
        case RecordType::Lease: {
          CompileLease lease;
          CanonicalReader r(payload);
          if (!decode_lease(r, lease)) return Status::error(ErrorCode::PersistenceCorrupt, "journal lease");
          recovered.leases[lease.id] = std::move(lease);
          break;
        }
        case RecordType::Intermediate: {
          IntermediateArtifact artifact;
          CanonicalReader r(payload);
          if (!decode_intermediate(r, artifact))
            return Status::error(ErrorCode::PersistenceCorrupt, "journal intermediate");
          recovered.intermediates[artifact.id] = std::move(artifact);
          break;
        }
        case RecordType::Artifact: {
          CompilationRequest request;
          if (!detail::decode_request_record(payload, request))
            return Status::error(ErrorCode::PersistenceCorrupt, "journal request");
          recovered.requests[request.request_identity] = std::move(request);
          break;
        }
        case RecordType::Header:
        case RecordType::RegistryEntry:
        case RecordType::SchemaInfo:
          break;
      }
    }
  }

  impl_->state = std::move(recovered);
  impl_->opened = true;

  // Coordinator restart: advance the epoch, invalidate every session and lease,
  // fence every worker, and classify in-flight work conservatively.
  impl_->state.header.epoch = impl_->state.header.epoch.is_zero() ? CoordinatorEpoch(1)
                                                                  : impl_->state.header.epoch.next();
  impl_->state.header.opened_at = impl_->now();
  impl_->state.header.restarts += 1;
  impl_->state.sessions.clear();
  impl_->state.controls.clear();
  impl_->state.violations.clear();

  for (auto& kv : impl_->state.workers) {
    WorkerRecord& worker = kv.second;
    const bool ever_registered = !worker.boot.is_zero();
    if (ever_registered) {
      worker.fenced = true;
      worker.ready = false;
      worker.health = WorkerHealth::Fenced;
      worker.in_flight = 0;
      worker.session = SessionId(0);
      worker.active_leases.clear();
      worker.trusted_evidence_fresh = false;
      // Toolchain evidence must be re-established by the restarted worker; a
      // pre-restart advertisement is not proof of what is on disk now.
      mark_capabilities_unknown(worker);
    }
  }
  for (auto& kv : impl_->state.leases) {
    kv.second.revoked = true;
    if (kv.second.revocation_reason.empty()) {
      kv.second.revocation_reason = "coordinator restart advanced the epoch";
    }
  }

  std::size_t ambiguous = 0;
  std::size_t requeued = 0;
  for (auto& kv : impl_->state.attempts) {
    CompilationAttempt& attempt = kv.second;
    if (is_terminal_state(attempt.state)) continue;
    if (attempt.state == AttemptState::Assigned || attempt.state == AttemptState::Preparing ||
        attempt.state == AttemptState::Running || attempt.state == AttemptState::Produced ||
        attempt.state == AttemptState::Validating || attempt.state == AttemptState::CommitReady) {
      attempt.state = AttemptState::Ambiguous;
      attempt.finished_at = impl_->now();
      attempt.failure = ErrorCode::Ambiguous;
      attempt.failure_detail = "coordinator restarted while the attempt was in flight";
      ++ambiguous;
    }
  }
  for (auto& kv : impl_->state.compilations) {
    CompilationRecord& compilation = kv.second;
    if (compilation.state == CompilationState::Committed || compilation.state == CompilationState::Cancelled ||
        compilation.state == CompilationState::Failed || compilation.state == CompilationState::Retired) {
      continue;
    }
    if (impl_->state.authoritative.count(compilation.id) != 0) {
      compilation.state = CompilationState::Committed;
      continue;
    }
    compilation.state = CompilationState::Pending;
    compilation.cache_hit = false;
    ++requeued;
  }

  if (config.enable_persistence) {
    std::vector<std::byte> header;
    CanonicalWriter w;
    w.domain("dc.header-record.v1");
    w.gen(impl_->state.header.epoch);
    w.u64(impl_->state.header.restarts);
    w.i64(impl_->state.header.opened_at);
    header.assign(w.bytes().begin(), w.bytes().end());
    Status status = impl_->persist(RecordType::Header, header);
    if (!status.ok()) return status;
    std::vector<std::byte> encoded;
    Status encoded_status = detail::encode_state(impl_->state, encoded);
    if (!encoded_status.ok()) return encoded_status;
    Status snapshot_status =
        impl_->store.write_snapshot(std::span<const std::byte>(encoded.data(), encoded.size()));
    if (!snapshot_status.ok()) return snapshot_status;
    impl_->state.header.records_since_snapshot = 0;
  }

  impl_->recovery.notes.push_back("epoch advanced to " + std::to_string(impl_->state.header.epoch.value()));
  impl_->recovery.notes.push_back("in-flight attempts classified AMBIGUOUS: " + std::to_string(ambiguous));
  impl_->recovery.notes.push_back("unfinished compilations requeued: " + std::to_string(requeued));
  return Status::success();
}

void Coordinator::close() {
  if (!impl_) return;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!impl_->opened) return;
  if (impl_->config.enable_persistence) {
    std::vector<std::byte> encoded;
    if (detail::encode_state(impl_->state, encoded).ok()) {
      impl_->store.write_snapshot(std::span<const std::byte>(encoded.data(), encoded.size()));
    }
    impl_->store.close();
  }
  impl_->opened = false;
}

CoordinatorEpoch Coordinator::epoch() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->state.header.epoch;
}

RecoveryReport Coordinator::recovery() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->recovery;
}

Status Coordinator::snapshot() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status status = impl_->ensure_open();
  if (!status.ok()) return status;
  if (!impl_->config.enable_persistence) {
    return Status::error(ErrorCode::Unsupported, "persistence is disabled");
  }
  std::vector<std::byte> encoded;
  Status encoded_status = detail::encode_state(impl_->state, encoded);
  if (!encoded_status.ok()) return encoded_status;
  Status written = impl_->store.write_snapshot(std::span<const std::byte>(encoded.data(), encoded.size()));
  if (!written.ok()) return written;
  impl_->state.header.records_since_snapshot = 0;
  return Status::success();
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------
Result<CompilationRecord> Coordinator::compilation(CompilationId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto found = impl_->state.compilations.find(id);
  if (found == impl_->state.compilations.end()) {
    return Result<CompilationRecord>(Status::error(ErrorCode::NotFound, "unknown compilation"));
  }
  return Result<CompilationRecord>(found->second);
}

Result<ArtifactCommit> Coordinator::commit(CompilationId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto found = impl_->state.authoritative.find(id);
  if (found == impl_->state.authoritative.end()) {
    return Result<ArtifactCommit>(Status::error(ErrorCode::NotFound, "no authoritative commit"));
  }
  auto commit = impl_->state.commits.find(found->second);
  if (commit == impl_->state.commits.end()) {
    return Result<ArtifactCommit>(Status::error(ErrorCode::IntegrityFailure, "authoritative commit is missing"));
  }
  return Result<ArtifactCommit>(commit->second);
}

const ArtifactCommit* Coordinator::authoritative_commit(CompilationId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto found = impl_->state.authoritative.find(id);
  if (found == impl_->state.authoritative.end()) return nullptr;
  auto commit = impl_->state.commits.find(found->second);
  if (commit == impl_->state.commits.end()) return nullptr;
  return &commit->second;
}

Result<Provenance> Coordinator::provenance(ProvenanceId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto found = impl_->state.provenances.find(id);
  if (found == impl_->state.provenances.end()) {
    return Result<Provenance>(Status::error(ErrorCode::NotFound, "unknown provenance"));
  }
  return Result<Provenance>(found->second);
}

Result<ValidationReport> Coordinator::validation(ValidationId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto found = impl_->state.validations.find(id);
  if (found == impl_->state.validations.end()) {
    return Result<ValidationReport>(Status::error(ErrorCode::NotFound, "unknown validation report"));
  }
  return Result<ValidationReport>(found->second);
}

Result<JobRecord> Coordinator::job(const Digest256& request_identity) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto found = impl_->state.jobs.find(request_identity);
  if (found == impl_->state.jobs.end()) {
    return Result<JobRecord>(Status::error(ErrorCode::NotFound, "unknown job"));
  }
  return Result<JobRecord>(found->second);
}

Result<CompilationRequest> Coordinator::request(const Digest256& request_identity) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const CompilationRequest* found = impl_->find_request(request_identity);
  if (found == nullptr) {
    return Result<CompilationRequest>(Status::error(ErrorCode::NotFound, "request is not retained"));
  }
  return Result<CompilationRequest>(*found);
}

Result<CompilationAttempt> Coordinator::attempt(CompilationAttemptId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto found = impl_->state.attempts.find(id);
  if (found == impl_->state.attempts.end()) {
    return Result<CompilationAttempt>(Status::error(ErrorCode::NotFound, "unknown attempt"));
  }
  return Result<CompilationAttempt>(found->second);
}

Result<std::vector<std::byte>> Coordinator::artifact_bytes(CompilationId id) const {
  Digest256 digest;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    auto found = impl_->state.authoritative.find(id);
    if (found == impl_->state.authoritative.end()) {
      return Result<std::vector<std::byte>>(
          Status::error(ErrorCode::ArtifactMissing, "compilation has no authoritative artifact"));
    }
    auto commit = impl_->state.commits.find(found->second);
    if (commit == impl_->state.commits.end()) {
      return Result<std::vector<std::byte>>(
          Status::error(ErrorCode::IntegrityFailure, "authoritative commit record is missing"));
    }
    digest = commit->second.artifact_digest;
  }
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->load_blob(digest);
}

Result<CacheDecision> Coordinator::cache_query(const Digest256& unit_identity) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto index = impl_->state.cache_index.find(unit_identity);
  if (index == impl_->state.cache_index.end()) {
    CacheDecision decision;
    decision.outcome = CacheOutcome::Miss;
    decision.reason = "no cache entry for this unit identity";
    return Result<CacheDecision>(decision);
  }
  auto entry = impl_->state.cache_entries.find(index->second);
  if (entry == impl_->state.cache_entries.end()) {
    CacheDecision decision;
    decision.outcome = CacheOutcome::Corrupt;
    decision.reason = "cache index points at a missing entry";
    return Result<CacheDecision>(decision);
  }
  CompilationRecord probe;
  probe.unit_identity = entry->second.unit_identity;
  probe.source_identity = entry->second.source_identity;
  probe.dependency_identity = entry->second.dependency_identity;
  probe.toolchain_identity = entry->second.toolchain_identity;
  probe.target_identity = entry->second.target_identity;
  probe.specialization_identity = entry->second.specialization_identity;
  probe.policy_identity = entry->second.policy_identity;
  probe.environment_identity = entry->second.environment_identity;
  probe.toolchain_generation = entry->second.toolchain_generation;
  probe.target_generation = entry->second.target_generation;
  CacheDecision decision = impl_->evaluate_cache_metadata(probe, entry->second);
  const bool blob_ok = decision.reusable() && impl_->has_blob(entry->second.artifact.digest);
  return Result<CacheDecision>(impl_->evaluate_cache_blob(probe, entry->second, blob_ok));
}

std::vector<WorkerRecord> Coordinator::workers() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<WorkerRecord> out;
  out.reserve(impl_->state.workers.size());
  for (const auto& kv : impl_->state.workers) out.push_back(kv.second);
  return out;
}

std::vector<CompilationRecord> Coordinator::compilations() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<CompilationRecord> out;
  out.reserve(impl_->state.compilations.size());
  for (const auto& kv : impl_->state.compilations) out.push_back(kv.second);
  return out;
}

std::vector<CompilationAttempt> Coordinator::attempts() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<CompilationAttempt> out;
  out.reserve(impl_->state.attempts.size());
  for (const auto& kv : impl_->state.attempts) out.push_back(kv.second);
  return out;
}

std::vector<ArtifactCommit> Coordinator::commits() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<ArtifactCommit> out;
  out.reserve(impl_->state.commits.size());
  for (const auto& kv : impl_->state.commits) out.push_back(kv.second);
  return out;
}

std::vector<Provenance> Coordinator::provenances() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<Provenance> out;
  out.reserve(impl_->state.provenances.size());
  for (const auto& kv : impl_->state.provenances) out.push_back(kv.second);
  return out;
}

std::vector<CacheEntry> Coordinator::cache_entries() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<CacheEntry> out;
  out.reserve(impl_->state.cache_entries.size());
  for (const auto& kv : impl_->state.cache_entries) out.push_back(kv.second);
  return out;
}

Result<CacheEntry> Coordinator::cache_entry(CacheEntryId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  auto found = impl_->state.cache_entries.find(id);
  if (found == impl_->state.cache_entries.end()) {
    return Result<CacheEntry>(Status::error(ErrorCode::NotFound, "unknown cache entry"));
  }
  return Result<CacheEntry>(found->second);
}

std::vector<NegativeCacheEntry> Coordinator::negative_cache_entries() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return std::vector<NegativeCacheEntry>(impl_->state.negative_cache.begin(), impl_->state.negative_cache.end());
}

std::vector<IntermediateArtifact> Coordinator::intermediates() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<IntermediateArtifact> out;
  out.reserve(impl_->state.intermediates.size());
  for (const auto& kv : impl_->state.intermediates) out.push_back(kv.second);
  return out;
}

std::vector<CompileLease> Coordinator::leases() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<CompileLease> out;
  out.reserve(impl_->state.leases.size());
  for (const auto& kv : impl_->state.leases) out.push_back(kv.second);
  return out;
}

std::vector<AuthorityViolation> Coordinator::violations() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->state.violations;
}

EligibilityReport Coordinator::eligibility(const CompilationRequest& request) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  EligibilityReport report;
  report.total_workers = static_cast<std::uint32_t>(impl_->state.workers.size());
  if (!request.units.empty()) {
    report.requirements = derive_requirements(request, request.units.front(), impl_->config);
  }
  std::vector<WorkerRecord> eligible;
  for (const auto& kv : impl_->state.workers) {
    const WorkerRecord& worker = kv.second;
    EligibilityDecision decision = evaluate_eligibility(worker, report.requirements);
    if (decision.eligible) {
      eligible.push_back(worker);
    } else {
      WorkerIneligibility entry;
      entry.worker = worker.id;
      entry.reason = std::string(to_string(decision.reason));
      entry.detail = decision.detail;
      report.ineligible.push_back(std::move(entry));
    }
  }
  report.eligible_workers = static_cast<std::uint32_t>(eligible.size());
  report.ranked = rank_workers(eligible, report.requirements, 0);
  return report;
}

// ---------------------------------------------------------------------------
// Auditor
// ---------------------------------------------------------------------------
AuditReport Coordinator::audit() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const detail::State& state = impl_->state;
  AuditReport report;
  report.compilations = state.compilations.size();
  report.attempts = state.attempts.size();
  report.workers = state.workers.size();
  report.leases = state.leases.size();
  report.cache_entries = state.cache_entries.size();
  report.provenances = state.provenances.size();
  report.violations = state.violations.size();

  const auto add = [&report](std::string invariant, std::string detail, CompilationId compilation) {
    AuditFinding finding;
    finding.invariant = std::move(invariant);
    finding.detail = std::move(detail);
    finding.compilation = compilation;
    report.findings.push_back(std::move(finding));
  };

  // 1. CompilationId uniqueness: the map key is the identity, so a duplicate
  //    would mean two records claim the same id with different content.
  for (const auto& kv : state.compilations) {
    if (kv.second.id != kv.first) {
      add("compilation_id_unique", "record key does not match its identity", kv.first);
    }
    if (kv.second.unit_identity.is_zero()) {
      add("compilation_has_unit_identity", "compilation has no unit identity", kv.first);
    }
  }

  // 2. At most one authoritative artifact commit per logical compilation.
  for (const auto& kv : state.authoritative) {
    auto commit = state.commits.find(kv.second);
    if (commit == state.commits.end()) {
      add("authoritative_commit_exists", "authoritative commit record is missing", kv.first);
      continue;
    }
    std::size_t authoritative_for = 0;
    for (const auto& other : state.commits) {
      if (other.second.compilation == kv.first && !other.second.superseded) ++authoritative_for;
    }
    if (authoritative_for != 1) {
      add("single_authoritative_commit",
          "compilation has " + std::to_string(authoritative_for) + " non-superseded commits", kv.first);
    }
    // 3. Committed artifacts reference valid generations and have provenance.
    auto compilation = state.compilations.find(kv.first);
    if (compilation == state.compilations.end()) {
      add("commit_references_compilation", "authoritative commit has no compilation record", kv.first);
      continue;
    }
    const CompilationRecord& record = compilation->second;
    if (commit->second.artifact_digest.is_zero()) {
      add("commit_has_digest", "authoritative commit has an empty artifact digest", kv.first);
    }
    if (state.provenances.find(commit->second.provenance) == state.provenances.end()) {
      add("commit_has_provenance", "authoritative commit has no provenance record", kv.first);
    }
    auto validation = state.validations.find(commit->second.validation);
    if (validation == state.validations.end()) {
      add("commit_has_validation", "authoritative commit has no validation record", kv.first);
    } else if (validation->second.aggregate != ValidationOutcome::Pass) {
      add("commit_validation_passed", "authoritative commit references a failed validation", kv.first);
    }
    if (record.state != CompilationState::Committed) {
      add("committed_state_consistent", "authoritative commit but compilation is not Committed", kv.first);
    }
    auto provenance = state.provenances.find(commit->second.provenance);
    if (provenance != state.provenances.end()) {
      if (provenance->second.toolchain_identity != record.toolchain_identity ||
          provenance->second.target_identity != record.target_identity ||
          provenance->second.dependency_identity != record.dependency_identity ||
          provenance->second.specialization_identity != record.specialization_identity ||
          provenance->second.policy_identity != record.policy_identity) {
        add("provenance_generation_consistency",
            "provenance identities differ from the committed compilation", kv.first);
      }
    }
    // 4. No stale worker holds live commit authority for a committed compilation.
    for (CompilationAttemptId attempt_id : record.attempts) {
      auto attempt = state.attempts.find(attempt_id);
      if (attempt == state.attempts.end()) continue;
      if (holds_commit_authority(attempt->second.state) && attempt->second.id != commit->second.attempt) {
        add("no_stale_authority_after_commit",
            "attempt " + std::to_string(attempt_id.value()) + " still holds commit authority",
            kv.first);
      }
      if (attempt->second.state == AttemptState::Cancelled) {
        const WorkerRecord* worker = impl_->find_worker(attempt->second.worker);
        if (worker != nullptr && worker->session.is_zero() && holds_commit_authority(attempt->second.state)) {
          add("cancelled_attempt_has_no_authority", "cancelled attempt retains authority", kv.first);
        }
      }
    }
  }

  // 5. No stale lease: a lease bound to a fenced worker or an old epoch must be revoked.
  for (const auto& kv : state.leases) {
    const CompileLease& lease = kv.second;
    if (lease.epoch != state.header.epoch && !lease.revoked) {
      add("no_stale_lease", "lease from a previous epoch is not revoked", lease.compilation);
    }
    auto worker = state.workers.find(lease.worker);
    if (worker != state.workers.end() && worker->second.fenced && !lease.revoked) {
      add("no_lease_for_fenced_worker", "fenced worker holds a live lease", lease.compilation);
    }
  }

  // 6. No cache entry marked reusable fails validation.
  for (const auto& kv : state.cache_entries) {
    const CacheEntry& entry = kv.second;
    if (entry.invalidated) continue;
    auto compilation = state.compilations.find(entry.compilation);
    if (compilation == state.compilations.end()) continue;
    CacheDecision decision = impl_->evaluate_cache_metadata(compilation->second, entry);
    if (!decision.reusable()) {
      add("cache_entry_matches_compilation",
          "live cache entry does not match its compilation: " + decision.reason, entry.compilation);
    }
    if (!impl_->has_blob(entry.artifact.digest)) {
      add("cache_entry_blob_present", "cache entry artifact is missing from the store", entry.compilation);
    }
  }

  // 7. Fan-in completeness: a committed link unit must have every mandatory child committed.
  for (const auto& kv : state.jobs) {
    const JobRecord& job = kv.second;
    auto request = state.requests.find(kv.first);
    if (request == state.requests.end()) continue;
    auto root = state.compilations.find(job.units.empty() ? CompilationId(0) : job.units[job.root_index]);
    if (root == state.compilations.end()) continue;
    if (root->second.state != CompilationState::Committed) continue;
    const CompilationUnitSpec* root_unit = request->second.find_unit(job.root_index);
    if (root_unit == nullptr) continue;
    for (std::uint32_t child : root_unit->child_units) {
      if (child >= job.units.size()) {
        add("fan_in_child_in_range", "link unit references an out-of-range child", root->second.id);
        continue;
      }
      auto child_record = state.compilations.find(job.units[child]);
      if (child_record == state.compilations.end()) {
        add("fan_in_child_exists", "mandatory child compilation is missing", root->second.id);
        continue;
      }
      if (child_record->second.state != CompilationState::Committed && root_unit->mandatory) {
        add("fan_in_incomplete_blocks_commit", "committed link unit has an uncommitted mandatory child",
            root->second.id);
      }
    }
  }

  // 8. Reproducibility-required divergent artifacts cannot both be authoritative.
  for (const auto& kv : state.compilations) {
    const CompilationRecord& record = kv.second;
    if (record.reproducibility_violation &&
        record.reproducibility == ReproducibilityRequirement::NotRequired) {
      add("reproducibility_violation_requires_policy",
          "reproducibility violation recorded under a policy that does not require it", record.id);
    }
    if (record.divergent_candidates.size() > 1) {
      const ContentRef& first = record.divergent_candidates.front();
      for (const auto& candidate : record.divergent_candidates) {
        if (candidate.digest != first.digest && record.reproducibility == ReproducibilityRequirement::Required &&
            !record.reproducibility_violation) {
          add("divergent_artifacts_flagged", "divergent candidates without a recorded violation", record.id);
        }
      }
    }
  }

  // 9. Attempt identity uniqueness and generation monotonicity.
  for (const auto& kv : state.attempts) {
    if (kv.second.id != kv.first) {
      add("attempt_id_unique", "attempt record key does not match its identity", kv.second.compilation);
    }
    if (kv.second.generation.is_zero()) {
      add("attempt_generation_nonzero", "attempt has a zero generation", kv.second.compilation);
    }
  }
  for (const auto& kv : state.compilations) {
    if (kv.second.generation.is_zero()) {
      add("compilation_generation_nonzero", "compilation has a zero generation", kv.first);
    }
    std::uint32_t ordinals = 0;
    for (CompilationAttemptId id : kv.second.attempts) {
      auto attempt = state.attempts.find(id);
      if (attempt == state.attempts.end()) {
        add("attempt_reference_valid", "compilation references a missing attempt", kv.first);
        continue;
      }
      ++ordinals;
    }
    if (ordinals != kv.second.attempts.size()) {
      add("attempt_reference_count", "attempt reference count mismatch", kv.first);
    }
  }

  // 10. Accounting closure: every authoritative compilation has exactly one commit.
  for (const auto& kv : state.compilations) {
    if (kv.second.state == CompilationState::Committed && state.authoritative.count(kv.first) == 0) {
      add("committed_has_authoritative_commit", "committed compilation has no authoritative commit", kv.first);
    }
  }

  report.committed = state.authoritative.size();
  report.clean = report.findings.empty();
  return report;
}

ExplainReport Coordinator::explain(CompilationId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  ExplainReport report;
  const auto& state = impl_->state;
  const auto line = [&report](std::string text) { report.lines.push_back(std::move(text)); };

  auto compilation = state.compilations.find(id);
  if (compilation == state.compilations.end()) {
    line("compilation " + std::to_string(id.value()) + ": NOT FOUND");
    return report;
  }
  const CompilationRecord& record = compilation->second;
  line("compilation: " + std::to_string(record.id.value()) + " generation " +
       std::to_string(record.generation.value()));
  line("state: " + std::string(to_string(record.state)));
  line("unit: " + std::to_string(record.unit.value()) + " index " + std::to_string(record.unit_index) +
       (record.is_root ? " (root)" : " (child)"));
  line("unit identity: " + record.unit_identity.hex());
  line("request identity: " + record.request_identity.hex());
  line("output kind: " + std::string(to_string(record.output_kind)));
  line("reproducibility: " + std::string(to_string(record.reproducibility)));
  line("identities:");
  line("  source          " + record.source_identity.hex());
  line("  dependencies    " + record.dependency_identity.hex());
  line("  toolchain       " + record.toolchain_identity.hex());
  line("  target          " + record.target_identity.hex());
  line("  specialization  " + record.specialization_identity.hex());
  line("  policy          " + record.policy_identity.hex());
  line("  environment     " + record.environment_identity.hex());
  line("generations: source=" + std::to_string(record.source_generation.value()) + " deps=" +
       std::to_string(record.dependency_generation.value()) + " toolchain=" +
       std::to_string(record.toolchain_generation.value()) + " target=" +
       std::to_string(record.target_generation.value()) + " spec=" +
       std::to_string(record.specialization_generation.value()) + " policy=" +
       std::to_string(record.policy_generation.value()));

  auto index = state.cache_index.find(record.unit_identity);
  if (index == state.cache_index.end()) {
    line("cache: MISS (no entry for this unit identity)");
  } else {
    auto entry = state.cache_entries.find(index->second);
    if (entry == state.cache_entries.end()) {
      line("cache: CORRUPT (index points at a missing entry)");
    } else {
      CacheDecision decision = impl_->evaluate_cache_metadata(record, entry->second);
      line("cache: " + std::string(to_string(decision.outcome)) + " - " + decision.reason);
      for (const auto& mismatch : decision.mismatches) {
        line("  mismatch " + mismatch.dimension + ": expected " + mismatch.expected + " actual " +
             mismatch.actual);
      }
      if (decision.generation_drift) line("  generation drift observed (content identity still equal)");
    }
  }

  if (record.cache_hit) line("served from cache: yes");

  line("attempts:");
  for (CompilationAttemptId attempt_id : record.attempts) {
    auto attempt = state.attempts.find(attempt_id);
    if (attempt == state.attempts.end()) {
      line("  " + std::to_string(attempt_id.value()) + ": MISSING");
      continue;
    }
    const CompilationAttempt& a = attempt->second;
    line("  " + std::to_string(a.id.value()) + " ordinal " + std::to_string(a.ordinal) + " state " +
         std::string(to_string(a.state)) + " worker " + std::to_string(a.worker.value()) + " boot " +
         std::to_string(a.worker_boot.value()) + " lease " + std::to_string(a.lease.value()) +
         (a.speculative ? " (speculative)" : ""));
    if (a.failure != ErrorCode::Ok) {
      line("    failure: " + std::string(to_string(a.failure)) + " " + a.failure_detail);
    }
    if (!a.candidate.digest.is_zero()) {
      line("    candidate: " + a.candidate.digest.hex() + " size " + std::to_string(a.candidate.size));
    }
  }

  auto authoritative = state.authoritative.find(record.id);
  if (authoritative == state.authoritative.end()) {
    line("authoritative artifact: none");
  } else {
    auto commit = state.commits.find(authoritative->second);
    if (commit == state.commits.end()) {
      line("authoritative artifact: COMMIT RECORD MISSING (integrity failure)");
    } else {
      line("authoritative artifact: " + commit->second.artifact_digest.hex() +
           (commit->second.deduplicated ? " (deduplicated)" : ""));
      line("commit: " + std::to_string(commit->second.id.value()) + " at epoch " +
           std::to_string(commit->second.epoch.value()) + " worker " +
           std::to_string(commit->second.worker.value()) + " boot " +
           std::to_string(commit->second.worker_boot.value()));
      auto provenance = state.provenances.find(commit->second.provenance);
      if (provenance != state.provenances.end()) {
        line("provenance: " + std::to_string(provenance->second.id.value()) + " evidence " +
             std::string(to_string(provenance->second.evidence)) + " compiler " +
             provenance->second.compiler_version_string);
      } else {
        line("provenance: MISSING (integrity failure)");
      }
      auto validation = state.validations.find(commit->second.validation);
      if (validation != state.validations.end()) {
        line("validation: " + std::string(to_string(validation->second.aggregate)) + " (" +
             validation->second.summary + ")");
        for (const auto& check : validation->second.checks) {
          line("  " + check.check + ": " + std::string(to_string(check.outcome)) + " " + check.detail);
        }
      }
    }
  }
  if (record.reproducibility_violation) {
    line("reproducibility violation: yes, divergent candidates retained: " +
         std::to_string(record.divergent_candidates.size()));
  }
  return report;
}

}  // namespace dc
