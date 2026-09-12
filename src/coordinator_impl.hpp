// Distributed Compilation - internal coordinator implementation state.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_COORDINATOR_IMPL_HPP
#define DC_COORDINATOR_IMPL_HPP

#include <deque>
#include <map>
#include <mutex>

#include "coordinator_state.hpp"
#include "dc/coordinator.hpp"

namespace dc {

struct Coordinator::Impl {
  CoordinatorConfig config;
  std::shared_ptr<Clock> clock;
  mutable std::mutex mutex;
  detail::State state;
  PersistentStore store;
  bool opened = false;
  RecoveryReport recovery;
  std::uint64_t persisted_records = 0;

  // Bounded in-memory cache in front of the content-addressed store. Blobs are
  // always verified against their digest when they enter this cache.
  std::map<Digest256, std::vector<std::byte>> blob_cache;
  std::deque<Digest256> blob_cache_order;
  std::uint64_t blob_cache_bytes = 0;
  std::uint64_t blob_cache_limit = 64ull * 1024 * 1024;

  // Evicts every completed request once the retained-request bound is reached.
  std::deque<Digest256> retained_order;

  // --- helpers shared by the transaction and query translation units -------
  UnixMillis now() const { return clock ? clock->now() : 0; }

  Status persist(RecordType type, const std::vector<std::byte>& payload);
  Status persist_entity(RecordType type, const std::vector<std::byte>& payload);
  void maybe_snapshot();

  Status store_blob(const std::vector<std::byte>& bytes);
  Result<std::vector<std::byte>> load_blob(const Digest256& digest);
  bool has_blob(const Digest256& digest) const;

  const CompilationRequest* find_request(const Digest256& identity) const;
  const detail::SessionRecord* find_session(SessionId id) const;
  WorkerRecord* find_worker(WorkerId id);
  const WorkerRecord* find_worker(WorkerId id) const;

  AuthorityExpectation expectation_for(const CompilationRecord& compilation,
                                       const CompilationAttempt& attempt) const;
  void record_violation(std::string operation, ErrorCode code, SessionId session, WorkerId worker,
                        std::string detail);

  // Requirements derived from the request and unit that a compilation belongs to.
  HardRequirements requirements_for(const CompilationRecord& compilation) const;

  std::vector<WorkerRecord> eligible_workers(const HardRequirements& requirements,
                                             const std::vector<CompilationId>& busy) const;

  // Cache validation. Both stages assume the caller holds the mutex.
  CacheDecision evaluate_cache_metadata(const CompilationRecord& compilation, const CacheEntry& entry) const;
  CacheDecision evaluate_cache_blob(const CompilationRecord& compilation, const CacheEntry& entry,
                                    bool blob_ok) const;

  void touch_cache_entry(CacheEntry& entry);

  // Adds (or refreshes) a cache entry for a committed artifact.
  void record_cache_entry(const CompilationRecord& compilation, const ArtifactCommit& commit,
                          const Provenance& provenance, const ValidationReport& validation);

  void add_negative_cache_entry(const CompilationRecord& compilation, NegativeCacheReason reason,
                                ErrorCode failure, std::string diagnostic);

  // Authority bookkeeping.
  Status transition_attempt(CompilationAttempt& attempt, AttemptState next);
  void finish_attempt_bookkeeping(CompilationAttempt& attempt);

  void enqueue_cancel_losers(const CompilationRecord& compilation, CompilationAttemptId winner);
  void revoke_leases_for(WorkerId worker, std::string reason);
  void fence_worker(WorkerRecord& worker, std::string reason);

  Status ensure_open() const {
    if (!opened) return Status::error(ErrorCode::PersistenceClosed, "coordinator is not open");
    return Status::success();
  }

  // Transaction helpers.
  Status register_and_check(CompilationRequest& request);
  bool unit_ready(const CompilationRecord& compilation) const;
  std::optional<Assignment> build_assignment(const WorkerRecord& worker, CompilationRecord& compilation,
                                             bool speculative);
  Result<CommitDecision> commit_locked(SessionId session, const ReportOutput& output,
                                       const ValidationReport& validation);
  Status fail_attempt_locked(CompilationAttempt& attempt, ErrorCode code, std::string detail,
                             bool produced_candidate);
  void schedule_retry_or_fail(CompilationRecord& compilation, ErrorCode code, std::string detail);
  Status fence_attempts_of_worker(WorkerId worker, std::string reason);
  void mark_job_progress(CompilationRecord& compilation);
};

}  // namespace dc

#endif  // DC_COORDINATOR_IMPL_HPP
