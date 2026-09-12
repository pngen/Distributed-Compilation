// Distributed Compilation - internal coordinator state and its codec.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_COORDINATOR_STATE_HPP
#define DC_COORDINATOR_STATE_HPP

#include <deque>
#include <map>
#include <string>
#include <vector>

#include "dc/coordinator.hpp"
#include "dc/model.hpp"
#include "dc/runtime.hpp"

namespace dc {
namespace detail {

struct SessionRecord {
  SessionId id;
  bool is_worker = false;
  WorkerId worker;
  WorkerBootId boot;
  CoordinatorEpoch epoch;
  std::string peer;
  std::string host;
  UnixMillis connected_at = 0;
  UnixMillis last_seen = 0;
  bool open = true;
  std::uint32_t max_inflight = 4;
};

struct StateHeader {
  CoordinatorEpoch epoch;
  Seq seq = 0;
  std::uint64_t next_compilation_id = 1;
  std::uint64_t next_unit_id = 1;
  std::uint64_t next_attempt_id = 1;
  std::uint64_t next_lease_id = 1;
  std::uint64_t next_artifact_id = 1;
  std::uint64_t next_commit_id = 1;
  std::uint64_t next_provenance_id = 1;
  std::uint64_t next_validation_id = 1;
  std::uint64_t next_cache_entry_id = 1;
  std::uint64_t next_worker_id = 1;
  std::uint64_t next_boot_id = 1;
  std::uint64_t next_session_id = 1;
  std::uint64_t next_intermediate_id = 1;
  CacheGeneration cache_generation;
  UnixMillis opened_at = 0;
  std::uint64_t records_since_snapshot = 0;
  std::uint64_t restarts = 0;
};

struct State {
  StateHeader header;

  SourceRegistry sources;
  IRRegistry irs;
  DependencyRegistry dependencies;
  ToolchainRegistry toolchains;
  TargetRegistry targets;
  SpecializationRegistry specializations;
  PolicyRegistry policies;

  std::map<WorkerId, WorkerRecord> workers;
  std::map<SessionId, SessionRecord> sessions;
  std::map<CompilationId, CompilationRecord> compilations;
  std::map<CompilationAttemptId, CompilationAttempt> attempts;
  std::map<ArtifactCommitId, ArtifactCommit> commits;
  std::map<CompilationId, ArtifactCommitId> authoritative;
  std::map<ProvenanceId, Provenance> provenances;
  std::map<ValidationId, ValidationReport> validations;
  std::map<CacheEntryId, CacheEntry> cache_entries;
  std::map<Digest256, CacheEntryId> cache_index;
  std::map<IntermediateId, IntermediateArtifact> intermediates;
  std::map<LeaseId, CompileLease> leases;
  std::map<Digest256, JobRecord> jobs;
  std::map<Digest256, CompilationRequest> requests;
  std::deque<NegativeCacheEntry> negative_cache;
  std::vector<AuthorityViolation> violations;
  std::vector<ControlMessage> controls;
};

// Drops a worker's capability evidence to UNKNOWN and re-commits the
// capability digest. Every mutation of a capability set must go through this or
// through canonicalize(), because the digest is an integrity commitment over
// the set: a stale digest makes the persisted record fail its own integrity
// check on the next decode.
void mark_capabilities_unknown(WorkerRecord& worker);

Status encode_state(const State& state, std::vector<std::byte>& out);
Status decode_state(std::span<const std::byte> bytes, State& out);

// A compact record for a single entity, used for journal upserts.
Status encode_job_record(const JobRecord& job, std::vector<std::byte>& out);
bool decode_job_record(std::span<const std::byte> bytes, JobRecord& out);
Status encode_request_record(const CompilationRequest& request, std::vector<std::byte>& out);
bool decode_request_record(std::span<const std::byte> bytes, CompilationRequest& out);
Status encode_registry_record(const Digest256& content, std::uint64_t generation, std::uint64_t registry_id,
                              std::vector<std::byte>& out);

}  // namespace detail
}  // namespace dc

#endif  // DC_COORDINATOR_STATE_HPP
