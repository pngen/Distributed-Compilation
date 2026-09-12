// Distributed Compilation - coordinator state codec.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "coordinator_state.hpp"

#include "dc/codec.hpp"

namespace dc {
namespace detail {
namespace {

constexpr std::size_t kMaxStateRecords = 4u * 1024u * 1024u;

template <class RegistryT, class IdT, class GenT>
void encode_registry(CanonicalWriter& w, const RegistryT& registry) {
  std::size_t slots = 0;
  std::size_t entries = 0;
  for (const auto& kv : registry.slots()) {
    ++slots;
    entries += kv.second.by_content.size();
  }
  w.u64(slots);
  w.u64(entries);
  for (const auto& kv : registry.slots()) {
    w.u64(kv.first.value());
    w.gen(GenT(kv.second.current.value()));
    w.u64(kv.second.by_content.size());
    for (const auto& content : kv.second.order) {
      auto found = kv.second.by_content.find(content);
      if (found == kv.second.by_content.end()) continue;
      w.digest(found->first);
      w.gen(GenT(found->second.value()));
    }
  }
}

template <class RegistryT, class IdT, class GenT>
bool decode_registry(CanonicalReader& r, RegistryT& registry) {
  std::uint64_t slots = 0;
  std::uint64_t entries = 0;
  if (!r.read_u64(slots)) return false;
  if (!r.read_u64(entries)) return false;
  if (slots > kMaxStateRecords || entries > kMaxStateRecords) {
    r.fail(ErrorCode::LimitExceeded, "registry record count exceeds bounded limit");
    return false;
  }
  for (std::uint64_t i = 0; i < slots; ++i) {
    std::uint64_t raw_id = 0;
    if (!r.read_u64(raw_id)) return false;
    IdT id;
    if (!IdT::decode(raw_id, id)) {
      r.fail(ErrorCode::Malformed, "registry id is zero");
      return false;
    }
    GenT current;
    if (!r.read_gen(current)) return false;
    std::uint64_t count = 0;
    if (!r.read_u64(count)) return false;
    if (count > kMaxStateRecords) {
      r.fail(ErrorCode::LimitExceeded, "registry entry count exceeds bounded limit");
      return false;
    }
    for (std::uint64_t k = 0; k < count; ++k) {
      Digest256 content;
      GenT generation;
      if (!r.read_digest(content)) return false;
      if (!r.read_gen(generation)) return false;
      registry.restore(id, content, generation);
    }
    (void)current;
  }
  return true;
}

}  // namespace

Status encode_state(const State& state, std::vector<std::byte>& out) {
  CanonicalWriter w;
  w.domain("dc.state.v1");
  w.u16(static_cast<std::uint16_t>(DC_SCHEMA_VERSION));
  w.gen(state.header.epoch);
  w.u64(state.header.seq);
  w.u64(state.header.next_compilation_id);
  w.u64(state.header.next_unit_id);
  w.u64(state.header.next_attempt_id);
  w.u64(state.header.next_lease_id);
  w.u64(state.header.next_artifact_id);
  w.u64(state.header.next_commit_id);
  w.u64(state.header.next_provenance_id);
  w.u64(state.header.next_validation_id);
  w.u64(state.header.next_cache_entry_id);
  w.u64(state.header.next_worker_id);
  w.u64(state.header.next_boot_id);
  w.u64(state.header.next_session_id);
  w.u64(state.header.next_intermediate_id);
  w.gen(state.header.cache_generation);
  w.i64(state.header.opened_at);
  w.u64(state.header.records_since_snapshot);
  w.u64(state.header.restarts);

  encode_registry<SourceRegistry, SourceId, SourceGeneration>(w, state.sources);
  encode_registry<IRRegistry, IRId, IRGeneration>(w, state.irs);
  encode_registry<DependencyRegistry, DependencySetId, DependencyGeneration>(w, state.dependencies);
  encode_registry<ToolchainRegistry, ToolchainId, ToolchainGeneration>(w, state.toolchains);
  encode_registry<TargetRegistry, TargetId, TargetGeneration>(w, state.targets);
  encode_registry<SpecializationRegistry, SpecializationId, SpecializationGeneration>(w, state.specializations);
  encode_registry<PolicyRegistry, CompilePolicyId, CompilePolicyGeneration>(w, state.policies);

  w.u64(state.workers.size());
  for (const auto& kv : state.workers) encode_worker(w, kv.second);

  w.u64(state.requests.size());
  for (const auto& kv : state.requests) encode_request(w, kv.second);

  w.u64(state.jobs.size());
  for (const auto& kv : state.jobs) encode_job(w, kv.second);

  w.u64(state.compilations.size());
  for (const auto& kv : state.compilations) encode_compilation(w, kv.second);

  w.u64(state.attempts.size());
  for (const auto& kv : state.attempts) encode_attempt(w, kv.second);

  w.u64(state.commits.size());
  for (const auto& kv : state.commits) encode_commit(w, kv.second);

  w.u64(state.authoritative.size());
  for (const auto& kv : state.authoritative) {
    w.id(kv.first);
    w.id(kv.second);
  }

  w.u64(state.provenances.size());
  for (const auto& kv : state.provenances) encode_provenance(w, kv.second);

  w.u64(state.validations.size());
  for (const auto& kv : state.validations) encode_validation_report(w, kv.second);

  w.u64(state.cache_entries.size());
  for (const auto& kv : state.cache_entries) encode_cache_entry(w, kv.second);

  w.u64(state.intermediates.size());
  for (const auto& kv : state.intermediates) encode_intermediate(w, kv.second);

  w.u64(state.leases.size());
  for (const auto& kv : state.leases) encode_lease(w, kv.second);

  w.u64(state.negative_cache.size());
  for (const auto& entry : state.negative_cache) encode_negative_cache(w, entry);

  w.u64(state.violations.size());
  for (const auto& violation : state.violations) {
    w.i64(violation.at);
    w.str(violation.operation);
    w.u16(static_cast<std::uint16_t>(violation.code));
    w.id(violation.session);
    w.id(violation.worker);
    w.str(violation.detail);
  }

  out.assign(w.bytes().begin(), w.bytes().end());
  return Status::success();
}

Status decode_state(std::span<const std::byte> bytes, State& out) {
  CanonicalReader r(bytes);
  if (!r.read_domain("dc.state.v1")) {
    return Status::error(ErrorCode::PersistenceCorrupt, "state domain tag mismatch");
  }
  std::uint16_t schema = 0;
  if (!r.read_u16(schema)) return Status::error(ErrorCode::PersistenceCorrupt, r.status().detail());
  if (schema != DC_SCHEMA_VERSION) {
    return Status::error(ErrorCode::SchemaMismatch, "state schema mismatch");
  }
  State state;
  if (!r.read_gen(state.header.epoch)) return Status::error(ErrorCode::PersistenceCorrupt, "epoch");
  if (!r.read_u64(state.header.seq)) return Status::error(ErrorCode::PersistenceCorrupt, "seq");
  if (!r.read_u64(state.header.next_compilation_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_unit_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_attempt_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_lease_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_artifact_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_commit_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_provenance_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_validation_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_cache_entry_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_worker_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_boot_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_session_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_u64(state.header.next_intermediate_id)) return Status::error(ErrorCode::PersistenceCorrupt, "ids");
  if (!r.read_gen(state.header.cache_generation)) return Status::error(ErrorCode::PersistenceCorrupt, "cache gen");
  if (!r.read_i64(state.header.opened_at)) return Status::error(ErrorCode::PersistenceCorrupt, "opened_at");
  if (!r.read_u64(state.header.records_since_snapshot)) {
    return Status::error(ErrorCode::PersistenceCorrupt, "records_since_snapshot");
  }
  if (!r.read_u64(state.header.restarts)) return Status::error(ErrorCode::PersistenceCorrupt, "restarts");

  const auto reject = [&r]() {
    return Status::error(ErrorCode::PersistenceCorrupt, "state decode failed: " + r.status().detail());
  };

  if (!decode_registry<SourceRegistry, SourceId, SourceGeneration>(r, state.sources)) return reject();
  if (!decode_registry<IRRegistry, IRId, IRGeneration>(r, state.irs)) return reject();
  if (!decode_registry<DependencyRegistry, DependencySetId, DependencyGeneration>(r, state.dependencies)) return reject();
  if (!decode_registry<ToolchainRegistry, ToolchainId, ToolchainGeneration>(r, state.toolchains)) return reject();
  if (!decode_registry<TargetRegistry, TargetId, TargetGeneration>(r, state.targets)) return reject();
  if (!decode_registry<SpecializationRegistry, SpecializationId, SpecializationGeneration>(r, state.specializations))
    return reject();
  if (!decode_registry<PolicyRegistry, CompilePolicyId, CompilePolicyGeneration>(r, state.policies)) return reject();

  std::uint64_t count = 0;
  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    WorkerRecord worker;
    if (!decode_worker(r, worker)) return reject();
    state.workers[worker.id] = std::move(worker);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    CompilationRequest request;
    if (!decode_request(r, request)) return reject();
    state.requests[request.request_identity] = std::move(request);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    JobRecord job;
    if (!decode_job(r, job)) return reject();
    state.jobs[job.request_identity] = std::move(job);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    CompilationRecord record;
    if (!decode_compilation(r, record)) return reject();
    state.compilations[record.id] = std::move(record);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    CompilationAttempt attempt;
    if (!decode_attempt(r, attempt)) return reject();
    state.attempts[attempt.id] = std::move(attempt);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    ArtifactCommit commit;
    if (!decode_commit(r, commit)) return reject();
    state.commits[commit.id] = std::move(commit);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    CompilationId compilation;
    ArtifactCommitId commit;
    if (!r.read_id(compilation)) return reject();
    if (!r.read_id(commit)) return reject();
    state.authoritative[compilation] = commit;
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    Provenance provenance;
    if (!decode_provenance(r, provenance)) return reject();
    state.provenances[provenance.id] = std::move(provenance);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    ValidationReport report;
    if (!decode_validation_report(r, report)) return reject();
    state.validations[report.id] = std::move(report);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    CacheEntry entry;
    if (!decode_cache_entry(r, entry)) return reject();
    auto existing = state.cache_index.find(entry.unit_identity);
    if (existing == state.cache_index.end() || entry.generation > state.cache_entries[existing->second].generation) {
      state.cache_index[entry.unit_identity] = entry.id;
    }
    state.cache_entries[entry.id] = std::move(entry);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    IntermediateArtifact artifact;
    if (!decode_intermediate(r, artifact)) return reject();
    state.intermediates[artifact.id] = std::move(artifact);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    CompileLease lease;
    if (!decode_lease(r, lease)) return reject();
    state.leases[lease.id] = std::move(lease);
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    NegativeCacheEntry entry;
    if (!decode_negative_cache(r, entry)) return reject();
    state.negative_cache.push_back(std::move(entry));
  }

  if (!r.read_u64(count) || count > kMaxStateRecords) return reject();
  for (std::uint64_t i = 0; i < count; ++i) {
    AuthorityViolation violation;
    if (!r.read_i64(violation.at)) return reject();
    if (!r.read_str(violation.operation)) return reject();
    std::uint16_t code = 0;
    if (!r.read_u16(code)) return reject();
    if (code > static_cast<std::uint16_t>(ErrorCode::Shutdown)) return reject();
    violation.code = static_cast<ErrorCode>(code);
    if (!r.read_id(violation.session)) return reject();
    if (!r.read_id(violation.worker)) return reject();
    if (!r.read_str(violation.detail)) return reject();
    state.violations.push_back(std::move(violation));
  }

  if (!r.at_end()) {
    return Status::error(ErrorCode::PersistenceCorrupt, "state has trailing bytes");
  }
  out = std::move(state);
  return Status::success();
}

Status encode_job_record(const JobRecord& job, std::vector<std::byte>& out) {
  CanonicalWriter w;
  encode_job(w, job);
  out.assign(w.bytes().begin(), w.bytes().end());
  return Status::success();
}

bool decode_job_record(std::span<const std::byte> bytes, JobRecord& out) {
  CanonicalReader r(bytes);
  return decode_job(r, out) && r.at_end();
}

Status encode_request_record(const CompilationRequest& request, std::vector<std::byte>& out) {
  CanonicalWriter w;
  encode_request(w, request);
  out.assign(w.bytes().begin(), w.bytes().end());
  return Status::success();
}

bool decode_request_record(std::span<const std::byte> bytes, CompilationRequest& out) {
  CanonicalReader r(bytes);
  return decode_request(r, out) && r.at_end();
}

Status encode_registry_record(const Digest256& content, std::uint64_t generation, std::uint64_t registry_id,
                              std::vector<std::byte>& out) {
  CanonicalWriter w;
  w.domain("dc.registry-record.v1");
  w.u64(registry_id);
  w.digest(content);
  w.u64(generation);
  out.assign(w.bytes().begin(), w.bytes().end());
  return Status::success();
}

}  // namespace detail
}  // namespace dc
