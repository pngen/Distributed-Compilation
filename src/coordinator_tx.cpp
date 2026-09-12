// Distributed Compilation - the distributed compilation transaction.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Flow: submit -> canonicalize -> cache consult -> eligibility -> ranking ->
// assignment -> worker compile -> report -> validate -> revalidate authority ->
// commit exactly once -> expose. Nothing before the final revalidation may
// promote a candidate to authority.
#include <algorithm>
#include <cstring>

#include "coordinator_impl.hpp"
#include "dc/codec.hpp"
#include "dc/process.hpp"

namespace dc {
namespace {

std::vector<std::byte> encode_worker_payload(const WorkerRecord& worker) {
  CanonicalWriter w;
  encode_worker(w, worker);
  return std::vector<std::byte>(w.bytes().begin(), w.bytes().end());
}

std::vector<std::byte> encode_compilation_payload(const CompilationRecord& record) {
  CanonicalWriter w;
  encode_compilation(w, record);
  return std::vector<std::byte>(w.bytes().begin(), w.bytes().end());
}

std::vector<std::byte> encode_attempt_payload(const CompilationAttempt& attempt) {
  CanonicalWriter w;
  encode_attempt(w, attempt);
  return std::vector<std::byte>(w.bytes().begin(), w.bytes().end());
}

std::vector<std::byte> encode_commit_payload(const ArtifactCommit& commit) {
  CanonicalWriter w;
  encode_commit(w, commit);
  return std::vector<std::byte>(w.bytes().begin(), w.bytes().end());
}

std::vector<std::byte> encode_provenance_payload(const Provenance& provenance) {
  CanonicalWriter w;
  encode_provenance(w, provenance);
  return std::vector<std::byte>(w.bytes().begin(), w.bytes().end());
}

std::vector<std::byte> encode_validation_payload(const ValidationReport& validation) {
  CanonicalWriter w;
  encode_validation_report(w, validation);
  return std::vector<std::byte>(w.bytes().begin(), w.bytes().end());
}

std::vector<std::byte> encode_lease_payload(const CompileLease& lease) {
  CanonicalWriter w;
  encode_lease(w, lease);
  return std::vector<std::byte>(w.bytes().begin(), w.bytes().end());
}

}  // namespace

// ---------------------------------------------------------------------------
// Registry resolution and declared-generation checks
// ---------------------------------------------------------------------------
Status Coordinator::Impl::register_and_check(CompilationRequest& request) {
  // A zero logical id must never become a registry key: it would make every
  // unnamed entity collide in one slot.
  if (request.toolchain.id.is_zero() || request.target.id.is_zero() ||
      request.specialization.id.is_zero() || request.policy.id.is_zero() ||
      request.dependencies.id.is_zero()) {
    return Status::error(ErrorCode::InvalidArgument,
                         "every registered identity must have a non-zero logical id");
  }

  const auto generation_conflict = [](ErrorCode code, const char* dimension, std::uint64_t declared,
                                      std::uint64_t actual) {
    return Status::error(code, std::string(dimension) + " generation declared as " +
                                   std::to_string(declared) + " but the coordinator resolved " +
                                   std::to_string(actual));
  };

  {
    const std::uint64_t declared = request.toolchain.generation.value();
    bool created = false;
    const ToolchainGeneration generation =
        state.toolchains.resolve(request.toolchain.id, request.toolchain.identity_digest, created);
    if (declared != 0 && generation.value() != declared) {
      return generation_conflict(ErrorCode::StaleToolchain, "toolchain", declared, generation.value());
    }
    request.toolchain.generation = generation;
  }
  {
    const std::uint64_t declared = request.target.generation.value();
    bool created = false;
    const TargetGeneration generation =
        state.targets.resolve(request.target.id, request.target.identity_digest, created);
    if (declared != 0 && generation.value() != declared) {
      return generation_conflict(ErrorCode::StaleTarget, "target", declared, generation.value());
    }
    request.target.generation = generation;
  }
  {
    const std::uint64_t declared = request.specialization.generation.value();
    bool created = false;
    const SpecializationGeneration generation = state.specializations.resolve(
        request.specialization.id, request.specialization.identity_digest, created);
    if (declared != 0 && generation.value() != declared) {
      return generation_conflict(ErrorCode::StaleSpecialization, "specialization", declared, generation.value());
    }
    request.specialization.generation = generation;
  }
  {
    const std::uint64_t declared = request.policy.generation.value();
    bool created = false;
    const CompilePolicyGeneration generation =
        state.policies.resolve(request.policy.id, request.policy.identity_digest, created);
    if (declared != 0 && generation.value() != declared) {
      return generation_conflict(ErrorCode::StalePolicy, "policy", declared, generation.value());
    }
    request.policy.generation = generation;
  }
  {
    const std::uint64_t declared = request.dependencies.generation.value();
    bool created = false;
    const DependencyGeneration generation =
        state.dependencies.resolve(request.dependencies.id, request.dependencies.identity_digest, created);
    if (declared != 0 && generation.value() != declared) {
      return generation_conflict(ErrorCode::StaleDependencies, "dependency set", declared, generation.value());
    }
    request.dependencies.generation = generation;
  }
  for (auto& unit : request.units) {
    for (auto& source : unit.sources) {
      bool created = false;
      state.sources.resolve(derive_source_id(source.logical_name), source.content.digest, created);
    }
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Submission
// ---------------------------------------------------------------------------
Result<SubmissionResult> Coordinator::submit(const SubmissionBundle& bundle) {
  // Content ingestion is authority-free, so it runs before the lock. Every blob
  // is verified against its digest on the way in.
  if (bundle.request.units.size() > impl_->config.max_units) {
    return Result<SubmissionResult>(
        Status::error(ErrorCode::LimitExceeded, "compilation request exceeds the unit bound"));
  }
  std::uint64_t total_bytes = 0;
  for (const auto& blob : bundle.blobs) {
    total_bytes += blob.bytes.size();
    if (total_bytes > impl_->config.max_bundle_bytes) {
      return Result<SubmissionResult>(
          Status::error(ErrorCode::LimitExceeded, "submission bundle exceeds the configured bound"));
    }
    if (blob.bytes.size() > impl_->config.max_blob_bytes) {
      return Result<SubmissionResult>(
          Status::error(ErrorCode::LimitExceeded, "submission blob exceeds the configured bound"));
    }
    const Digest256 actual = sha256(std::span<const std::byte>(blob.bytes.data(), blob.bytes.size()));
    if (!blob.digest.is_zero() && actual != blob.digest) {
      return Result<SubmissionResult>(
          Status::error(ErrorCode::IntegrityFailure, "submission blob does not match its declared digest"));
    }
  }

  SubmissionResult result;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status open_status = impl_->ensure_open();
  if (!open_status.ok()) return Result<SubmissionResult>(open_status);

  CompilationRequest request = bundle.request;
  Status canonical_status = canonicalize(request);
  if (!canonical_status.ok()) return Result<SubmissionResult>(canonical_status);

  const auto find_blob = [&bundle](const Digest256& digest) -> const Blob* {
    for (const auto& blob : bundle.blobs) {
      if (blob.digest == digest) return &blob;
      const Digest256 computed = sha256(std::span<const std::byte>(blob.bytes.data(), blob.bytes.size()));
      if (computed == digest) return &blob;
    }
    return nullptr;
  };
  for (const auto& unit : request.units) {
    for (const auto& source : unit.sources) {
      if (find_blob(source.content.digest) == nullptr) {
        return Result<SubmissionResult>(Status::error(
            ErrorCode::InvalidArgument,
            "submission bundle is missing content for '" + source.logical_name + "'"));
      }
    }
    for (const auto& dep : unit.dependencies) {
      if (find_blob(dep.content.digest) == nullptr) {
        return Result<SubmissionResult>(Status::error(
            ErrorCode::InvalidArgument, "submission bundle is missing dependency content for '" + dep.name + "'"));
      }
    }
  }

  Status register_status = impl_->register_and_check(request);
  if (!register_status.ok()) return Result<SubmissionResult>(register_status);

  result.request_id = request.request_id;
  result.request_identity = request.request_identity;

  const bool known_job = impl_->state.jobs.count(request.request_identity) != 0;
  if (known_job && impl_->state.jobs[request.request_identity].request_id != request.request_id) {
    result.duplicate_request = true;
  }

  for (const auto& blob : bundle.blobs) {
    Status store_status = impl_->store_blob(blob.bytes);
    if (!store_status.ok()) return Result<SubmissionResult>(store_status);
  }

  if (impl_->state.requests.count(request.request_identity) == 0) {
    impl_->state.requests.emplace(request.request_identity, request);
    impl_->retained_order.push_back(request.request_identity);
    const std::size_t retention_bound = 8192;
    while (impl_->retained_order.size() > retention_bound) {
      const Digest256 victim = impl_->retained_order.front();
      auto job = impl_->state.jobs.find(victim);
      if (job != impl_->state.jobs.end() && !job->second.committed && job->second.failure == ErrorCode::Ok) {
        break;   // unfinished work must keep its request
      }
      impl_->retained_order.pop_front();
      impl_->state.requests.erase(victim);
    }
    std::vector<std::byte> payload;
    detail::encode_request_record(request, payload);
    Status persist_status = impl_->persist(RecordType::Artifact, payload);
    if (!persist_status.ok()) return Result<SubmissionResult>(persist_status);
  }

  JobRecord job;
  if (known_job) {
    job = impl_->state.jobs[request.request_identity];
  } else {
    job.request_id = request.request_id;
    job.request_generation = request.request_generation;
    job.request_identity = request.request_identity;
    job.created_at = impl_->now();
  }
  job.units.resize(request.units.size());
  job.mandatory_units.clear();
  job.root_index = 0;

  for (const auto& unit : request.units) {
    const CompilationId compilation_id = derive_compilation_id(unit.identity_digest);
    job.units[unit.index] = compilation_id;
    if (unit.mandatory) job.mandatory_units.push_back(unit.index);

    auto existing = impl_->state.compilations.find(compilation_id);
    if (existing == impl_->state.compilations.end()) {
      CompilationRecord record;
      record.id = compilation_id;
      record.generation = CompilationGeneration(1);
      record.unit = derive_unit_handle(unit.identity_digest);
      record.unit_generation = UnitGeneration(1);
      record.unit_identity = unit.identity_digest;
      record.request_id = request.request_id;
      record.request_generation = request.request_generation;
      record.request_identity = request.request_identity;
      record.unit_index = unit.index;
      record.is_root = unit.index == 0;
      record.parent_unit_index = 0;
      record.output_kind = unit.output_kind;
      record.reproducibility = request.policy.reproducibility;
      record.created_at = impl_->now();
      record.updated_at = record.created_at;
      record.environment_identity = compute_environment_identity(request.environment);
      record.policy_identity = request.policy.identity_digest;
      record.specialization_identity = request.specialization.identity_digest;
      record.toolchain_identity = request.toolchain.identity_digest;
      record.target_identity = request.target.identity_digest;
      record.dependency_identity = request.dependencies.identity_digest;
      record.policy_generation = request.policy.generation;
      record.specialization_generation = request.specialization.generation;
      record.toolchain_generation = request.toolchain.generation;
      record.target_generation = request.target.generation;
      record.dependency_generation = request.dependencies.generation;

      // Source identity binds every source and dependency content this unit
      // reads, so a content edit can never be invisible to cache validation.
      CanonicalWriter w;
      w.domain("dc.unit-source-identity.v1");
      w.digest(unit.identity_digest);
      w.list(static_cast<std::uint32_t>(unit.sources.size()));
      for (const auto& source : unit.sources) {
        w.str(source.logical_name);
        w.digest(source.content.digest);
      }
      w.list(static_cast<std::uint32_t>(unit.dependencies.size()));
      for (const auto& dep : unit.dependencies) {
        w.str(dep.name);
        w.digest(dep.content.digest);
      }
      record.source_identity = w.hash();

      impl_->state.compilations.emplace(compilation_id, record);
      std::vector<std::byte> payload = encode_compilation_payload(record);
      Status persist_status = impl_->persist(RecordType::Compilation, payload);
      if (!persist_status.ok()) return Result<SubmissionResult>(persist_status);
    } else if (bundle.force_rebuild && existing->second.state == CompilationState::Committed) {
      CompilationRecord& record = existing->second;
      record.generation = record.generation.next();
      auto prior = impl_->state.authoritative.find(record.id);
      if (prior != impl_->state.authoritative.end()) {
        auto commit = impl_->state.commits.find(prior->second);
        if (commit != impl_->state.commits.end()) {
          commit->second.superseded = true;
          std::vector<std::byte> payload = encode_commit_payload(commit->second);
          Status persist_status = impl_->persist(RecordType::Commit, payload);
          if (!persist_status.ok()) return Result<SubmissionResult>(persist_status);
        }
        impl_->state.authoritative.erase(prior);
      }
      record.state = CompilationState::Pending;
      record.cache_hit = false;
      record.commit.reset();
      record.reproducibility_violation = false;
      record.divergent_candidates.clear();
      record.updated_at = impl_->now();
      std::vector<std::byte> payload = encode_compilation_payload(record);
      Status persist_status = impl_->persist(RecordType::Compilation, payload);
      if (!persist_status.ok()) return Result<SubmissionResult>(persist_status);
    } else if (existing->second.unit_index > unit.index) {
      existing->second.unit_index = unit.index;
    }
  }
  std::sort(job.mandatory_units.begin(), job.mandatory_units.end());
  job.mandatory_units.erase(std::unique(job.mandatory_units.begin(), job.mandatory_units.end()),
                            job.mandatory_units.end());
  impl_->state.jobs[request.request_identity] = job;
  {
    std::vector<std::byte> payload;
    detail::encode_job_record(job, payload);
    Status persist_status = impl_->persist(RecordType::Job, payload);
    if (!persist_status.ok()) return Result<SubmissionResult>(persist_status);
  }

  for (const auto& unit : request.units) {
    UnitSubmission submission;
    submission.index = unit.index;
    const CompilationId compilation_id = derive_compilation_id(unit.identity_digest);
    CompilationRecord& record = impl_->state.compilations[compilation_id];
    submission.compilation = record.id;
    submission.unit = record.unit;
    submission.unit_generation = record.unit_generation;
    submission.unit_identity = record.unit_identity;
    submission.state = record.state;

    // Cache consultation comes first: an identical resubmission must travel the
    // validated-reuse path rather than short-circuiting on the commit record,
    // because that path is the one that re-proves every identity dimension.
    if (request.policy.cache != CachePolicy::Bypass) {
      auto index = impl_->state.cache_index.find(record.unit_identity);
      if (index == impl_->state.cache_index.end()) {
        submission.cache.outcome = CacheOutcome::Miss;
        submission.cache.reason = "no cache entry for this unit identity";
      } else {
        auto entry = impl_->state.cache_entries.find(index->second);
        if (entry == impl_->state.cache_entries.end()) {
          submission.cache.outcome = CacheOutcome::Corrupt;
          submission.cache.reason = "cache index points at a missing entry";
        } else {
          CacheDecision decision = impl_->evaluate_cache_metadata(record, entry->second);
          if (decision.reusable()) {
            decision = impl_->evaluate_cache_blob(record, entry->second,
                                                  impl_->has_blob(entry->second.artifact.digest));
          }
          submission.cache = decision;
          if (decision.reusable()) {
            // A compilation that already holds an authoritative commit stays
            // Committed; the cache hit is recorded as the reuse path.
            record.state = impl_->state.authoritative.count(record.id) != 0 ? CompilationState::Committed
                                                                            : CompilationState::CacheHit;
            record.cache_hit = true;
            record.updated_at = impl_->now();
            submission.state = record.state;
            submission.committed = true;
            auto commit = impl_->state.commits.find(entry->second.commit);
            if (commit != impl_->state.commits.end()) submission.commit = commit->second;
            impl_->touch_cache_entry(entry->second);
            std::vector<std::byte> payload = encode_compilation_payload(record);
            Status persist_status = impl_->persist(RecordType::Compilation, payload);
            if (!persist_status.ok()) return Result<SubmissionResult>(persist_status);
            result.served_from_cache = true;
            submission.detail = "validated cache reuse: " + decision.reason;
            result.units.push_back(std::move(submission));
            continue;
          }
        }
      }
    } else {
      submission.cache.outcome = CacheOutcome::Miss;
      submission.cache.reason = "cache policy is BYPASS";
    }

    if (record.state == CompilationState::Committed && !bundle.force_rebuild) {
      submission.committed = true;
      auto commit = impl_->state.authoritative.find(record.id);
      if (commit != impl_->state.authoritative.end()) {
        auto found = impl_->state.commits.find(commit->second);
        if (found != impl_->state.commits.end()) submission.commit = found->second;
      }
      submission.detail = "served from the authoritative commit record";
      result.served_from_cache = true;
      result.units.push_back(std::move(submission));
      continue;
    }

    record.state = CompilationState::Pending;
    record.cache_hit = false;
    submission.state = record.state;
    submission.scheduled = true;
    submission.detail = "queued for assignment";
    result.units.push_back(std::move(submission));
  }

  result.all_committed = true;
  for (const auto& unit : result.units) {
    if (!unit.committed) result.all_committed = false;
  }
  JobRecord& stored_job = impl_->state.jobs[request.request_identity];
  stored_job.committed = result.all_committed;
  if (result.all_committed) stored_job.committed_unit = stored_job.units.empty()
                                                            ? CompilationId(0)
                                                            : stored_job.units[stored_job.root_index];
  {
    std::vector<std::byte> payload;
    detail::encode_job_record(stored_job, payload);
    Status persist_status = impl_->persist(RecordType::Job, payload);
    if (!persist_status.ok()) return Result<SubmissionResult>(persist_status);
  }
  return Result<SubmissionResult>(result);
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------
bool Coordinator::Impl::unit_ready(const CompilationRecord& compilation) const {
  const CompilationRequest* request = find_request(compilation.request_identity);
  if (request == nullptr) return false;
  const CompilationUnitSpec* unit = request->find_unit(compilation.unit_index);
  if (unit == nullptr) return false;
  if (unit->kind != UnitKind::Link) return true;
  auto job = state.jobs.find(compilation.request_identity);
  if (job == state.jobs.end()) return false;
  for (std::uint32_t child : unit->child_units) {
    if (child >= job->second.units.size()) return false;
    auto child_record = state.compilations.find(job->second.units[child]);
    if (child_record == state.compilations.end()) return false;
    if (child_record->second.state != CompilationState::Committed &&
        child_record->second.state != CompilationState::CacheHit) {
      return false;
    }
  }
  return true;
}

std::optional<Assignment> Coordinator::Impl::build_assignment(const WorkerRecord& worker,
                                                              CompilationRecord& compilation,
                                                              bool speculative) {
  const CompilationRequest* request = find_request(compilation.request_identity);
  if (request == nullptr) return std::nullopt;
  const CompilationUnitSpec* unit = request->find_unit(compilation.unit_index);
  if (unit == nullptr) return std::nullopt;

  Assignment assignment;
  assignment.session = worker.session;
  assignment.worker = worker.id;
  assignment.worker_boot = worker.boot;
  assignment.worker_generation = worker.generation;
  assignment.compilation = compilation.id;
  assignment.compilation_generation = compilation.generation;
  assignment.unit = compilation.unit;
  assignment.unit_generation = compilation.unit_generation;
  assignment.unit_index = unit->index;
  assignment.kind = unit->kind;
  assignment.output_kind = unit->output_kind;
  assignment.logical_name = unit->logical_name;
  assignment.toolchain = request->toolchain;
  assignment.target = request->target;
  assignment.specialization = request->specialization;
  assignment.policy = request->policy;
  assignment.environment = request->environment;
  assignment.validation = request->validation;
  assignment.max_compile_millis = config.max_compile_millis;
  assignment.speculative = speculative;

  for (const auto& source : unit->sources) {
    Result<std::vector<std::byte>> bytes = load_blob(source.content.digest);
    if (!bytes.ok()) return std::nullopt;
    AssignmentSource payload;
    payload.logical_name = source.logical_name;
    payload.format = source.format;
    payload.language_mode = source.language_mode;
    payload.bytes = std::move(bytes.value());
    assignment.sources.push_back(std::move(payload));
  }
  for (const auto& dep : unit->dependencies) {
    Result<std::vector<std::byte>> bytes = load_blob(dep.content.digest);
    if (!bytes.ok()) return std::nullopt;
    AssignmentDependency payload;
    payload.name = dep.name;
    payload.kind = dep.kind;
    payload.bytes = std::move(bytes.value());
    assignment.dependencies.push_back(std::move(payload));
  }
  assignment.flags = unit->flags;

  if (unit->kind == UnitKind::Link) {
    auto job = state.jobs.find(compilation.request_identity);
    if (job == state.jobs.end()) return std::nullopt;
    for (std::uint32_t child : unit->child_units) {
      if (child >= job->second.units.size()) return std::nullopt;
      auto child_record = state.compilations.find(job->second.units[child]);
      if (child_record == state.compilations.end()) return std::nullopt;
      auto commit = state.authoritative.find(child_record->second.id);
      if (commit == state.authoritative.end()) return std::nullopt;
      auto commit_record = state.commits.find(commit->second);
      if (commit_record == state.commits.end()) return std::nullopt;
      Result<std::vector<std::byte>> bytes = load_blob(commit_record->second.artifact_digest);
      if (!bytes.ok()) return std::nullopt;
      AssignmentChild payload;
      payload.logical_name = child_record->second.unit_identity.hex().substr(0, 16);
      const CompilationRequest* child_request = find_request(child_record->second.request_identity);
      if (child_request != nullptr) {
        const CompilationUnitSpec* child_unit = child_request->find_unit(child_record->second.unit_index);
        if (child_unit != nullptr) payload.logical_name = child_unit->logical_name;
      }
      payload.kind = commit_record->second.artifact_generation.is_zero() ? OutputKind::Object
                                                                        : child_record->second.output_kind;
      payload.bytes = std::move(bytes.value());
      assignment.children.push_back(std::move(payload));
    }
  }

  compilation.attempt_ordinal_counter += 1;
  const std::uint32_t ordinal = compilation.attempt_ordinal_counter;
  const CompilationAttemptId attempt_id(state.header.next_attempt_id++);
  const CompilationAttemptGeneration attempt_generation(ordinal);
  const LeaseId lease_id(state.header.next_lease_id++);
  // A lease generation is monotonic per compilation, so a lease issued for an
  // earlier attempt ordinal can never satisfy a later claim.
  const LeaseGeneration lease_generation(ordinal);

  CompilationAttempt attempt;
  attempt.id = attempt_id;
  attempt.generation = attempt_generation;
  attempt.compilation = compilation.id;
  attempt.compilation_generation = compilation.generation;
  attempt.unit = compilation.unit;
  attempt.worker = worker.id;
  attempt.worker_boot = worker.boot;
  attempt.worker_generation = worker.generation;
  attempt.lease = lease_id;
  attempt.lease_generation = lease_generation;
  attempt.epoch = state.header.epoch;
  attempt.state = AttemptState::Created;
  attempt.ordinal = ordinal;
  attempt.speculative = speculative;
  attempt.created_at = now();
  Status moved = transition_attempt(attempt, AttemptState::Eligible);
  if (!moved.ok()) return std::nullopt;
  moved = transition_attempt(attempt, AttemptState::Assigned);
  if (!moved.ok()) return std::nullopt;

  CompileLease lease;
  lease.id = lease_id;
  lease.generation = lease_generation;
  lease.compilation = compilation.id;
  lease.compilation_generation = compilation.generation;
  lease.unit = compilation.unit;
  lease.attempt = attempt_id;
  lease.worker = worker.id;
  lease.worker_boot = worker.boot;
  lease.worker_generation = worker.generation;
  lease.epoch = state.header.epoch;
  lease.issued_at = now();

  assignment.attempt = attempt_id;
  assignment.attempt_generation = attempt_generation;
  assignment.lease = lease;

  AuthorityClaim claim;
  claim.epoch = state.header.epoch;
  claim.compilation = compilation.id;
  claim.compilation_generation = compilation.generation;
  claim.unit = compilation.unit;
  claim.unit_generation = compilation.unit_generation;
  claim.attempt = attempt_id;
  claim.attempt_generation = attempt_generation;
  claim.worker = worker.id;
  claim.worker_boot = worker.boot;
  claim.worker_generation = worker.generation;
  claim.lease = lease_id;
  claim.lease_generation = lease_generation;
  claim.source_generation = compilation.source_generation;
  claim.ir_generation = compilation.ir_generation;
  claim.dependency_generation = compilation.dependency_generation;
  claim.toolchain_generation = compilation.toolchain_generation;
  claim.target_generation = compilation.target_generation;
  claim.specialization_generation = compilation.specialization_generation;
  claim.policy_generation = compilation.policy_generation;
  claim.cache_generation = state.header.cache_generation;
  claim.request_identity = compilation.request_identity;
  claim.unit_identity = compilation.unit_identity;
  assignment.claim = claim;

  state.leases[lease_id] = lease;
  state.attempts[attempt_id] = attempt;
  compilation.attempts.push_back(attempt_id);
  compilation.current_attempt = attempt_id;
  compilation.state = CompilationState::Assigned;
  compilation.updated_at = now();

  WorkerRecord* live = find_worker(worker.id);
  if (live != nullptr) {
    live->in_flight += 1;
    live->active_leases.push_back(lease_id);
  }

  std::vector<std::byte> payload = encode_lease_payload(lease);
  (void)persist(RecordType::Lease, payload);
  payload = encode_attempt_payload(attempt);
  (void)persist(RecordType::Attempt, payload);
  payload = encode_compilation_payload(compilation);
  (void)persist(RecordType::Compilation, payload);
  if (live != nullptr) {
    payload = encode_worker_payload(*live);
    (void)persist(RecordType::Worker, payload);
  }
  return assignment;
}

std::vector<Assignment> Coordinator::pump() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<Assignment> assignments;
  if (!impl_->opened) return assignments;

  for (auto& kv : impl_->state.compilations) {
    CompilationRecord& compilation = kv.second;
    if (compilation.state != CompilationState::Pending && compilation.state != CompilationState::Eligible) {
      continue;
    }
    if (impl_->state.authoritative.count(compilation.id) != 0) continue;
    bool in_flight = false;
    for (CompilationAttemptId id : compilation.attempts) {
      auto attempt = impl_->state.attempts.find(id);
      if (attempt != impl_->state.attempts.end() && holds_commit_authority(attempt->second.state)) {
        in_flight = true;
        break;
      }
    }
    if (in_flight) continue;
    if (!impl_->unit_ready(compilation)) {
      compilation.state = CompilationState::Eligible;
      continue;
    }

    const HardRequirements requirements = impl_->requirements_for(compilation);
    std::vector<WorkerRecord> eligible = impl_->eligible_workers(requirements, {});
    if (eligible.empty()) {
      compilation.state = CompilationState::Eligible;
      compilation.failure_detail = "no eligible worker";
      compilation.failure = ErrorCode::NoEligibleWorker;
      continue;
    }
    const std::vector<RankedWorker> ranked = rank_workers(eligible, requirements, 0);
    if (ranked.empty()) {
      compilation.state = CompilationState::Eligible;
      continue;
    }
    const WorkerRecord* chosen = nullptr;
    for (const auto& worker : eligible) {
      if (worker.id == ranked.front().id && worker.boot == ranked.front().boot) {
        chosen = &worker;
        break;
      }
    }
    if (chosen == nullptr) continue;

    std::optional<Assignment> assignment = impl_->build_assignment(*chosen, compilation, false);
    if (!assignment.has_value()) continue;
    assignments.push_back(std::move(*assignment));

    const CompilationRequest* request = impl_->find_request(compilation.request_identity);
    if (request != nullptr && request->policy.allow_speculative_duplication && ranked.size() >= 2) {
      const WorkerRecord* alternate = nullptr;
      for (const auto& worker : eligible) {
        if (worker.id == ranked[1].id && worker.boot == ranked[1].boot) {
          alternate = &worker;
          break;
        }
      }
      if (alternate != nullptr) {
        std::optional<Assignment> duplicate = impl_->build_assignment(*alternate, compilation, true);
        if (duplicate.has_value()) assignments.push_back(std::move(*duplicate));
      }
    }
  }
  return assignments;
}

std::vector<ControlMessage> Coordinator::drain_controls() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<ControlMessage> out;
  out.swap(impl_->state.controls);
  return out;
}

// ---------------------------------------------------------------------------
// Failure handling
// ---------------------------------------------------------------------------
Status Coordinator::Impl::fail_attempt_locked(CompilationAttempt& attempt, ErrorCode code, std::string detail,
                                              bool produced_candidate) {
  AttemptState next = AttemptState::Failed;
  if (code == ErrorCode::Fenced || code == ErrorCode::StaleWorkerBoot ||
      code == ErrorCode::StaleWorkerGeneration) {
    next = AttemptState::Fenced;
  } else if (code == ErrorCode::Cancelled) {
    next = AttemptState::Cancelled;
  } else if (code == ErrorCode::Ambiguous) {
    next = AttemptState::Ambiguous;
  }
  if (attempt.state != next) {
    Status moved = transition_attempt(attempt, next);
    if (!moved.ok() && !is_terminal_state(attempt.state)) return moved;
  }
  attempt.failure = code;
  attempt.failure_detail = std::move(detail);
  (void)produced_candidate;
  finish_attempt_bookkeeping(attempt);
  std::vector<std::byte> payload = encode_attempt_payload(attempt);
  return persist(RecordType::Attempt, payload);
}

void Coordinator::Impl::schedule_retry_or_fail(CompilationRecord& compilation, ErrorCode code,
                                               std::string detail) {
  const CompilationRequest* request = find_request(compilation.request_identity);
  std::uint32_t max_attempts = 1;
  if (request != nullptr) {
    max_attempts = std::max<std::uint32_t>(1, std::min<std::uint32_t>(
                                                  request->policy.max_attempts_per_unit,
                                                  config.max_attempts_hard_cap));
  }
  const FailureClass klass = classify_failure(code);
  const bool may_retry = klass != FailureClass::NonRetryable && compilation.attempt_ordinal_counter < max_attempts;
  if (may_retry) {
    compilation.state = CompilationState::Eligible;
    compilation.failure = code;
    compilation.failure_detail = std::move(detail);
  } else {
    compilation.state = CompilationState::Failed;
    compilation.failure = code;
    compilation.failure_detail = std::move(detail);
    if (klass == FailureClass::Ambiguous) compilation.state = CompilationState::Ambiguous;
  }
  compilation.updated_at = now();
  propagate_fan_in_failure(compilation.id);
}

// A link unit may only commit when every mandatory child is authoritative. The
// converse also has to hold: when a mandatory child can never become
// authoritative, the parent must fail rather than wait forever for a gate that
// will never open.
void Coordinator::Impl::propagate_fan_in_failure(CompilationId failed) {
  for (auto& job_kv : state.jobs) {
    JobRecord& job = job_kv.second;
    const CompilationRequest* request = find_request(job.request_identity);
    if (request == nullptr) continue;
    for (CompilationId unit_id : job.units) {
      if (unit_id.is_zero() || unit_id == failed) continue;
      auto parent = state.compilations.find(unit_id);
      if (parent == state.compilations.end()) continue;
      if (parent->second.state == CompilationState::Committed ||
          parent->second.state == CompilationState::CacheHit ||
          parent->second.state == CompilationState::Failed ||
          parent->second.state == CompilationState::Cancelled) {
        continue;
      }
      const CompilationUnitSpec* unit = request->find_unit(parent->second.unit_index);
      if (unit == nullptr || unit->kind != UnitKind::Link) continue;
      bool depends = false;
      for (std::uint32_t child : unit->child_units) {
        if (child < job.units.size() && job.units[child] == failed) depends = true;
      }
      if (!depends || !unit->mandatory) continue;
      auto child_record = state.compilations.find(failed);
      if (child_record == state.compilations.end()) continue;
      const CompilationState child_state = child_record->second.state;
      if (child_state != CompilationState::Failed && child_state != CompilationState::Cancelled &&
          child_state != CompilationState::Ambiguous && child_state != CompilationState::Fenced) {
        continue;
      }
      parent->second.state = CompilationState::Failed;
      parent->second.failure = ErrorCode::FanInIncomplete;
      parent->second.failure_detail = "mandatory child compilation " + std::to_string(failed.value()) +
                                      " cannot become authoritative (state " +
                                      std::string(to_string(child_state)) + ")";
      parent->second.updated_at = now();
      std::vector<std::byte> payload = encode_compilation_payload(parent->second);
      (void)persist(RecordType::Compilation, payload);
      job.failure = ErrorCode::FanInIncomplete;
      job.failure_detail = parent->second.failure_detail;
      std::vector<std::byte> job_payload;
      detail::encode_job_record(job, job_payload);
      (void)persist(RecordType::Job, job_payload);
    }
  }
}

Status Coordinator::fail_attempt(SessionId session_id, const AttemptFailure& failure) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status open_status = impl_->ensure_open();
  if (!open_status.ok()) return open_status;

  auto attempt = impl_->state.attempts.find(failure.claim.attempt);
  if (attempt == impl_->state.attempts.end()) {
    impl_->record_violation("fail_attempt", ErrorCode::StaleAttempt, session_id, WorkerId(0),
                            "failure report for an unknown attempt");
    return Status::error(ErrorCode::StaleAttempt, "unknown attempt");
  }
  auto compilation = impl_->state.compilations.find(failure.claim.compilation);
  if (compilation == impl_->state.compilations.end()) {
    return Status::error(ErrorCode::StaleCompilation, "unknown compilation");
  }
  const detail::SessionRecord* session = impl_->find_session(session_id);
  if (session == nullptr || !session->is_worker || session->worker != attempt->second.worker ||
      session->boot != attempt->second.worker_boot) {
    impl_->record_violation("fail_attempt", ErrorCode::StaleWorkerBoot, session_id,
                            session == nullptr ? WorkerId(0) : session->worker,
                            "failure report from a session that does not own the attempt");
    return Status::error(ErrorCode::StaleWorkerBoot, "session does not own this attempt");
  }
  const AuthorityExpectation expected = impl_->expectation_for(compilation->second, attempt->second);
  Status authority = validate_authority(failure.claim, expected);
  if (!authority.ok()) {
    impl_->record_violation("fail_attempt", authority.code(), session_id, session->worker, authority.detail());
    return authority;
  }
  CompilationAttempt& target = attempt->second;
  if (is_terminal_state(target.state)) return Status::success();
  Status moved = impl_->fail_attempt_locked(target, failure.code, failure.detail, true);
  if (!moved.ok()) return moved;
  impl_->schedule_retry_or_fail(compilation->second, failure.code, failure.detail);
  std::vector<std::byte> payload = encode_compilation_payload(compilation->second);
  return impl_->persist(RecordType::Compilation, payload);
}

Status Coordinator::disconnect_session(SessionId session_id, const std::string& reason) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!impl_->opened) return Status::success();
  auto found = impl_->state.sessions.find(session_id);
  if (found == impl_->state.sessions.end()) return Status::success();
  detail::SessionRecord session = found->second;
  session.open = false;
  impl_->state.sessions[session_id] = session;

  if (!session.is_worker) return Status::success();
  WorkerRecord* worker = impl_->find_worker(session.worker);
  if (worker == nullptr) return Status::success();
  if (worker->boot != session.boot) {
    // A reconnect already replaced this session; the old session must not be
    // able to fence the live worker.
    return Status::success();
  }

  // Every attempt bound to this boot loses its authority. A running attempt may
  // have produced a result the coordinator never saw, so it is classified
  // AMBIGUOUS rather than Failed: it can never commit, but the work is
  // re-issued as a fresh attempt generation.
  for (auto& kv : impl_->state.attempts) {
    CompilationAttempt& attempt = kv.second;
    if (attempt.worker != session.worker || attempt.worker_boot != session.boot) continue;
    if (is_terminal_state(attempt.state)) continue;
    const bool was_running = attempt.state == AttemptState::Running ||
                             attempt.state == AttemptState::Preparing ||
                             attempt.state == AttemptState::Produced ||
                             attempt.state == AttemptState::Validating;
    const ErrorCode code = was_running ? ErrorCode::Ambiguous : ErrorCode::Fenced;
    (void)impl_->fail_attempt_locked(attempt, code, "worker session lost: " + reason, false);
    auto compilation = impl_->state.compilations.find(attempt.compilation);
    if (compilation != impl_->state.compilations.end()) {
      impl_->schedule_retry_or_fail(compilation->second, code, "worker session lost: " + reason);
      std::vector<std::byte> payload = encode_compilation_payload(compilation->second);
      (void)impl_->persist(RecordType::Compilation, payload);
    }
  }
  impl_->fence_worker(*worker, "worker session lost: " + reason);
  std::vector<std::byte> payload = encode_worker_payload(*worker);
  (void)impl_->persist(RecordType::Worker, payload);
  return Status::success();
}

Status Coordinator::cancel(CompilationId id, const std::string& reason) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status open_status = impl_->ensure_open();
  if (!open_status.ok()) return open_status;
  auto compilation = impl_->state.compilations.find(id);
  if (compilation == impl_->state.compilations.end()) {
    return Status::error(ErrorCode::NotFound, "unknown compilation");
  }
  CompilationRecord& record = compilation->second;
  if (record.state == CompilationState::Committed) {
    return Status::error(ErrorCode::ArtifactAlreadyCommitted,
                         "compilation already has an authoritative artifact");
  }

  for (CompilationAttemptId attempt_id : record.attempts) {
    auto attempt = impl_->state.attempts.find(attempt_id);
    if (attempt == impl_->state.attempts.end()) continue;
    CompilationAttempt& target = attempt->second;
    if (is_terminal_state(target.state)) continue;
    const WorkerRecord* worker = impl_->find_worker(target.worker);
    ControlMessage control;
    if (worker != nullptr) control.session = worker->session;
    control.kind = ControlKind::CancelAttempt;
    control.compilation = record.id;
    control.compilation_generation = record.generation;
    control.attempt = target.id;
    control.attempt_generation = target.generation;
    control.lease = target.lease;
    control.lease_generation = target.lease_generation;
    control.reason = reason;
    impl_->state.controls.push_back(control);
    (void)impl_->fail_attempt_locked(target, ErrorCode::Cancelled, reason, true);
  }
  for (auto& kv : impl_->state.leases) {
    if (kv.second.compilation != record.id || kv.second.revoked) continue;
    kv.second.revoked = true;
    kv.second.revocation_reason = "compilation cancelled: " + reason;
    std::vector<std::byte> payload = encode_lease_payload(kv.second);
    (void)impl_->persist(RecordType::Lease, payload);
  }
  record.state = CompilationState::Cancelled;
  record.failure = ErrorCode::Cancelled;
  record.failure_detail = reason;
  record.updated_at = impl_->now();
  std::vector<std::byte> payload = encode_compilation_payload(record);
  return impl_->persist(RecordType::Compilation, payload);
}

// ---------------------------------------------------------------------------
// Worker lifecycle
// ---------------------------------------------------------------------------
Result<RegisteredWorker> Coordinator::register_worker(const WorkerRegistration& registration) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status open_status = impl_->ensure_open();
  if (!open_status.ok()) return Result<RegisteredWorker>(open_status);
  if (registration.worker_id.is_zero() || registration.boot_id.is_zero()) {
    return Result<RegisteredWorker>(
        Status::error(ErrorCode::InvalidArgument, "worker id and boot id are required"));
  }
  WorkerCapabilities capabilities = registration.capabilities;
  if (capabilities.toolchains.size() > 64 || capabilities.targets.size() > 64 ||
      capabilities.input_formats.size() > 64 || capabilities.plugins.size() > 256 ||
      capabilities.sdks.size() > 64) {
    return Result<RegisteredWorker>(
        Status::error(ErrorCode::LimitExceeded, "worker capability advertisement exceeds bounds"));
  }
  canonicalize(capabilities);
  if (capabilities.host.empty()) capabilities.host = registration.host;

  if (impl_->state.workers.size() >= impl_->config.max_workers &&
      impl_->state.workers.count(registration.worker_id) == 0) {
    return Result<RegisteredWorker>(Status::error(ErrorCode::LimitExceeded, "worker table is full"));
  }

  WorkerRecord* existing = impl_->find_worker(registration.worker_id);
  WorkerRecord worker;
  WorkerGeneration generation(1);
  if (existing != nullptr) {
    worker = *existing;
    // A fresh boot always gets a fresh generation. Reconnecting with the same
    // boot id still advances the generation, so authority bound to the previous
    // generation can never be inherited.
    generation = worker.generation.is_zero() ? WorkerGeneration(1) : worker.generation.next();
  } else {
    worker.id = registration.worker_id;
  }

  worker.boot = registration.boot_id;
  worker.generation = generation;
  worker.session = SessionId(impl_->state.header.next_session_id++);
  worker.endpoint = registration.endpoint;
  worker.host = registration.host.empty() ? capabilities.host : registration.host;
  worker.capabilities = capabilities;
  worker.capabilities.host = worker.host;
  worker.health = capabilities.evidence == EvidenceClass::Unknown ? WorkerHealth::Unknown : WorkerHealth::Healthy;
  worker.ready = false;
  worker.fenced = false;
  worker.in_flight = 0;
  worker.queue_depth = 0;
  worker.active_leases.clear();
  worker.registered_at = impl_->now();
  worker.last_seen = worker.registered_at;
  worker.trusted_evidence_fresh = capabilities.evidence == EvidenceClass::Real;

  detail::SessionRecord session;
  session.id = worker.session;
  session.is_worker = true;
  session.worker = worker.id;
  session.boot = worker.boot;
  session.epoch = impl_->state.header.epoch;
  session.peer = registration.endpoint;
  session.host = worker.host;
  session.connected_at = worker.registered_at;
  session.last_seen = worker.registered_at;
  session.open = true;
  session.max_inflight = std::max<std::uint32_t>(1, std::min<std::uint32_t>(registration.max_inflight, 64));
  impl_->state.sessions[session.id] = session;
  impl_->state.workers[worker.id] = worker;

  std::vector<std::byte> payload = encode_worker_payload(worker);
  Status persist_status = impl_->persist_entity(RecordType::Worker, payload);
  if (!persist_status.ok()) return Result<RegisteredWorker>(persist_status);

  RegisteredWorker registered;
  registered.session = worker.session;
  registered.worker = worker.id;
  registered.boot = worker.boot;
  registered.generation = worker.generation;
  registered.epoch = impl_->state.header.epoch;
  registered.detail = existing != nullptr ? "reconnect with a fresh boot identity" : "admitted";
  return Result<RegisteredWorker>(registered);
}

Status Coordinator::advertise_capabilities(SessionId session_id, const WorkerCapabilities& capabilities) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status open_status = impl_->ensure_open();
  if (!open_status.ok()) return open_status;
  const detail::SessionRecord* session = impl_->find_session(session_id);
  if (session == nullptr || !session->is_worker) {
    return Status::error(ErrorCode::Unauthorized, "session is not a worker session");
  }
  WorkerRecord* worker = impl_->find_worker(session->worker);
  if (worker == nullptr) return Status::error(ErrorCode::NotFound, "unknown worker");
  if (worker->boot != session->boot) {
    impl_->record_violation("advertise_capabilities", ErrorCode::StaleWorkerBoot, session_id, session->worker,
                            "capability advertisement from a superseded boot");
    return Status::error(ErrorCode::StaleWorkerBoot, "worker boot identity has been superseded");
  }
  WorkerCapabilities updated = capabilities;
  canonicalize(updated);
  updated.host = worker->host;
  worker->capabilities = updated;
  worker->health = updated.evidence == EvidenceClass::Unknown ? WorkerHealth::Unknown : WorkerHealth::Healthy;
  worker->trusted_evidence_fresh = updated.evidence == EvidenceClass::Real;
  worker->last_seen = impl_->now();
  std::vector<std::byte> payload = encode_worker_payload(*worker);
  return impl_->persist_entity(RecordType::Worker, payload);
}

Status Coordinator::mark_ready(SessionId session_id) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status open_status = impl_->ensure_open();
  if (!open_status.ok()) return open_status;
  const detail::SessionRecord* session = impl_->find_session(session_id);
  if (session == nullptr || !session->is_worker) {
    return Status::error(ErrorCode::Unauthorized, "session is not a worker session");
  }
  WorkerRecord* worker = impl_->find_worker(session->worker);
  if (worker == nullptr) return Status::error(ErrorCode::NotFound, "unknown worker");
  if (worker->boot != session->boot) {
    return Status::error(ErrorCode::StaleWorkerBoot, "worker boot identity has been superseded");
  }
  if (worker->capabilities.evidence == EvidenceClass::Unknown) {
    // A worker with no capability evidence may not become ready: eligibility
    // would then be decided on UNKNOWN, which fails closed anyway, and a
    // "ready" label without evidence would be a lie.
    return Status::error(ErrorCode::Unknown,
                         "worker cannot become ready without evidence-backed capabilities");
  }
  worker->ready = true;
  worker->health = WorkerHealth::Healthy;
  worker->last_seen = impl_->now();
  std::vector<std::byte> payload = encode_worker_payload(*worker);
  return impl_->persist(RecordType::Worker, payload);
}

Status Coordinator::heartbeat(SessionId session_id) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status open_status = impl_->ensure_open();
  if (!open_status.ok()) return open_status;
  detail::SessionRecord* session = nullptr;
  auto found = impl_->state.sessions.find(session_id);
  if (found != impl_->state.sessions.end()) session = &found->second;
  if (session == nullptr || !session->open) {
    return Status::error(ErrorCode::StaleSession, "session is not open at this epoch");
  }
  session->last_seen = impl_->now();
  if (session->is_worker) {
    WorkerRecord* worker = impl_->find_worker(session->worker);
    if (worker == nullptr) return Status::error(ErrorCode::NotFound, "unknown worker");
    if (worker->boot != session->boot) {
      return Status::error(ErrorCode::StaleWorkerBoot, "worker boot identity has been superseded");
    }
    worker->last_seen = session->last_seen;
    if (worker->health == WorkerHealth::Suspect) worker->health = WorkerHealth::Healthy;
  }
  return Status::success();
}

Status Coordinator::begin_compile(const AuthorityClaim& claim) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status open_status = impl_->ensure_open();
  if (!open_status.ok()) return open_status;

  auto attempt = impl_->state.attempts.find(claim.attempt);
  if (attempt == impl_->state.attempts.end()) {
    impl_->record_violation("begin_compile", ErrorCode::StaleAttempt, SessionId(0), WorkerId(0),
                            "begin for an unknown attempt");
    return Status::error(ErrorCode::StaleAttempt, "unknown attempt");
  }
  auto compilation = impl_->state.compilations.find(claim.compilation);
  if (compilation == impl_->state.compilations.end()) {
    return Status::error(ErrorCode::StaleCompilation, "unknown compilation");
  }
  const AuthorityExpectation expected = impl_->expectation_for(compilation->second, attempt->second);
  Status authority = validate_authority(claim, expected);
  if (!authority.ok()) {
    impl_->record_violation("begin_compile", authority.code(), SessionId(0), attempt->second.worker,
                            authority.detail());
    return authority;
  }
  CompilationAttempt& target = attempt->second;
  if (target.state != AttemptState::Assigned && target.state != AttemptState::Preparing &&
      target.state != AttemptState::Running) {
    return Status::error(ErrorCode::StaleAttempt,
                         "attempt is in state " + std::string(to_string(target.state)));
  }
  if (target.state == AttemptState::Assigned) {
    Status moved = impl_->transition_attempt(target, AttemptState::Preparing);
    if (!moved.ok()) return moved;
    target.started_at = impl_->now();
    // Starting a speculative sibling must never drag a compilation that has
    // already committed back out of Committed.
    if (compilation->second.state != CompilationState::Committed) {
      compilation->second.state = CompilationState::Running;
    }
    compilation->second.updated_at = target.started_at;
  }
  std::vector<std::byte> payload = encode_attempt_payload(target);
  Status persist_status = impl_->persist(RecordType::Attempt, payload);
  if (!persist_status.ok()) return persist_status;
  payload = encode_compilation_payload(compilation->second);
  return impl_->persist(RecordType::Compilation, payload);
}

Status Coordinator::handle_validate_response(SessionId session_id, std::uint32_t mode,
                                              EvidenceClass evidence, const Digest256& capabilities_digest,
                                              const std::string& detail) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status open_status = impl_->ensure_open();
  if (!open_status.ok()) return open_status;
  const detail::SessionRecord* session = impl_->find_session(session_id);
  if (session == nullptr || !session->is_worker) {
    return Status::error(ErrorCode::Unauthorized, "session is not a worker session");
  }
  WorkerRecord* worker = impl_->find_worker(session->worker);
  if (worker == nullptr) return Status::error(ErrorCode::NotFound, "unknown worker");
  if (worker->boot != session->boot) {
    // A response from a superseded boot proves nothing about the live worker.
    return Status::error(ErrorCode::StaleWorkerBoot, "validate response from a superseded boot");
  }
  if (mode != 0) return Status::success();
  if (capabilities_digest != worker->capabilities.digest) {
    // The toolchain the worker can actually see has changed since it
    // registered. Its old advertisement is not evidence of the current state.
    worker->trusted_evidence_fresh = false;
    worker->ready = false;
    worker->health = WorkerHealth::Suspect;
    impl_->record_violation("validate_output", ErrorCode::StaleToolchain, session_id, worker->id,
                            "evidence revalidation produced a different capability digest: " + detail);
    std::vector<std::byte> payload = encode_worker_payload(*worker);
    return impl_->persist(RecordType::Worker, payload);
  }
  worker->trusted_evidence_fresh = evidence == EvidenceClass::Real;
  worker->last_seen = impl_->now();
  std::vector<std::byte> payload = encode_worker_payload(*worker);
  return impl_->persist(RecordType::Worker, payload);
}

Status Coordinator::shutdown_sessions() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!impl_->opened) return Status::success();
  for (const auto& kv : impl_->state.sessions) {
    if (!kv.second.open || !kv.second.is_worker) continue;
    ControlMessage control;
    control.session = kv.first;
    control.kind = ControlKind::Shutdown;
    control.reason = "coordinator shutdown";
    impl_->state.controls.push_back(control);
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------
Result<CommitDecision> Coordinator::Impl::commit_locked(SessionId session, const ReportOutput& output,
                                                        const ValidationReport& validation) {
  CommitDecision decision;
  auto attempt_it = state.attempts.find(output.claim.attempt);
  auto compilation_it = state.compilations.find(output.claim.compilation);
  if (attempt_it == state.attempts.end() || compilation_it == state.compilations.end()) {
    return Result<CommitDecision>(Status::error(ErrorCode::StaleAttempt, "attempt or compilation vanished"));
  }
  CompilationAttempt& attempt = attempt_it->second;
  CompilationRecord& compilation = compilation_it->second;
  const detail::SessionRecord* session_record = find_session(session);
  const WorkerId worker_id = session_record != nullptr ? session_record->worker : attempt.worker;

  const Digest256 artifact_digest = attempt.candidate.digest;
  if (artifact_digest.is_zero()) {
    return Result<CommitDecision>(Status::error(ErrorCode::IntegrityFailure, "candidate digest is absent"));
  }

  if (validation.aggregate != ValidationOutcome::Pass) {
    decision.outcome = CommitOutcome::Refused;
    decision.error = ErrorCode::ValidationFailure;
    decision.detail = "candidate artifact failed validation: " + validation.summary;
    decision.validation = validation;
    (void)fail_attempt_locked(attempt, ErrorCode::ValidationFailure, decision.detail, true);
    compilation.state = CompilationState::Failed;
    compilation.failure = ErrorCode::ValidationFailure;
    compilation.failure_detail = decision.detail;
    compilation.updated_at = now();
    std::vector<std::byte> payload = encode_compilation_payload(compilation);
    (void)persist(RecordType::Compilation, payload);
    return Result<CommitDecision>(decision);
  }

  auto existing = state.authoritative.find(compilation.id);
  if (existing != state.authoritative.end()) {
    auto prior = state.commits.find(existing->second);
    if (prior != state.commits.end() && !prior->second.superseded) {
      if (prior->second.artifact_digest == artifact_digest) {
        // Equivalent duplicate: the same logical artifact converged. No second
        // authority is created. The attempt still has to walk the legal
        // lifecycle, because a duplicate arrives in Produced and Committed is
        // only reachable from CommitReady.
        Status moved = Status::success();
        if (attempt.state == AttemptState::Produced) moved = transition_attempt(attempt, AttemptState::Validating);
        if (moved.ok() && attempt.state == AttemptState::Validating) {
          moved = transition_attempt(attempt, AttemptState::CommitReady);
        }
        if (moved.ok()) moved = transition_attempt(attempt, AttemptState::Committed);
        if (!moved.ok()) {
          (void)fail_attempt_locked(attempt, ErrorCode::IllegalTransition, moved.detail(), true);
          return Result<CommitDecision>(moved);
        }
        attempt.failure = ErrorCode::Ok;
        attempt.failure_detail = "deduplicated into authoritative commit " +
                                 std::to_string(prior->second.id.value());
        finish_attempt_bookkeeping(attempt);
        std::vector<std::byte> payload = encode_attempt_payload(attempt);
        (void)persist(RecordType::Attempt, payload);
        if (compilation.state != CompilationState::Committed) {
          compilation.state = CompilationState::Committed;
          compilation.updated_at = now();
          std::vector<std::byte> restored = encode_compilation_payload(compilation);
          (void)persist(RecordType::Compilation, restored);
        }
        decision.outcome = CommitOutcome::Deduplicated;
        decision.commit = prior->second;
        decision.validation = validation;
        decision.artifact_authoritative = true;
        decision.detail = "equivalent candidate deduplicated onto the existing authoritative commit";
        return Result<CommitDecision>(decision);
      }

      // Divergent output for one logical compilation.
      compilation.divergent_candidates.push_back(ContentRef{artifact_digest, attempt.candidate.size});
      if (compilation.reproducibility == ReproducibilityRequirement::Required) {
        compilation.reproducibility_violation = true;
        decision.outcome = CommitOutcome::ReproducibilityViolation;
        decision.error = ErrorCode::ReproducibilityViolation;
        decision.detail = "reproducibility is REQUIRED but two workers produced different digests for one "
                          "logical compilation";
        (void)fail_attempt_locked(attempt, ErrorCode::ReproducibilityViolation, decision.detail, true);
        std::vector<std::byte> payload = encode_compilation_payload(compilation);
        (void)persist(RecordType::Compilation, payload);
        return Result<CommitDecision>(decision);
      }
      decision.outcome = CommitOutcome::Refused;
      decision.error = ErrorCode::ArtifactMismatch;
      decision.detail = "candidate digest differs from the authoritative artifact; refusing to select a winner "
                        "silently";
      (void)fail_attempt_locked(attempt, ErrorCode::ArtifactMismatch, decision.detail, true);
      std::vector<std::byte> payload = encode_compilation_payload(compilation);
      (void)persist(RecordType::Compilation, payload);
      return Result<CommitDecision>(decision);
    }
  }

  // First authoritative commit for this logical compilation.
  Status moved = transition_attempt(attempt, AttemptState::Validating);
  if (!moved.ok()) return Result<CommitDecision>(moved);
  compilation.state = CompilationState::Validating;
  compilation.updated_at = now();

  ValidationReport stored_validation = validation;
  stored_validation.id = ValidationId(state.header.next_validation_id++);
  state.validations[stored_validation.id] = stored_validation;

  Provenance provenance;
  provenance.id = ProvenanceId(state.header.next_provenance_id++);
  provenance.generation = ProvenanceGeneration(1);
  provenance.compilation = compilation.id;
  provenance.compilation_generation = compilation.generation;
  provenance.unit = compilation.unit;
  provenance.attempt = attempt.id;
  provenance.attempt_generation = attempt.generation;
  provenance.epoch = state.header.epoch;
  provenance.worker = attempt.worker;
  provenance.worker_boot = attempt.worker_boot;
  provenance.worker_generation = attempt.worker_generation;
  provenance.lease = attempt.lease;
  provenance.lease_generation = attempt.lease_generation;
  provenance.request_id = compilation.request_id;
  provenance.request_identity = compilation.request_identity;
  provenance.unit_identity = compilation.unit_identity;
  provenance.artifact = ContentRef{artifact_digest, attempt.candidate.size};
  provenance.source_identity = compilation.source_identity;
  provenance.dependency_identity = compilation.dependency_identity;
  provenance.toolchain_identity = compilation.toolchain_identity;
  provenance.target_identity = compilation.target_identity;
  provenance.specialization_identity = compilation.specialization_identity;
  provenance.policy_identity = compilation.policy_identity;
  provenance.validation = stored_validation.id;
  provenance.evidence = EvidenceClass::Real;
  provenance.compiler_invocation = attempt.compiler_invocation;
  provenance.compiler_version_string = attempt.compiler_version_string;
  provenance.compiler_wall_millis = attempt.compiler_wall_millis;
  provenance.produced_at = now();

  const std::uint64_t artifact_id_value = state.header.next_artifact_id++;
  ArtifactCommit commit;
  commit.id = ArtifactCommitId(state.header.next_commit_id++);
  commit.generation = ArtifactCommitGeneration(1);
  commit.compilation = compilation.id;
  commit.compilation_generation = compilation.generation;
  commit.unit = compilation.unit;
  commit.artifact = ArtifactId(artifact_id_value);
  commit.artifact_generation = ArtifactGeneration(1);
  commit.artifact_digest = artifact_digest;
  commit.provenance = provenance.id;
  commit.validation = stored_validation.id;
  commit.epoch = state.header.epoch;
  commit.worker = attempt.worker;
  commit.worker_boot = attempt.worker_boot;
  commit.attempt = attempt.id;
  commit.committed_at = now();
  commit.deduplicated = false;

  attempt.artifact = commit.artifact;
  moved = transition_attempt(attempt, AttemptState::CommitReady);
  if (!moved.ok()) return Result<CommitDecision>(moved);
  compilation.state = CompilationState::CommitReady;
  moved = transition_attempt(attempt, AttemptState::Committed);
  if (!moved.ok()) return Result<CommitDecision>(moved);
  compilation.state = CompilationState::Committed;
  compilation.commit = commit;
  compilation.failure = ErrorCode::Ok;
  compilation.failure_detail.clear();
  compilation.updated_at = now();
  finish_attempt_bookkeeping(attempt);

  state.validations[stored_validation.id] = stored_validation;
  state.provenances[provenance.id] = provenance;
  state.commits[commit.id] = commit;
  state.authoritative[compilation.id] = commit.id;

  if (compilation.output_kind == OutputKind::Object) {
    IntermediateArtifact intermediate;
    intermediate.id = IntermediateId(state.header.next_intermediate_id++);
    intermediate.generation = IntermediateGeneration(1);
    intermediate.kind = IntermediateKind::ObjectFile;
    intermediate.content = ContentRef{artifact_digest, attempt.candidate.size};
    // The intermediate is bound to the unit content identity as well as to the
    // toolchain and target, so a filename match alone never justifies reuse.
    intermediate.provenance_identity = provenance.unit_identity;
    intermediate.toolchain_identity = compilation.toolchain_identity;
    intermediate.target_identity = compilation.target_identity;
    intermediate.dependency_identity = compilation.dependency_identity;
    intermediate.compilation = compilation.id;
    intermediate.compilation_generation = compilation.generation;
    intermediate.authoritative = true;
    state.intermediates[intermediate.id] = intermediate;
    CanonicalWriter w;
    encode_intermediate(w, intermediate);
    std::vector<std::byte> payload(w.bytes().begin(), w.bytes().end());
    (void)persist(RecordType::Intermediate, payload);
  }

  record_cache_entry(compilation, commit, provenance, stored_validation);
  mark_job_progress(compilation);
  enqueue_cancel_losers(compilation, attempt.id);

  std::vector<std::byte> payload = encode_validation_payload(stored_validation);
  (void)persist(RecordType::Validation, payload);
  payload = encode_provenance_payload(provenance);
  (void)persist(RecordType::Provenance, payload);
  payload = encode_commit_payload(commit);
  Status commit_persisted = persist(RecordType::Commit, payload);
  if (!commit_persisted.ok()) return Result<CommitDecision>(commit_persisted);
  payload = encode_attempt_payload(attempt);
  (void)persist(RecordType::Attempt, payload);
  payload = encode_compilation_payload(compilation);
  (void)persist(RecordType::Compilation, payload);
  if (WorkerRecord* worker = find_worker(worker_id)) {
    payload = encode_worker_payload(*worker);
    (void)persist(RecordType::Worker, payload);
  }

  // Notify the winning worker that its output became authoritative.
  ControlMessage control;
  control.session = session;
  control.kind = ControlKind::CommitNotification;
  control.compilation = compilation.id;
  control.compilation_generation = compilation.generation;
  control.attempt = attempt.id;
  control.attempt_generation = attempt.generation;
  control.commit = commit.id;
  control.artifact_digest = artifact_digest;
  state.controls.push_back(control);

  decision.outcome = CommitOutcome::Committed;
  decision.commit = commit;
  decision.validation = stored_validation;
  decision.artifact_authoritative = true;
  decision.detail = "authoritative artifact committed";
  return Result<CommitDecision>(decision);
}

void Coordinator::Impl::mark_job_progress(CompilationRecord& compilation) {
  auto job = state.jobs.find(compilation.request_identity);
  if (job == state.jobs.end()) return;
  bool all = true;
  for (CompilationId unit : job->second.units) {
    if (unit.is_zero()) continue;
    auto record = state.compilations.find(unit);
    if (record == state.compilations.end()) {
      all = false;
      break;
    }
    if (record->second.state != CompilationState::Committed && record->second.state != CompilationState::CacheHit) {
      all = false;
      break;
    }
  }
  job->second.committed = all;
  if (all) job->second.committed_unit = job->second.units.empty() ? CompilationId(0)
                                                                  : job->second.units[job->second.root_index];
  std::vector<std::byte> payload;
  detail::encode_job_record(job->second, payload);
  (void)persist(RecordType::Job, payload);
}

Result<CommitDecision> Coordinator::report_output(SessionId session_id, const ReportOutput& output) {
  Digest256 candidate_digest;
  TargetIdentity target;
  ValidationRequirements requirements;
  OutputKind output_kind = OutputKind::Object;
  std::size_t candidate_size = 0;

  // ---- Phase 1: reservation ----
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    Status open_status = impl_->ensure_open();
    if (!open_status.ok()) return Result<CommitDecision>(open_status);

    auto attempt = impl_->state.attempts.find(output.claim.attempt);
    if (attempt == impl_->state.attempts.end()) {
      impl_->record_violation("report_output", ErrorCode::StaleAttempt, session_id, WorkerId(0),
                              "report for an unknown attempt");
      return Result<CommitDecision>(Status::error(ErrorCode::StaleAttempt, "unknown attempt"));
    }
    auto compilation = impl_->state.compilations.find(output.claim.compilation);
    if (compilation == impl_->state.compilations.end()) {
      return Result<CommitDecision>(Status::error(ErrorCode::StaleCompilation, "unknown compilation"));
    }
    const detail::SessionRecord* session = impl_->find_session(session_id);
    if (session == nullptr || !session->is_worker) {
      return Result<CommitDecision>(Status::error(ErrorCode::Unauthorized, "session is not a worker session"));
    }
    if (session->worker != attempt->second.worker || session->boot != attempt->second.worker_boot) {
      impl_->record_violation("report_output", ErrorCode::StaleWorkerBoot, session_id, session->worker,
                              "report from a session that does not own the attempt");
      return Result<CommitDecision>(
          Status::error(ErrorCode::StaleWorkerBoot, "session does not own this attempt"));
    }
    const AuthorityExpectation expected = impl_->expectation_for(compilation->second, attempt->second);
    Status authority = validate_authority(output.claim, expected);
    if (!authority.ok()) {
      impl_->record_violation("report_output", authority.code(), session_id, session->worker, authority.detail());
      return Result<CommitDecision>(authority);
    }
    CompilationAttempt& target_attempt = attempt->second;
    if (target_attempt.state != AttemptState::Running && target_attempt.state != AttemptState::Preparing) {
      return Result<CommitDecision>(Status::error(
          ErrorCode::StaleAttempt, "attempt is in state " + std::string(to_string(target_attempt.state))));
    }
    if (output.bytes.size() > impl_->config.max_artifact_bytes) {
      return Result<CommitDecision>(
          Status::error(ErrorCode::LimitExceeded, "reported artifact exceeds the configured bound"));
    }
    candidate_size = output.bytes.size();
    candidate_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
    if (!output.declared_digest.is_zero() && candidate_digest != output.declared_digest) {
      return Result<CommitDecision>(
          Status::error(ErrorCode::IntegrityFailure, "reported artifact does not match its declared digest"));
    }
    target_attempt.candidate = ContentRef{candidate_digest, candidate_size};
    target_attempt.candidate_digest = candidate_digest;
    target_attempt.compiler_invocation = output.compiler_invocation;
    target_attempt.compiler_version_string = output.compiler_version_string;
    target_attempt.compiler_wall_millis = output.compiler_wall_millis;
    Status moved = impl_->transition_attempt(target_attempt, AttemptState::Produced);
    if (!moved.ok()) return Result<CommitDecision>(moved);
    // A compilation that already holds an authoritative commit must not be
    // dragged backwards by a duplicate report: the reservation only marks work
    // in progress for a compilation that has not committed yet.
    if (compilation->second.state != CompilationState::Committed &&
        impl_->state.authoritative.count(compilation->second.id) == 0) {
      compilation->second.state = CompilationState::Producing;
    }
    compilation->second.updated_at = impl_->now();

    const CompilationRequest* request = impl_->find_request(compilation->second.request_identity);
    if (request != nullptr) {
      target = request->target;
      requirements = request->validation;
      output_kind = output.kind;
      const CompilationUnitSpec* unit = request->find_unit(compilation->second.unit_index);
      if (unit != nullptr) output_kind = unit->output_kind;
    }
    std::vector<std::byte> payload = encode_attempt_payload(target_attempt);
    Status persist_status = impl_->persist(RecordType::Attempt, payload);
    if (!persist_status.ok()) return Result<CommitDecision>(persist_status);
    payload = encode_compilation_payload(compilation->second);
    (void)impl_->persist(RecordType::Compilation, payload);
  }

  // ---- Phase 2: unlocked work (digest re-verification, validation, storage) ----
  const Digest256 verified = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
  if (verified != candidate_digest) {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    return Result<CommitDecision>(
        Status::error(ErrorCode::IntegrityFailure, "candidate bytes changed while being validated"));
  }
  ValidationReport validation = validate_artifact_bytes(
      std::span<const std::byte>(output.bytes.data(), output.bytes.size()), output_kind, target, requirements,
      candidate_digest);
  // A smoke test executes the artifact, so it is meaningful only for a unit that
  // produces an executable. Applying a request-level smoke test to an
  // intermediate object would fail every fan-out job for the wrong reason.
  const bool executable_output = output_kind == OutputKind::Executable;
  if (requirements.require_smoke_test && executable_output &&
      validation.aggregate == ValidationOutcome::Pass) {
    // The smoke test executes the produced binary on the coordinator, which is
    // the only way to prove the artifact is loadable by an independent process.
    Workspace scratch;
    auto workspace = Workspace::create(impl_->config.state_root / "scratch",
                                       "smoke-" + std::to_string(output.claim.attempt.value()));
    if (workspace.ok()) {
      scratch = std::move(workspace.value());
      const std::string file_name = output.logical_name.empty() ? "artifact.exe" : "artifact.bin";
      Status written = scratch.write_file(
          file_name, std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
      if (written.ok()) {
        auto resolved = scratch.resolve(file_name);
        if (resolved.ok()) {
          validation.checks.push_back(run_smoke_test(resolved.value(), requirements.smoke_expected_stdout,
                                                     requirements.smoke_timeout_ms));
          validation.aggregate = ValidationOutcome::Pass;
          for (const auto& check : validation.checks) {
            if (check.outcome == ValidationOutcome::Fail) validation.aggregate = ValidationOutcome::Fail;
          }
        }
      }
      (void)scratch.cleanup();
    } else {
      ValidationCheck check;
      check.check = "smoke_test";
      check.outcome = ValidationOutcome::Fail;
      check.detail = "could not create a scratch workspace for the smoke test";
      validation.checks.push_back(check);
      validation.aggregate = ValidationOutcome::Fail;
    }
  }
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    Status stored = impl_->store_blob(output.bytes);
    if (!stored.ok()) return Result<CommitDecision>(stored);
  }

  // ---- Phase 3: revalidation and commit ----
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    auto attempt = impl_->state.attempts.find(output.claim.attempt);
    if (attempt == impl_->state.attempts.end()) {
      return Result<CommitDecision>(Status::error(ErrorCode::StaleAttempt, "attempt disappeared"));
    }
    auto compilation = impl_->state.compilations.find(output.claim.compilation);
    if (compilation == impl_->state.compilations.end()) {
      return Result<CommitDecision>(Status::error(ErrorCode::StaleCompilation, "compilation disappeared"));
    }
    const AuthorityExpectation expected = impl_->expectation_for(compilation->second, attempt->second);
    Status authority = validate_authority(output.claim, expected);
    if (!authority.ok()) {
      impl_->record_violation("commit_revalidate", authority.code(), session_id, attempt->second.worker,
                              authority.detail());
      Status moved = impl_->transition_attempt(attempt->second, AttemptState::Fenced);
      if (moved.ok()) {
        impl_->finish_attempt_bookkeeping(attempt->second);
        std::vector<std::byte> payload = encode_attempt_payload(attempt->second);
        (void)impl_->persist(RecordType::Attempt, payload);
      }
      CommitDecision decision;
      decision.outcome = CommitOutcome::Refused;
      decision.error = authority.code();
      decision.detail = "authority moved while the candidate was being validated: " + authority.detail();
      return Result<CommitDecision>(decision);
    }
    return impl_->commit_locked(session_id, output, validation);
  }
}

}  // namespace dc
