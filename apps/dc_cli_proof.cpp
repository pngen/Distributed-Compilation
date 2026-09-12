// Distributed Compilation - offline verification proof driven from the CLI.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// This runs the entire transaction in-process against a real coordinator with
// durable state, a real assignment, a real (synthetic-profile) compile through
// the adapter interface, a real commit and a real cache consultation. It exists
// so that an installed copy of the runtime can prove itself without a cluster.
#include <algorithm>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "app_common.hpp"
#include "dc/codec.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"
#include "dc/persistence.hpp"
#include "dc/wire.hpp"

namespace {

using namespace dc;
using namespace dc::app;

struct Check {
  std::string name;
  bool passed = false;
  std::string detail;
};

int fail(const std::string& message) {
  emit_error("dc_cli verify: " + message);
  return 1;
}

Blob make_blob(std::string_view text) {
  Blob blob;
  blob.bytes.assign(reinterpret_cast<const std::byte*>(text.data()),
                    reinterpret_cast<const std::byte*>(text.data()) + text.size());
  blob.digest = sha256(std::span<const std::byte>(blob.bytes.data(), blob.bytes.size()));
  return blob;
}

SubmissionBundle make_bundle(const ToolchainIdentity& toolchain, const TargetIdentity& target,
                             const Blob& source, const std::string& unit_name, OutputKind kind) {
  SubmissionBundle bundle;
  bundle.request.toolchain = toolchain;
  bundle.request.target = target;
  bundle.request.request_id = RequestId(1);
  bundle.request.policy.reproducibility = ReproducibilityRequirement::Required;
  bundle.request.policy.require_provable_toolchain = false;
  bundle.request.policy.cache = CachePolicy::ReadWrite;
  CompilationUnitSpec unit;
  unit.index = 0;
  unit.logical_name = unit_name;
  unit.kind = UnitKind::Compile;
  unit.output_kind = kind;
  UnitSource unit_source;
  unit_source.logical_name = unit_name;
  unit_source.format = InputFormat::Source;
  unit_source.language_mode = "c++20";
  unit_source.content.digest = source.digest;
  unit_source.content.size = source.bytes.size();
  unit.sources.push_back(unit_source);
  bundle.request.units.push_back(unit);
  bundle.blobs.push_back(source);
  return bundle;
}

// Drives one assignment through the real adapter and reports the result back.
Status drive_one(Coordinator& coordinator, const std::string& worker_name, const std::filesystem::path& scratch) {
  const std::vector<Assignment> assignments = coordinator.pump();
  if (assignments.empty()) return Status::error(ErrorCode::NotFound, "no assignment was produced");
  const Assignment assignment = assignments.front();
  (void)worker_name;

  // The worker record vector must outlive the toolchain pointer used below.
  const std::vector<WorkerRecord> workers = coordinator.workers();
  const ToolchainIdentity* toolchain = nullptr;
  for (const auto& candidate : workers) {
    if (candidate.id != assignment.worker) continue;
    for (const auto& advertised : candidate.capabilities.toolchains) {
      if (advertised.identity_digest == assignment.toolchain.identity_digest) toolchain = &advertised;
    }
  }
  if (toolchain == nullptr) return Status::error(ErrorCode::Internal, "assigned toolchain not found");

  // Mirror the worker protocol: a lease must be acknowledged before a result
  // may be reported.
  Status begun = coordinator.begin_compile(assignment.claim);
  if (!begun.ok()) return begun;

  auto compiled = run_compile_unit(assignment, *toolchain, scratch, nullptr);
  if (!compiled.ok()) return compiled.status();
  ReportOutput output;
  output.claim = assignment.claim;
  output.kind = assignment.output_kind;
  output.logical_name = assignment.logical_name;
  output.bytes = compiled.value().artifact;
  output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
  output.compiler_invocation = compiled.value().invocation;
  output.compiler_version_string = compiled.value().compiler_version;
  output.compiler_wall_millis = compiled.value().wall_millis;
  auto decision = coordinator.report_output(assignment.session, output);
  if (!decision.ok()) return decision.status();
  if (decision.value().outcome != CommitOutcome::Committed) {
    return Status::error(decision.value().error, decision.value().detail);
  }
  return Status::success();
}

}  // namespace

int run_verify_command(const Arguments& arguments) {
  std::vector<Check> checks;
  const auto record = [&checks](std::string name, bool passed, std::string detail) {
    checks.push_back(Check{std::move(name), passed, std::move(detail)});
    emit(std::string("[") + (passed ? "PASS" : "FAIL") + "] " + checks.back().name +
         (checks.back().detail.empty() ? "" : " - " + checks.back().detail));
  };

  const std::filesystem::path root = arguments.get("state-root", unique_temp_path("dc-verify").string());
  const std::filesystem::path state_dir = root / "state";
  const std::filesystem::path scratch = root / "scratch";
  if (!ensure_directory(state_dir).ok() || !ensure_directory(scratch).ok()) {
    return fail("cannot create verification workspace");
  }

  DiscoveryOptions discovery;
  discovery.include_synthetic = true;
  discovery.cuda_roots = {};
  discovery.msvc_roots = arguments.has("no-msvc") ? std::vector<std::filesystem::path>{} : default_msvc_roots();
  discovery.compute_binary_digests = false;
  const DiscoveryResult discovered = discover_toolchains(discovery);
  record("toolchain discovery", !discovered.toolchains.empty(),
         std::to_string(discovered.toolchains.size()) + " toolchains, " +
             std::to_string(discovered.targets.size()) + " targets");
  if (discovered.toolchains.empty()) {
    (void)remove_tree_quiet(root);
    return fail("no toolchains available for verification");
  }

  const ToolchainIdentity* toolchain = nullptr;
  for (const auto& candidate : discovered.toolchains) {
    if (candidate.family == CompilerFamily::SyntheticGeneric) toolchain = &candidate;
  }
  if (toolchain == nullptr) toolchain = &discovered.toolchains.front();
  const TargetIdentity* target = &discovered.targets.front();
  for (const auto& candidate : discovered.targets) {
    if (candidate.evidence == EvidenceClass::Synthetic) target = &candidate;
  }

  CoordinatorConfig config;
  config.state_root = state_dir;
  config.enable_persistence = true;
  config.clock = std::make_shared<ManualClock>();
  Coordinator coordinator;
  Status opened = coordinator.open(config);
  if (!opened.ok()) {
    (void)remove_tree_quiet(root);
    return fail("cannot open coordinator: " + opened.describe());
  }

  WorkerCapabilities capabilities;
  capabilities.toolchains = {*toolchain};
  capabilities.targets = {*target};
  capabilities.input_formats = {InputFormat::Source, InputFormat::Object};
  capabilities.logical_cores = 4;
  capabilities.memory_bytes = 4ull * 1024 * 1024 * 1024;
  capabilities.scratch_bytes = 4ull * 1024 * 1024 * 1024;
  capabilities.max_artifact_bytes = 64ull * 1024 * 1024;
  capabilities.filesystem_isolation = true;
  capabilities.sandbox = true;
  capabilities.deterministic_build = true;
  capabilities.trusted = true;
  capabilities.evidence = EvidenceClass::Synthetic;
  capabilities.host = "local";
  canonicalize(capabilities);

  WorkerRegistration registration;
  registration.endpoint = "local";
  registration.host = "local";
  registration.worker_id = WorkerId(101);
  registration.boot_id = WorkerBootId(1001);
  registration.max_inflight = 2;
  registration.capabilities = capabilities;
  auto registered = coordinator.register_worker(registration);
  if (!registered.ok()) {
    coordinator.close();
    (void)remove_tree_quiet(root);
    return fail("worker registration refused: " + registered.status().describe());
  }
  Status ready = coordinator.mark_ready(registered.value().session);
  record("worker admission", ready.ok(), ready.ok() ? "ready" : ready.describe());

  const Blob source = make_blob("int add(int a, int b) { return a + b; }\n");
  SubmissionBundle bundle = make_bundle(*toolchain, *target, source, "verify.cpp", OutputKind::Assembly);
  auto submitted = coordinator.submit(bundle);
  if (!submitted.ok()) {
    coordinator.close();
    (void)remove_tree_quiet(root);
    return fail("submission refused: " + submitted.status().describe());
  }
  record("canonical request identity", !submitted.value().request_identity.is_zero(),
         submitted.value().request_identity.hex());

  // Identity stability: a request rebuilt with the same content must hash equal.
  SubmissionBundle rebuilt = make_bundle(*toolchain, *target, source, "verify.cpp", OutputKind::Assembly);
  Status recanonical = canonicalize(rebuilt.request);
  record("canonicalization is deterministic",
         recanonical.ok() && rebuilt.request.request_identity == submitted.value().request_identity,
         recanonical.ok() ? "identity stable" : recanonical.describe());

  Status driven = drive_one(coordinator, "verify", scratch);
  record("assignment, compile and commit", driven.ok(), driven.ok() ? "committed" : driven.describe());

  const CompilationId compilation = submitted.value().units.front().compilation;
  auto commit = coordinator.commit(compilation);
  record("authoritative artifact", commit.ok(),
         commit.ok() ? commit.value().artifact_digest.hex() : commit.status().describe());

  auto provenance = commit.ok() ? coordinator.provenance(commit.value().provenance)
                                : Result<Provenance>(Status::error(ErrorCode::NotFound, "no commit"));
  record("provenance recorded", provenance.ok() && !provenance.value().artifact.digest.is_zero(),
         provenance.ok() ? std::string(to_string(provenance.value().evidence)) : provenance.status().describe());

  // Cache reuse: the identical request must resolve through validated reuse.
  auto resubmitted = coordinator.submit(bundle);
  record("validated cache reuse",
         resubmitted.ok() && resubmitted.value().served_from_cache && resubmitted.value().all_committed,
         resubmitted.ok() ? "cache served" : resubmitted.status().describe());

  // Dependency invalidation: changed source content is a different compilation.
  const Blob changed = make_blob("int add(int a, int b) { return a + b + 1; }\n");
  SubmissionBundle mutated = make_bundle(*toolchain, *target, changed, "verify.cpp", OutputKind::Assembly);
  auto mutated_result = coordinator.submit(mutated);
  record("content change yields a new identity",
         mutated_result.ok() && !mutated_result.value().all_committed &&
             mutated_result.value().request_identity != submitted.value().request_identity,
         mutated_result.ok() ? "new identity derived" : mutated_result.status().describe());

  Status driven2 = drive_one(coordinator, "verify", scratch);
  record("second compilation committed", driven2.ok(), driven2.ok() ? "committed" : driven2.describe());

  // Duplicate commit refusal: an equivalent report cannot create a second authority.
  const AuditReport audit = coordinator.audit();
  record("invariant audit", audit.clean, audit.render());

  // Restart durability: reopen the same state and confirm the artifact survives.
  const Digest256 committed_digest = commit.ok() ? commit.value().artifact_digest : Digest256{};
  coordinator.close();
  Coordinator reopened;
  Status reopen_status = reopened.open(config);
  record("reopen advances the epoch", reopen_status.ok() && reopened.epoch().value() >= 2,
         reopen_status.ok() ? "epoch " + std::to_string(reopened.epoch().value()) : reopen_status.describe());
  auto survived = reopened.commit(compilation);
  record("committed artifact survives restart",
         survived.ok() && survived.value().artifact_digest == committed_digest,
         survived.ok() ? survived.value().artifact_digest.hex() : survived.status().describe());
  const AuditReport reopened_audit = reopened.audit();
  record("audit after restart", reopened_audit.clean, reopened_audit.render());
  reopened.close();

  (void)remove_tree_quiet(root);

  std::size_t failures = 0;
  for (const auto& check : checks) {
    if (!check.passed) ++failures;
  }
  emit("DC_CLI_VERIFY checks=" + std::to_string(checks.size()) + " failures=" + std::to_string(failures) +
       (failures == 0 ? " ok=yes" : " ok=no"));
  return failures == 0 ? 0 : 1;
}
