// Distributed Compilation - example: the distributed compilation transaction.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Runs a complete transaction in-process against a durable coordinator:
// canonicalize, cache consult, assign, compile through a real adapter, validate,
// commit exactly once, then prove validated reuse and dependency invalidation.
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "dc/codec.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"

using namespace dc;

namespace {

void line(const std::string& text) { std::printf("%s\n", text.c_str()); }

Blob make_blob(const std::string& text) {
  Blob blob;
  blob.bytes.assign(reinterpret_cast<const std::byte*>(text.data()),
                    reinterpret_cast<const std::byte*>(text.data()) + text.size());
  blob.digest = sha256(std::span<const std::byte>(blob.bytes.data(), blob.bytes.size()));
  return blob;
}

ToolchainIdentity synthetic_toolchain() {
  DiscoveryOptions options;
  options.include_synthetic = true;
  options.cuda_roots = {};
  options.msvc_roots = {};
  for (const auto& candidate : discover_toolchains(options).toolchains) {
    if (candidate.family == CompilerFamily::SyntheticGeneric) return candidate;
  }
  return discover_toolchains(options).toolchains.front();
}

TargetIdentity synthetic_target() {
  DiscoveryOptions options;
  options.include_synthetic = true;
  options.cuda_roots = {};
  options.msvc_roots = {};
  for (const auto& candidate : discover_toolchains(options).targets) {
    if (candidate.evidence == EvidenceClass::Synthetic) return candidate;
  }
  return TargetIdentity{};
}

SubmissionBundle build(const std::string& source_text, const std::string& dependency_text) {
  SubmissionBundle bundle;
  bundle.request.toolchain = synthetic_toolchain();
  bundle.request.target = synthetic_target();
  bundle.request.request_id = RequestId(1);
  bundle.request.policy.require_provable_toolchain = false;
  bundle.request.policy.reproducibility = ReproducibilityRequirement::Preferred;
  const Blob source = make_blob(source_text);
  const Blob dependency = make_blob(dependency_text);
  CompilationUnitSpec unit;
  unit.index = 0;
  unit.logical_name = "unit.cpp";
  unit.kind = UnitKind::Compile;
  unit.output_kind = OutputKind::Assembly;
  UnitSource unit_source;
  unit_source.logical_name = "unit.cpp";
  unit_source.format = InputFormat::Source;
  unit_source.language_mode = "c++20";
  unit_source.content.digest = source.digest;
  unit_source.content.size = source.bytes.size();
  unit.sources.push_back(unit_source);
  DependencyEntry entry;
  entry.name = "config.h";
  entry.kind = DependencyKind::Header;
  entry.content.digest = dependency.digest;
  entry.content.size = dependency.bytes.size();
  unit.dependencies.push_back(entry);
  bundle.request.units.push_back(unit);
  bundle.request.dependencies.entries.push_back(entry);
  bundle.blobs.push_back(source);
  bundle.blobs.push_back(dependency);
  return bundle;
}

Status drive(Coordinator& coordinator, const std::filesystem::path& scratch) {
  const std::vector<Assignment> assignments = coordinator.pump();
  if (assignments.empty()) return Status::error(ErrorCode::NotFound, "no assignment was produced");
  for (const auto& assignment : assignments) {
    const Status begun = coordinator.begin_compile(assignment.claim);
    if (!begun.ok()) return begun;
    const std::vector<WorkerRecord> workers = coordinator.workers();
    const ToolchainIdentity* toolchain = nullptr;
    for (const auto& worker : workers) {
      for (const auto& advertised : worker.capabilities.toolchains) {
        if (advertised.identity_digest == assignment.toolchain.identity_digest) toolchain = &advertised;
      }
    }
    if (toolchain == nullptr) return Status::error(ErrorCode::NotFound, "assigned toolchain not advertised");
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
    if (decision.value().outcome != CommitOutcome::Committed &&
        decision.value().outcome != CommitOutcome::Deduplicated) {
      return Status::error(decision.value().error, decision.value().detail);
    }
  }
  return Status::success();
}

}  // namespace

int main() {
  const std::filesystem::path root = std::filesystem::temp_directory_path() /
                                     ("dc-example-" + std::to_string(static_cast<long long>(SystemClock().now())));
  CoordinatorConfig config;
  config.state_root = root / "state";
  Coordinator coordinator;
  if (!coordinator.open(config).ok()) {
    line("example: cannot open the coordinator");
    return 1;
  }

  WorkerCapabilities capabilities;
  capabilities.toolchains = {synthetic_toolchain()};
  capabilities.targets = {synthetic_target()};
  capabilities.input_formats = {InputFormat::Source};
  capabilities.logical_cores = 4;
  capabilities.memory_bytes = 4ull * 1024 * 1024 * 1024;
  capabilities.scratch_bytes = 4ull * 1024 * 1024 * 1024;
  capabilities.max_artifact_bytes = 16ull * 1024 * 1024;
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
  registration.worker_id = WorkerId(1);
  registration.boot_id = WorkerBootId(2);
  registration.max_inflight = 2;
  registration.capabilities = capabilities;
  auto registered = coordinator.register_worker(registration);
  if (!registered.ok()) {
    line("example: worker registration refused: " + registered.status().describe());
    return 1;
  }
  (void)coordinator.mark_ready(registered.value().session);
  const SessionId session = registered.value().session;

  SubmissionBundle bundle = build("int f() { return 7; }\n", "#pragma once\n#define VALUE 7\n");
  auto submitted = coordinator.submit(bundle);
  if (!submitted.ok()) {
    line("example: submission refused: " + submitted.status().describe());
    return 1;
  }
  const CompilationId compilation = submitted.value().units.front().compilation;
  line("1. submitted: compilation " + std::to_string(compilation.value()) +
       " cache=" + std::string(to_string(submitted.value().units.front().cache.outcome)));

  (void)session;
  const Status driven = drive(coordinator, root / "scratch");
  if (!driven.ok()) {
    line("example: transaction failed: " + driven.describe());
    return 1;
  }
  auto commit = coordinator.commit(compilation);
  line("2. committed: " + (commit.ok() ? commit.value().artifact_digest.hex() : commit.status().describe()));
  if (commit.ok()) {
    auto provenance = coordinator.provenance(commit.value().provenance);
    if (provenance.ok()) {
      line("   provenance " + std::to_string(provenance.value().id.value()) + " evidence " +
           std::string(to_string(provenance.value().evidence)) + " compiler " +
           provenance.value().compiler_version_string);
    }
  }

  auto reused = coordinator.submit(bundle);
  line(std::string("3. resubmitted: served from validated reuse=") +
       (reused.ok() && reused.value().served_from_cache ? "yes" : "no") +
       " cache=" + (reused.ok() ? std::string(to_string(reused.value().units.front().cache.outcome))
                                : std::string("n/a")));

  SubmissionBundle mutated = build("int f() { return 7; }\n", "#pragma once\n#define VALUE 8\n");
  auto invalidated = coordinator.submit(mutated);
  line(std::string("4. dependency changed: reuse refused=") +
       (invalidated.ok() && !invalidated.value().served_from_cache ? "yes" : "no") +
       " new identity=" +
       (invalidated.ok() &&
                invalidated.value().units.front().compilation != compilation
            ? "yes"
            : "no"));

  const AuditReport audit = coordinator.audit();
  line(std::string("5. audit clean=") + (audit.clean ? "yes" : "no") + " compilations=" +
       std::to_string(audit.compilations) + " committed=" + std::to_string(audit.committed));

  const ExplainReport explanation = coordinator.explain(compilation);
  line("6. explanation:");
  for (const auto& entry : explanation.lines) line("   " + entry);

  coordinator.close();
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  return audit.clean ? 0 : 1;
}
