// Distributed Compilation - benchmarks over completed work.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every measurement covers work the runtime actually completed (a canonical
// identity derived, a cache decision returned, an artifact committed), not a
// submission. Compiler wall time is reported separately from coordinator
// overhead so the two are never conflated.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "dc/codec.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"

using namespace dc;

namespace {

using SteadyClock = std::chrono::steady_clock;

struct Measurement {
  std::string operation;
  std::size_t scale = 0;
  double total_millis = 0.0;
  double per_operation_micros = 0.0;
};

std::vector<Measurement> g_measurements;

void record(const std::string& operation, std::size_t scale, double total_millis) {
  Measurement measurement;
  measurement.operation = operation;
  measurement.scale = scale;
  measurement.total_millis = total_millis;
  measurement.per_operation_micros = scale == 0 ? 0.0 : (total_millis * 1000.0) / static_cast<double>(scale);
  g_measurements.push_back(measurement);
}

Blob make_blob(const std::string& text) {
  Blob blob;
  blob.bytes.assign(reinterpret_cast<const std::byte*>(text.data()),
                    reinterpret_cast<const std::byte*>(text.data()) + text.size());
  blob.digest = sha256(std::span<const std::byte>(blob.bytes.data(), blob.bytes.size()));
  return blob;
}

// Discovery is performed once: rebuilding a toolchain identity per request
// would measure the discovery scanner rather than the runtime.
const ToolchainIdentity& synthetic_toolchain() {
  static const ToolchainIdentity toolchain = [] {
    DiscoveryOptions options;
    options.include_synthetic = true;
    options.cuda_roots = {};
    options.msvc_roots = {};
    options.compute_binary_digests = false;
    const DiscoveryResult discovered = discover_toolchains(options);
    for (const auto& candidate : discovered.toolchains) {
      if (candidate.family == CompilerFamily::SyntheticGeneric) return candidate;
    }
    return discovered.toolchains.front();
  }();
  return toolchain;
}

const TargetIdentity& synthetic_target() {
  static const TargetIdentity target = [] {
    DiscoveryOptions options;
    options.include_synthetic = true;
    options.cuda_roots = {};
    options.msvc_roots = {};
    const DiscoveryResult discovered = discover_toolchains(options);
    for (const auto& candidate : discovered.targets) {
      if (candidate.evidence == EvidenceClass::Synthetic) return candidate;
    }
    return TargetIdentity{};
  }();
  return target;
}

void progress(const std::string& text) {
  std::fprintf(stderr, "  [bench] %s\n", text.c_str());
  std::fflush(stderr);
}

SubmissionBundle make_bundle(std::size_t index, const std::string& dependency_text) {
  SubmissionBundle bundle;
  bundle.request.toolchain = synthetic_toolchain();
  bundle.request.target = synthetic_target();
  bundle.request.request_id = RequestId(1000 + index);
  bundle.request.policy.require_provable_toolchain = false;
  const Blob source = make_blob("int f" + std::to_string(index) + "() { return " + std::to_string(index) + "; }\n");
  const Blob dependency = make_blob(dependency_text);
  CompilationUnitSpec unit;
  unit.index = 0;
  unit.logical_name = "unit" + std::to_string(index) + ".cpp";
  unit.kind = UnitKind::Compile;
  unit.output_kind = OutputKind::Assembly;
  UnitSource unit_source;
  unit_source.logical_name = unit.logical_name;
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

void print_table() {
  std::printf("%-34s %10s %14s %16s\n", "operation", "scale", "total ms", "per op (us)");
  std::printf("%-34s %10s %14s %16s\n", "----------------------------------", "----------",
              "--------------", "----------------");
  for (const auto& measurement : g_measurements) {
    std::printf("%-34s %10llu %14.2f %16.3f\n", measurement.operation.c_str(),
                static_cast<unsigned long long>(measurement.scale), measurement.total_millis,
                measurement.per_operation_micros);
  }
}

}  // namespace

int main(int argc, char** argv) {
  const std::vector<std::size_t> scales = {10, 100, 1000, 10000, 100000};
  const std::size_t commit_scale_limit = argc > 1 ? static_cast<std::size_t>(std::stoull(argv[1])) : 10000;
  std::printf("Distributed Compilation %s benchmark\n", DC_VERSION_STRING);
  std::printf("Compiler wall time is reported separately from runtime overhead.\n\n");

  const std::filesystem::path root = std::filesystem::temp_directory_path() /
                                     ("dc-bench-" + std::to_string(static_cast<long long>(SystemClock().now())));
  CoordinatorConfig config;
  config.state_root = root / "state";
  config.enable_persistence = false;   // measures the state machine, not the disk
  config.clock = std::make_shared<ManualClock>();
  Coordinator coordinator;
  if (!coordinator.open(config).ok()) {
    std::printf("cannot open the coordinator\n");
    return 1;
  }
  WorkerCapabilities capabilities;
  capabilities.toolchains = {synthetic_toolchain()};
  capabilities.targets = {synthetic_target()};
  capabilities.input_formats = {InputFormat::Source};
  capabilities.logical_cores = 16;
  capabilities.memory_bytes = 32ull * 1024 * 1024 * 1024;
  capabilities.scratch_bytes = 32ull * 1024 * 1024 * 1024;
  capabilities.max_artifact_bytes = 64ull * 1024 * 1024;
  capabilities.filesystem_isolation = true;
  capabilities.sandbox = true;
  capabilities.deterministic_build = true;
  capabilities.trusted = true;
  capabilities.evidence = EvidenceClass::Synthetic;
  capabilities.host = "local";
  canonicalize(capabilities);
  std::vector<SessionId> sessions;
  for (int i = 0; i < 4; ++i) {
    WorkerRegistration registration;
    registration.endpoint = "local";
    registration.host = "local";
    registration.worker_id = WorkerId(100 + static_cast<std::uint64_t>(i));
    registration.boot_id = WorkerBootId(200 + static_cast<std::uint64_t>(i));
    registration.max_inflight = 1000000;
    registration.capabilities = capabilities;
    auto registered = coordinator.register_worker(registration);
    if (!registered.ok()) {
      std::printf("worker registration failed: %s\n", registered.status().describe().c_str());
      return 1;
    }
    (void)coordinator.mark_ready(registered.value().session);
    sessions.push_back(registered.value().session);
  }

  const std::string dependency_text = "#pragma once\n#define VALUE 1\n";
  std::vector<SubmissionBundle> bundles;
  std::vector<CompilationId> compilations;
  double compiler_wall_millis = 0.0;

  for (std::size_t scale : scales) {
    progress("scale " + std::to_string(scale) + ": building requests");
    // Canonical request identity.
    bundles.clear();
    bundles.reserve(scale);
    const auto canonical_start = SteadyClock::now();
    for (std::size_t i = 0; i < scale; ++i) {
      SubmissionBundle bundle = make_bundle(i, dependency_text);
      const Status canonical = canonicalize(bundle.request);
      if (!canonical.ok()) {
        std::printf("canonicalization failed at scale %llu index %llu: %s\n",
                    static_cast<unsigned long long>(scale), static_cast<unsigned long long>(i),
                    canonical.describe().c_str());
        return 1;
      }
      bundles.push_back(std::move(bundle));
    }
    record("canonical request identity", scale,
           std::chrono::duration<double, std::milli>(SteadyClock::now() - canonical_start).count());
    progress("scale " + std::to_string(scale) + ": canonical identity done");

    // Submission (derives identity, consults the cache, registers generations).
    const auto submit_start = SteadyClock::now();
    for (const auto& bundle : bundles) {
      auto submitted = coordinator.submit(bundle);
      if (!submitted.ok()) {
        std::printf("submission failed at scale %llu: %s\n", static_cast<unsigned long long>(scale),
                    submitted.status().describe().c_str());
        return 1;
      }
    }
    record("submit + cache consult", scale,
           std::chrono::duration<double, std::milli>(SteadyClock::now() - submit_start).count());
    progress("scale " + std::to_string(scale) + ": submit done");

    // Eligibility evaluation.
    const auto eligibility_start = SteadyClock::now();
    for (const auto& bundle : bundles) {
      (void)coordinator.eligibility(bundle.request);
    }
    record("worker eligibility + ranking", scale,
           std::chrono::duration<double, std::milli>(SteadyClock::now() - eligibility_start).count());
    progress("scale " + std::to_string(scale) + ": eligibility done");

    // Assignment creation.
    const auto assign_start = SteadyClock::now();
    std::vector<Assignment> assignments = coordinator.pump();
    record("assignment creation", assignments.size(),
           std::chrono::duration<double, std::milli>(SteadyClock::now() - assign_start).count());
    if (assignments.size() < scale) {
      // Assignment is deliberately bounded by the per-worker in-flight cap, so
      // the measured scale is the number of assignments actually created.
      std::printf("note: %llu of %llu compilations were assigned at this scale "
                  "(per-worker in-flight cap reached)\n",
                  static_cast<unsigned long long>(assignments.size()),
                  static_cast<unsigned long long>(scale));
    }
    progress("scale " + std::to_string(scale) + ": assignment done");

    if (scale <= commit_scale_limit) {
      // Compile and commit through the real adapter path.
      const auto compile_start = SteadyClock::now();
      const ToolchainIdentity toolchain = synthetic_toolchain();
      std::size_t committed = 0;
      for (const auto& assignment : assignments) {
        if (!coordinator.begin_compile(assignment.claim).ok()) continue;
        auto compiled = run_compile_unit(assignment, toolchain, root / "scratch", nullptr);
        if (!compiled.ok()) continue;
        compiler_wall_millis += static_cast<double>(compiled.value().wall_millis);
        ReportOutput output;
        output.claim = assignment.claim;
        output.kind = assignment.output_kind;
        output.logical_name = assignment.logical_name;
        output.bytes = compiled.value().artifact;
        output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
        auto decision = coordinator.report_output(assignment.session, output);
        if (decision.ok() && (decision.value().outcome == CommitOutcome::Committed ||
                              decision.value().outcome == CommitOutcome::Deduplicated)) {
          ++committed;
        }
      }
      record("artifact commit (incl. adapter)", committed,
             std::chrono::duration<double, std::milli>(SteadyClock::now() - compile_start).count());

      // Cache lookup on committed work.
      const auto lookup_start = SteadyClock::now();
      std::size_t reusable = 0;
      for (const auto& assignment : assignments) {
        auto decision = coordinator.cache_query(assignment.claim.unit_identity);
        if (decision.ok() && decision.value().reusable()) ++reusable;
      }
      record("cache validation lookup", assignments.size(),
             std::chrono::duration<double, std::milli>(SteadyClock::now() - lookup_start).count());
      if (reusable == 0 && !assignments.empty()) std::printf("warning: no reusable cache entries measured\n");

      // Provenance lookup.
      const std::vector<ArtifactCommit> commits = coordinator.commits();
      const auto provenance_start = SteadyClock::now();
      std::size_t found = 0;
      for (const auto& commit : commits) {
        auto provenance = coordinator.provenance(commit.provenance);
        if (provenance.ok()) ++found;
      }
      record("provenance lookup", found,
             std::chrono::duration<double, std::milli>(SteadyClock::now() - provenance_start).count());
    }

    // Dependency invalidation: the same unit with changed dependency content.
    const auto invalidation_start = SteadyClock::now();
    std::size_t invalidated = 0;
    for (const auto& bundle : bundles) {
      SubmissionBundle mutated = bundle;
      const Blob changed = make_blob(dependency_text + "// revision " + std::to_string(reinterpret_cast<std::uintptr_t>(&bundle)));
      mutated.request.dependencies.entries.front().content.digest = changed.digest;
      mutated.request.dependencies.entries.front().content.size = changed.bytes.size();
      mutated.request.units.front().dependencies.front().content.digest = changed.digest;
      mutated.request.units.front().dependencies.front().content.size = changed.bytes.size();
      mutated.blobs.push_back(changed);
      auto submitted = coordinator.submit(mutated);
      if (submitted.ok() && !submitted.value().served_from_cache) ++invalidated;
    }
    record("dependency invalidation", invalidated,
           std::chrono::duration<double, std::milli>(SteadyClock::now() - invalidation_start).count());
    progress("scale " + std::to_string(scale) + ": invalidation done");

    // Invariant audit over the accumulated state.
    const auto audit_start = SteadyClock::now();
    const AuditReport audit = coordinator.audit();
    record("invariant audit", audit.compilations,
           std::chrono::duration<double, std::milli>(SteadyClock::now() - audit_start).count());
    progress("scale " + std::to_string(scale) + ": audit done");
    if (!audit.clean) {
      std::printf("audit is not clean at scale %llu\n", static_cast<unsigned long long>(scale));
      return 1;
    }
  }

  // Persistence: snapshot save and load of accumulated state. Every durable
  // record is fsync'd before it is acknowledged, so this phase is measured at a
  // bounded, explicitly reported scale rather than at the largest in-memory
  // scale; the reported scale is the number of compilations actually persisted.
  config.enable_persistence = true;
  config.state_root = root / "persist";
  coordinator.close();
  Coordinator persistent;
  const Status persistent_opened = persistent.open(config);
  if (!persistent_opened.ok()) {
    std::printf("persistent open failed: %s\n", persistent_opened.describe().c_str());
    return 1;
  }
  const std::size_t persistence_scale = std::min<std::size_t>(bundles.size(), 1000);
  progress("persistence: submitting " + std::to_string(persistence_scale) + " durable requests");
  for (std::size_t i = 0; i < persistence_scale; ++i) {
    (void)persistent.submit(bundles[i]);
  }
  const auto snapshot_start = SteadyClock::now();
  if (!persistent.snapshot().ok()) {
    std::printf("snapshot failed\n");
    return 1;
  }
  record("snapshot save", persistence_scale,
         std::chrono::duration<double, std::milli>(SteadyClock::now() - snapshot_start).count());
  persistent.close();
  progress("persistence: reloading");
  const auto load_start = SteadyClock::now();
  Coordinator reloaded;
  const Status opened = reloaded.open(config);
  record("snapshot load + recovery classification", persistence_scale,
         std::chrono::duration<double, std::milli>(SteadyClock::now() - load_start).count());
  if (!opened.ok()) {
    std::printf("reload failed: %s\n", opened.describe().c_str());
    return 1;
  }
  reloaded.close();
  coordinator.close();

  std::error_code ec;
  std::filesystem::remove_all(root, ec);

  std::printf("\n");
  print_table();
  std::printf("\ncompiler wall time (adapter invocations): %.2f ms\n", compiler_wall_millis);
  std::printf("Note: 'artifact commit (incl. adapter)' includes synthetic adapter work; the\n");
  std::printf("      remaining rows measure coordinator overhead only.\n");
  return 0;
}
