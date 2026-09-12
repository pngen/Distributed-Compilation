// Distributed Compilation - concurrency and race tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "dc/codec.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"
#include "dc/persistence.hpp"
#include "dc_test.hpp"

using namespace dc;

namespace {

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

SubmissionBundle make_bundle(const std::string& source_text, std::uint64_t request_id) {
  SubmissionBundle bundle;
  bundle.request.toolchain = synthetic_toolchain();
  bundle.request.target = synthetic_target();
  bundle.request.request_id = RequestId(request_id);
  bundle.request.policy.require_provable_toolchain = false;
  const Blob source = make_blob(source_text);
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
  bundle.request.units.push_back(unit);
  bundle.blobs.push_back(source);
  return bundle;
}

struct Fixture {
  std::filesystem::path root;
  Coordinator coordinator;

  explicit Fixture(int workers) {
    root = std::filesystem::temp_directory_path() /
           ("dc-conc-" + std::to_string(static_cast<long long>(SystemClock().now())) + "-" +
            std::to_string(reinterpret_cast<std::uintptr_t>(this)));
    CoordinatorConfig config;
    config.state_root = root / "state";
    config.clock = std::make_shared<ManualClock>();
    if (!coordinator.open(config).ok()) std::abort();
    WorkerCapabilities capabilities;
    capabilities.toolchains = {synthetic_toolchain()};
    capabilities.targets = {synthetic_target()};
    capabilities.input_formats = {InputFormat::Source};
    capabilities.logical_cores = 8;
    capabilities.memory_bytes = 8ull * 1024 * 1024 * 1024;
    capabilities.scratch_bytes = 8ull * 1024 * 1024 * 1024;
    capabilities.max_artifact_bytes = 16ull * 1024 * 1024;
    capabilities.filesystem_isolation = true;
    capabilities.sandbox = true;
    capabilities.deterministic_build = true;
    capabilities.trusted = true;
    capabilities.evidence = EvidenceClass::Synthetic;
    capabilities.host = "local";
    canonicalize(capabilities);
    for (int i = 0; i < workers; ++i) {
      WorkerRegistration registration;
      registration.endpoint = "local";
      registration.host = "local";
      registration.worker_id = WorkerId(1000 + static_cast<std::uint64_t>(i));
      registration.boot_id = WorkerBootId(2000 + static_cast<std::uint64_t>(i));
      registration.max_inflight = 8;
      registration.capabilities = capabilities;
      auto registered = coordinator.register_worker(registration);
      if (!registered.ok()) std::abort();
      (void)coordinator.mark_ready(registered.value().session);
    }
  }

  ~Fixture() {
    coordinator.close();
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
  }
};

}  // namespace

DC_TEST(concurrency, identical_submissions_race_to_one_authority) {
  DC_PHASE("CANONICALIZE");
  Fixture fixture(4);
  SubmissionBundle bundle = make_bundle("int f() { return 21; }\n", 5001);
  auto canonical = bundle;
  DC_EXPECT(canonicalize(canonical.request).ok());

  constexpr int kThreads = 8;
  std::vector<std::thread> threads;
  std::atomic<int> accepted{0};
  std::atomic<int> failed{0};
  std::vector<Status> statuses(kThreads);
  for (int i = 0; i < kThreads; ++i) {
    threads.emplace_back([&fixture, &bundle, &accepted, &failed, &statuses, i]() {
      SubmissionBundle copy = bundle;
      auto submitted = fixture.coordinator.submit(copy);
      statuses[static_cast<std::size_t>(i)] = submitted.status();
      if (submitted.ok()) {
        ++accepted;
      } else {
        ++failed;
      }
    });
  }
  for (auto& thread : threads) thread.join();
  DC_EXPECT_EQ(accepted.load(), kThreads);
  DC_EXPECT_EQ(failed.load(), 0);

  // Every accepted submission must describe the same logical compilation.
  const std::vector<CompilationRecord> compilations = fixture.coordinator.compilations();
  DC_EXPECT_EQ(compilations.size(), 1u);

  // Drive the work, then confirm exactly one authority exists.
  const std::vector<Assignment> assignments = fixture.coordinator.pump();
  DC_EXPECT(!assignments.empty());
  const Assignment assignment = assignments.front();
  DC_EXPECT(fixture.coordinator.begin_compile(assignment.claim).ok());
  const std::vector<WorkerRecord> workers = fixture.coordinator.workers();
  const ToolchainIdentity* toolchain = nullptr;
  for (const auto& worker : workers) {
    for (const auto& advertised : worker.capabilities.toolchains) {
      if (advertised.identity_digest == assignment.toolchain.identity_digest) toolchain = &advertised;
    }
  }
  DC_EXPECT(toolchain != nullptr);
  auto compiled = run_compile_unit(assignment, *toolchain, fixture.root / "scratch", nullptr);
  DC_EXPECT(compiled.ok());
  ReportOutput output;
  output.claim = assignment.claim;
  output.kind = assignment.output_kind;
  output.logical_name = assignment.logical_name;
  output.bytes = compiled.value().artifact;
  output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
  auto decision = fixture.coordinator.report_output(assignment.session, output);
  DC_EXPECT(decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.value().outcome), static_cast<int>(CommitOutcome::Committed));
  DC_EXPECT_EQ(fixture.coordinator.commits().size(), 1u);
  const AuditReport audit = fixture.coordinator.audit();
  DC_EXPECT_MSG(audit.clean, audit.render());
}

DC_TEST(concurrency, duplicate_completion_race_commits_once) {
  DC_PHASE("COMMIT");
  Fixture fixture(8);
  SubmissionBundle bundle = make_bundle("int f() { return 22; }\n", 5002);
  bundle.request.policy.allow_speculative_duplication = true;
  auto submitted = fixture.coordinator.submit(bundle);
  DC_EXPECT(submitted.ok());

  const std::vector<Assignment> assignments = fixture.coordinator.pump();
  DC_EXPECT_MSG(assignments.size() >= 2, "expected speculative duplication");
  for (const auto& assignment : assignments) {
    DC_EXPECT(fixture.coordinator.begin_compile(assignment.claim).ok());
  }

  const std::string body = "; concurrent artifact\n";
  const Digest256 digest = sha256(std::string_view(body));
  std::vector<std::thread> threads;
  std::atomic<int> committed{0};
  std::atomic<int> deduplicated{0};
  std::atomic<int> refused{0};
  for (const auto& assignment : assignments) {
    threads.emplace_back([&fixture, assignment, &body, &digest, &committed, &deduplicated, &refused]() {
      ReportOutput output;
      output.claim = assignment.claim;
      output.kind = OutputKind::Assembly;
      output.logical_name = "unit.cpp";
      output.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                          reinterpret_cast<const std::byte*>(body.data()) + body.size());
      output.declared_digest = digest;
      auto decision = fixture.coordinator.report_output(assignment.session, output);
      if (!decision.ok()) {
        ++refused;
        return;
      }
      if (decision.value().outcome == CommitOutcome::Committed) ++committed;
      if (decision.value().outcome == CommitOutcome::Deduplicated) ++deduplicated;
      if (decision.value().outcome == CommitOutcome::Refused) ++refused;
    });
  }
  for (auto& thread : threads) thread.join();

  // Exactly one authoritative commit exists no matter how the reports interleave.
  DC_EXPECT_EQ(committed.load(), 1);
  const std::vector<ArtifactCommit> commits = fixture.coordinator.commits();
  int authoritative = 0;
  for (const auto& commit : commits) {
    if (!commit.superseded) ++authoritative;
  }
  DC_EXPECT_EQ(authoritative, 1);
  DC_EXPECT_EQ(fixture.coordinator.commits().size(), 1u);
  const AuditReport audit = fixture.coordinator.audit();
  DC_EXPECT_MSG(audit.clean, audit.render());
}

DC_TEST(concurrency, snapshot_during_submission_stays_consistent) {
  DC_PHASE("PERSISTENCE");
  Fixture fixture(4);
  std::atomic<bool> stop{false};
  std::atomic<int> snapshots{0};
  std::thread snapshots_thread([&fixture, &stop, &snapshots]() {
    while (!stop.load()) {
      if (fixture.coordinator.snapshot().ok()) ++snapshots;
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  std::vector<std::thread> submitters;
  std::atomic<int> accepted{0};
  for (int i = 0; i < 4; ++i) {
    submitters.emplace_back([&fixture, &accepted, i]() {
      for (int j = 0; j < 25; ++j) {
        SubmissionBundle bundle = make_bundle("int f() { return " + std::to_string(i * 100 + j) + "; }\n",
                                              6000 + static_cast<std::uint64_t>(i * 100 + j));
        if (fixture.coordinator.submit(bundle).ok()) ++accepted;
      }
    });
  }
  for (auto& thread : submitters) thread.join();
  stop.store(true);
  snapshots_thread.join();

  DC_EXPECT_EQ(accepted.load(), 100);
  const AuditReport audit = fixture.coordinator.audit();
  DC_EXPECT_MSG(audit.clean, audit.render());
  DC_EXPECT(snapshots.load() > 0);

  // The state written under concurrent mutation must still reload cleanly.
  CoordinatorConfig config;
  config.state_root = fixture.root / "state";
  config.enable_persistence = true;
  fixture.coordinator.close();
  Coordinator reopened;
  const Status opened = reopened.open(config);
  DC_EXPECT_MSG(opened.ok(), opened.describe());
  DC_EXPECT(reopened.audit().clean);
  reopened.close();
}

DC_TEST(concurrency, cancellation_racing_completion_leaves_valid_state) {
  DC_PHASE("COMMIT");
  Fixture fixture(4);
  for (int round = 0; round < 10; ++round) {
    SubmissionBundle bundle = make_bundle("int f() { return " + std::to_string(round) + "; }\n",
                                          7000 + static_cast<std::uint64_t>(round));
    auto submitted = fixture.coordinator.submit(bundle);
    DC_EXPECT(submitted.ok());
    const CompilationId compilation = submitted.value().units.front().compilation;
    const std::vector<Assignment> assignments = fixture.coordinator.pump();
    if (assignments.empty()) continue;
    const Assignment assignment = assignments.front();
    (void)fixture.coordinator.begin_compile(assignment.claim);

    std::atomic<bool> cancel_done{false};
    std::thread canceller([&fixture, compilation, &cancel_done]() {
      (void)fixture.coordinator.cancel(compilation, "race");
      cancel_done.store(true);
    });
    const std::string body = "; racing artifact " + std::to_string(round) + "\n";
    ReportOutput output;
    output.claim = assignment.claim;
    output.kind = OutputKind::Assembly;
    output.logical_name = "unit.cpp";
    output.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                        reinterpret_cast<const std::byte*>(body.data()) + body.size());
    output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
    (void)fixture.coordinator.report_output(assignment.session, output);
    canceller.join();
    DC_EXPECT(cancel_done.load());
  }
  // Whatever the interleaving, the state machine must remain self-consistent.
  const AuditReport audit = fixture.coordinator.audit();
  DC_EXPECT_MSG(audit.clean, audit.render());
}

DC_TEST(concurrency, cache_query_during_commit_is_consistent) {
  DC_PHASE("CACHE");
  Fixture fixture(4);
  std::atomic<bool> stop{false};
  std::atomic<int> queries{0};
  std::atomic<int> unsafe{0};
  std::thread querier([&fixture, &stop, &queries, &unsafe]() {
    while (!stop.load()) {
      for (const auto& entry : fixture.coordinator.cache_entries()) {
        auto decision = fixture.coordinator.cache_query(entry.unit_identity);
        if (!decision.ok()) continue;
        ++queries;
        // A reusable decision must never describe a missing artifact.
        if (decision.value().reusable()) {
          auto record = fixture.coordinator.compilation(entry.compilation);
          if (!record.ok() || record.value().state == CompilationState::Failed) ++unsafe;
        }
      }
    }
  });
  for (int round = 0; round < 20; ++round) {
    SubmissionBundle bundle = make_bundle("int f() { return " + std::to_string(round) + "; }\n",
                                          8000 + static_cast<std::uint64_t>(round));
    auto submitted = fixture.coordinator.submit(bundle);
    if (!submitted.ok()) continue;
    const std::vector<Assignment> assignments = fixture.coordinator.pump();
    if (assignments.empty()) continue;
    const Assignment assignment = assignments.front();
    if (!fixture.coordinator.begin_compile(assignment.claim).ok()) continue;
    const std::vector<WorkerRecord> workers = fixture.coordinator.workers();
    const ToolchainIdentity* toolchain = nullptr;
    for (const auto& worker : workers) {
      for (const auto& advertised : worker.capabilities.toolchains) {
        if (advertised.identity_digest == assignment.toolchain.identity_digest) toolchain = &advertised;
      }
    }
    if (toolchain == nullptr) continue;
    auto compiled = run_compile_unit(assignment, *toolchain, fixture.root / "scratch", nullptr);
    if (!compiled.ok()) continue;
    ReportOutput output;
    output.claim = assignment.claim;
    output.kind = assignment.output_kind;
    output.logical_name = assignment.logical_name;
    output.bytes = compiled.value().artifact;
    output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
    (void)fixture.coordinator.report_output(assignment.session, output);
  }
  stop.store(true);
  querier.join();
  DC_EXPECT(queries.load() > 0);
  DC_EXPECT_EQ(unsafe.load(), 0);
  const AuditReport audit = fixture.coordinator.audit();
  DC_EXPECT_MSG(audit.clean, audit.render());
}

#include <chrono>

int main(int argc, char** argv) {
  if (argc > 2 && std::string(argv[1]) == "--sleep-ms") {
    std::this_thread::sleep_for(std::chrono::milliseconds(std::stoll(argv[2])));
    return 0;
  }
  if (argc > 2 && std::string(argv[1]) == "--emit-bytes") {
    const std::size_t count = static_cast<std::size_t>(std::stoull(argv[2]));
    const std::string chunk(4096, 'x');
    std::size_t written_total = 0;
    while (written_total < count) {
      const std::size_t take = std::min<std::size_t>(chunk.size(), count - written_total);
      std::fwrite(chunk.data(), 1, take, stdout);
      written_total += take;
    }
    std::fflush(stdout);
    return 0;
  }
  return dctest::run_all(argc, argv);
}
