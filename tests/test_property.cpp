// Distributed Compilation - randomized and property tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every randomized case is driven by an explicit, recorded seed so that a
// failure is reproducible from its printed seed alone.
#include <algorithm>
#include <random>
#include <string>
#include <vector>

#include "dc/codec.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"
#include "dc/persistence.hpp"
#include "dc/wire.hpp"
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

std::string make_source(std::mt19937_64& rng, int length) {
  std::string text = "int f() { return ";
  text += std::to_string(static_cast<int>(rng() % 1000));
  text += "; }\n";
  while (static_cast<int>(text.size()) < length) text += "// padding\n";
  return text;
}

WorkerCapabilities synthetic_capabilities() {
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
  return capabilities;
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

Status drive_assignment(Coordinator& coordinator, const Assignment& assignment,
                        const std::filesystem::path& scratch);

// Drives every assignment the coordinator is willing to hand out, in order.
// Servicing only the first would leave earlier work pending and make later
// assertions depend on which compilation happened to be pumped first.
Status drive_all(Coordinator& coordinator, const std::filesystem::path& scratch) {
  int serviced = 0;
  for (;;) {
    const std::vector<Assignment> assignments = coordinator.pump();
    if (assignments.empty()) break;
    // Every assignment produced by one pump call must be serviced: the others
    // already hold live leases, so a later pump will not re-offer them.
    for (const auto& assignment : assignments) {
      Status status = drive_assignment(coordinator, assignment, scratch);
      if (!status.ok()) return status;
      ++serviced;
    }
    if (serviced > 64) break;
  }
  if (serviced == 0) return Status::error(ErrorCode::NotFound, "no assignment");
  return Status::success();
}

Status drive_assignment(Coordinator& coordinator, const Assignment& assignment,
                        const std::filesystem::path& scratch) {
  const std::vector<WorkerRecord> workers = coordinator.workers();
  const ToolchainIdentity* toolchain = nullptr;
  for (const auto& worker : workers) {
    for (const auto& advertised : worker.capabilities.toolchains) {
      if (advertised.identity_digest == assignment.toolchain.identity_digest) toolchain = &advertised;
    }
  }
  if (toolchain == nullptr) return Status::error(ErrorCode::NotFound, "no toolchain");
  const Status begun = coordinator.begin_compile(assignment.claim);
  if (!begun.ok()) return begun;
  auto compiled = run_compile_unit(assignment, *toolchain, scratch, nullptr);
  if (!compiled.ok()) return compiled.status();
  ReportOutput output;
  output.claim = assignment.claim;
  output.kind = assignment.output_kind;
  output.logical_name = assignment.logical_name;
  output.bytes = compiled.value().artifact;
  output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
  auto decision = coordinator.report_output(assignment.session, output);
  if (!decision.ok()) return decision.status();
  if (decision.value().outcome != CommitOutcome::Committed &&
      decision.value().outcome != CommitOutcome::Deduplicated) {
    return Status::error(decision.value().error, decision.value().detail);
  }
  return Status::success();
}

}  // namespace

DC_TEST(property, canonical_identity_survives_permutation) {
  DC_PHASE("CANONICALIZE");
  for (std::uint64_t seed = 1; seed <= 25; ++seed) {
    std::mt19937_64 rng(seed);
    const int dependency_count = 1 + static_cast<int>(rng() % 6);
    SubmissionBundle base = make_bundle(make_source(rng, 64), seed);
    std::vector<Blob> blobs;
    for (int i = 0; i < dependency_count; ++i) {
      Blob blob = make_blob("header " + std::to_string(i) + " seed " + std::to_string(seed));
      DependencyEntry entry;
      entry.name = "h" + std::to_string(i) + ".h";
      entry.kind = static_cast<DependencyKind>(rng() % 11);
      entry.content.digest = blob.digest;
      entry.content.size = blob.bytes.size();
      base.request.dependencies.entries.push_back(entry);
      base.blobs.push_back(blob);
    }
    DC_EXPECT_MSG(canonicalize(base.request).ok(), "seed " + std::to_string(seed));

    SubmissionBundle permuted = base;
    std::shuffle(permuted.request.dependencies.entries.begin(), permuted.request.dependencies.entries.end(), rng);
    DC_EXPECT(canonicalize(permuted.request).ok());
    DC_EXPECT_MSG(permuted.request.request_identity.hex() == base.request.request_identity.hex(),
                  "dependency permutation changed identity at seed " + std::to_string(seed));

    SubmissionBundle mutated = base;
    const std::size_t victim = static_cast<std::size_t>(rng() % mutated.request.dependencies.entries.size());
    Blob changed = make_blob("changed content seed " + std::to_string(seed));
    mutated.request.dependencies.entries[victim].content.digest = changed.digest;
    mutated.request.dependencies.entries[victim].content.size = changed.bytes.size();
    mutated.blobs.push_back(changed);
    DC_EXPECT(canonicalize(mutated.request).ok());
    DC_EXPECT_MSG(mutated.request.request_identity.hex() != base.request.request_identity.hex(),
                  "dependency content change did not change identity at seed " + std::to_string(seed));
  }
}

DC_TEST(property, cache_never_serves_changed_content) {
  DC_PHASE("CACHE");
  const std::filesystem::path root = std::filesystem::temp_directory_path() /
                                     ("dc-prop-" + std::to_string(static_cast<long long>(SystemClock().now())));
  CoordinatorConfig config;
  config.state_root = root / "state";
  config.clock = std::make_shared<ManualClock>();
  Coordinator coordinator;
  DC_EXPECT(coordinator.open(config).ok());
  WorkerRegistration registration;
  registration.endpoint = "local";
  registration.host = "local";
  registration.worker_id = WorkerId(31);
  registration.boot_id = WorkerBootId(32);
  registration.max_inflight = 4;
  registration.capabilities = synthetic_capabilities();
  auto registered = coordinator.register_worker(registration);
  DC_EXPECT(registered.ok());
  (void)coordinator.mark_ready(registered.value().session);

  for (std::uint64_t seed = 100; seed < 110; ++seed) {
    std::mt19937_64 rng(seed);
    SubmissionBundle bundle = make_bundle(make_source(rng, 48), seed);
    auto submitted = coordinator.submit(bundle);
    DC_EXPECT(submitted.ok());
    DC_EXPECT(drive_all(coordinator, root / "scratch").ok());

    auto reused = coordinator.submit(bundle);
    DC_EXPECT(reused.ok());
    DC_EXPECT_MSG(reused.value().served_from_cache,
                  "identical content missed the cache at seed " + std::to_string(seed) + ": " +
                      std::string(to_string(reused.value().units.front().cache.outcome)) + " " +
                      reused.value().units.front().cache.reason + " [" +
                      reused.value().units.front().detail + "]");

    SubmissionBundle other = bundle;
    const Blob changed = make_blob(make_source(rng, 48) + "// different\n");
    other.request.units.front().sources.front().content.digest = changed.digest;
    other.request.units.front().sources.front().content.size = changed.bytes.size();
    other.blobs.push_back(changed);
    auto miss = coordinator.submit(other);
    DC_EXPECT(miss.ok());
    DC_EXPECT_MSG(!miss.value().served_from_cache,
                  "content change reused a cache entry at seed " + std::to_string(seed));
  }
  DC_EXPECT(coordinator.audit().clean);
  coordinator.close();
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

DC_TEST(property, serialization_round_trip_is_lossless) {
  DC_PHASE("PERSISTENCE");
  for (std::uint64_t seed = 200; seed < 240; ++seed) {
    std::mt19937_64 rng(seed);
    SubmissionBundle bundle = make_bundle(make_source(rng, 40), seed);
    CompilationRequest& request = bundle.request;
    request.policy.max_attempts_per_unit = 1 + static_cast<std::uint32_t>(rng() % 5);
    request.specialization.fields.push_back(
        SpecField::make_signed("tile", static_cast<std::int64_t>(rng() % 4096)));
    request.specialization.fields.push_back(SpecField::make_text("dtype", rng() % 2 ? "fp16" : "bf16"));
    request.specialization.fields.push_back(SpecField::make_boolean("fastmath", (rng() % 2) == 0));
    DC_EXPECT(canonicalize(request).ok());

    CanonicalWriter writer;
    encode_request(writer, request);
    const std::vector<std::byte> encoded(writer.bytes().begin(), writer.bytes().end());
    CanonicalReader reader(std::span<const std::byte>(encoded.data(), encoded.size()));
    CompilationRequest decoded;
    DC_EXPECT_MSG(decode_request(reader, decoded), "decode failed at seed " + std::to_string(seed));
    DC_EXPECT_EQ(decoded.request_identity.hex(), request.request_identity.hex());
    DC_EXPECT_EQ(decoded.toolchain.identity_digest.hex(), request.toolchain.identity_digest.hex());
    DC_EXPECT_EQ(decoded.specialization.identity_digest.hex(), request.specialization.identity_digest.hex());
    DC_EXPECT_EQ(decoded.policy.identity_digest.hex(), request.policy.identity_digest.hex());
    DC_EXPECT_EQ(decoded.units.size(), request.units.size());

    CanonicalWriter again;
    encode_request(again, decoded);
    DC_EXPECT_EQ(again.hash().hex(), writer.hash().hex());
  }
}

DC_TEST(property, duplicate_commit_collapses_to_one_authority) {
  DC_PHASE("COMMIT");
  const std::filesystem::path root = std::filesystem::temp_directory_path() /
                                     ("dc-dup-" + std::to_string(static_cast<long long>(SystemClock().now())));
  CoordinatorConfig config;
  config.state_root = root / "state";
  config.clock = std::make_shared<ManualClock>();
  Coordinator coordinator;
  DC_EXPECT(coordinator.open(config).ok());
  for (int i = 0; i < 4; ++i) {
    WorkerRegistration registration;
    registration.endpoint = "local";
    registration.host = "local";
    registration.worker_id = WorkerId(100 + static_cast<std::uint64_t>(i));
    registration.boot_id = WorkerBootId(200 + static_cast<std::uint64_t>(i));
    registration.max_inflight = 4;
    registration.capabilities = synthetic_capabilities();
    auto registered = coordinator.register_worker(registration);
    DC_EXPECT(registered.ok());
    (void)coordinator.mark_ready(registered.value().session);
  }

  SubmissionBundle bundle = make_bundle("int f() { return 5; }\n", 301);
  bundle.request.policy.allow_speculative_duplication = true;
  auto submitted = coordinator.submit(bundle);
  DC_EXPECT(submitted.ok());

  const std::vector<Assignment> assignments = coordinator.pump();
  DC_EXPECT_MSG(assignments.size() >= 2, "speculative duplication must produce several attempts");
  const std::string body = "; identical artifact\n";
  const Digest256 digest = sha256(std::string_view(body));
  int committed = 0;
  int deduplicated = 0;
  for (const auto& assignment : assignments) {
    DC_EXPECT(coordinator.begin_compile(assignment.claim).ok());
    ReportOutput output;
    output.claim = assignment.claim;
    output.kind = OutputKind::Assembly;
    output.logical_name = "unit.cpp";
    output.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                        reinterpret_cast<const std::byte*>(body.data()) + body.size());
    output.declared_digest = digest;
    auto decision = coordinator.report_output(assignment.session, output);
    if (!decision.ok()) continue;   // a loser may legitimately be refused after the winner commits
    if (decision.value().outcome == CommitOutcome::Committed) ++committed;
    if (decision.value().outcome == CommitOutcome::Deduplicated) ++deduplicated;
  }
  DC_EXPECT_EQ(committed, 1);
  const std::vector<ArtifactCommit> commits = coordinator.commits();
  int authoritative = 0;
  for (const auto& commit : commits) {
    if (commit.compilation == submitted.value().units.front().compilation && !commit.superseded) ++authoritative;
  }
  DC_EXPECT_EQ(authoritative, 1);
  const AuditReport audit = coordinator.audit();
  std::string state_note;
  for (const auto& record : coordinator.compilations()) {
    state_note += " compilation " + std::to_string(record.id.value()) + " state " +
                  std::string(to_string(record.state)) + ";";
  }
  for (const auto& attempt : coordinator.attempts()) {
    state_note += " attempt " + std::to_string(attempt.id.value()) + " state " +
                  std::string(to_string(attempt.state)) + ";";
  }
  DC_EXPECT_MSG(audit.clean, audit.render() + state_note);
  coordinator.close();
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

DC_TEST(property, generation_registry_is_content_addressed) {
  DC_PHASE("CANONICALIZE");
  // The history bound is set above the number of distinct contents, so no
  // eviction can occur and the generation must be a pure function of content.
  for (std::uint64_t seed = 400; seed < 420; ++seed) {
    std::mt19937_64 rng(seed);
    SourceRegistry registry(64);
    std::vector<Digest256> seen;
    std::vector<std::uint64_t> generations;
    for (int i = 0; i < 40; ++i) {
      const Digest256 content = sha256("content-" + std::to_string(seed) + "-" + std::to_string(rng() % 6));
      bool created = false;
      const SourceGeneration generation = registry.resolve(SourceId(5), content, created);
      auto found = std::find(seen.begin(), seen.end(), content);
      if (found != seen.end()) {
        const std::size_t index = static_cast<std::size_t>(found - seen.begin());
        DC_EXPECT_MSG(generation.value() == generations[index],
                      "generation drifted for repeated content at seed " + std::to_string(seed));
      } else {
        seen.push_back(content);
        generations.push_back(generation.value());
      }
    }
  }
}

DC_TEST(property, generation_eviction_fails_closed) {
  DC_PHASE("CANONICALIZE");
  // When a content's generation is forgotten because the bounded history was
  // exhausted, re-submitting that content must yield a higher generation than
  // before. A cache entry recorded against the forgotten generation then fails
  // closed, which is the intended behaviour.
  SourceRegistry registry(2);
  const Digest256 first = sha256(std::string_view("generation-one"));
  const Digest256 second = sha256(std::string_view("generation-two"));
  const Digest256 third = sha256(std::string_view("generation-three"));
  bool created = false;
  const SourceGeneration one = registry.resolve(SourceId(7), first, created);
  DC_EXPECT_EQ(one.value(), 1ull);
  const SourceGeneration two = registry.resolve(SourceId(7), second, created);
  DC_EXPECT_EQ(two.value(), 2ull);
  const SourceGeneration three = registry.resolve(SourceId(7), third, created);
  DC_EXPECT_EQ(three.value(), 3ull);
  SourceGeneration known;
  DC_EXPECT(!registry.lookup(SourceId(7), first, known));
  const SourceGeneration revived = registry.resolve(SourceId(7), first, created);
  DC_EXPECT(created);
  DC_EXPECT_MSG(revived.value() > one.value(),
                "an evicted generation must not be resurrected as the same generation");
}

int main(int argc, char** argv) { return dctest::run_all(argc, argv); }
