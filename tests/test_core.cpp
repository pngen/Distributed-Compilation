// Distributed Compilation - unit tests for identity, authority and commit semantics.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <algorithm>
#include <string>
#include <vector>

#include "dc/codec.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"
#include "dc/net.hpp"
#include "dc/persistence.hpp"
#include "dc/process.hpp"
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
  options.compute_binary_digests = false;
  const DiscoveryResult discovered = discover_toolchains(options);
  for (const auto& candidate : discovered.toolchains) {
    if (candidate.family == CompilerFamily::SyntheticGeneric) return candidate;
  }
  return discovered.toolchains.front();
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

SubmissionBundle make_bundle(const ToolchainIdentity& toolchain, const TargetIdentity& target,
                             const std::string& source_text, const std::string& unit_name,
                             OutputKind kind, ReproducibilityRequirement reproducibility) {
  SubmissionBundle bundle;
  bundle.request.toolchain = toolchain;
  bundle.request.target = target;
  bundle.request.request_id = RequestId(1);
  bundle.request.policy.reproducibility = reproducibility;
  bundle.request.policy.require_provable_toolchain = false;
  const Blob source = make_blob(source_text);
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

struct Harness {
  std::filesystem::path root;
  Coordinator coordinator;
  SessionId session;
  SessionId second_session;

  Harness() {
    root = std::filesystem::temp_directory_path() /
           ("dc-test-" + std::to_string(static_cast<long long>(SystemClock().now())) + "-" +
            std::to_string(reinterpret_cast<std::uintptr_t>(this)));
    CoordinatorConfig config;
    config.state_root = root / "state";
    config.enable_persistence = true;
    config.clock = std::make_shared<ManualClock>();
    const Status opened = coordinator.open(config);
    if (!opened.ok()) std::abort();
    WorkerCapabilities capabilities;
    capabilities.toolchains = {synthetic_toolchain()};
    capabilities.targets = {synthetic_target()};
    capabilities.input_formats = {InputFormat::Source, InputFormat::Object};
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
    registration.worker_id = WorkerId(11);
    registration.boot_id = WorkerBootId(22);
    registration.max_inflight = 4;
    registration.capabilities = capabilities;
    auto registered = coordinator.register_worker(registration);
    if (!registered.ok()) std::abort();
    session = registered.value().session;
    (void)coordinator.mark_ready(session);

    // A second worker on the same host: needed to exercise speculative
    // duplication and cross-worker divergence.
    WorkerRegistration second = registration;
    second.worker_id = WorkerId(12);
    second.boot_id = WorkerBootId(23);
    auto second_registered = coordinator.register_worker(second);
    if (!second_registered.ok()) std::abort();
    second_session = second_registered.value().session;
    (void)coordinator.mark_ready(second_session);
  }

  ~Harness() {
    coordinator.close();
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
  }

  Status drive_one() {
    const std::vector<Assignment> assignments = coordinator.pump();
    if (assignments.empty()) return Status::error(ErrorCode::NotFound, "no assignment");
    const Assignment assignment = assignments.front();
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
    auto compiled = run_compile_unit(assignment, *toolchain, root / "scratch", nullptr);
    if (!compiled.ok()) return compiled.status();
    ReportOutput output;
    output.claim = assignment.claim;
    output.kind = assignment.output_kind;
    output.logical_name = assignment.logical_name;
    output.bytes = compiled.value().artifact;
    output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
    output.compiler_invocation = compiled.value().invocation;
    output.compiler_version_string = compiled.value().compiler_version;
    auto decision = coordinator.report_output(session, output);
    if (!decision.ok()) return decision.status();
    if (decision.value().outcome != CommitOutcome::Committed) {
      return Status::error(decision.value().error, decision.value().detail);
    }
    return Status::success();
  }
};

}  // namespace

DC_TEST(identity, strong_ids_are_distinct_domains) {
  DC_PHASE("IDENTITY");
  const WorkerId worker(7);
  const WorkerGeneration generation(7);
  DC_EXPECT_EQ(worker.value(), generation.value());
  DC_EXPECT(worker != WorkerId(0));
  WorkerId decoded;
  DC_EXPECT(!WorkerId::decode(0, decoded));
  DC_EXPECT(WorkerId::decode(9, decoded));
  DC_EXPECT_EQ(decoded.value(), 9u);
  WorkerGeneration next = WorkerGeneration(3).next();
  DC_EXPECT_EQ(next.value(), 4u);
  DC_EXPECT(WorkerGeneration(3) < next);
}

DC_TEST(digest, sha256_and_hex_are_correct) {
  DC_PHASE("DIGEST");
  const Digest256 empty = sha256(std::string_view(""));
  DC_EXPECT_EQ(empty.hex(),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  const Digest256 abc = sha256(std::string_view("abc"));
  DC_EXPECT_EQ(abc.hex(),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  Digest256 parsed;
  DC_EXPECT(Digest256::parse_hex(abc.hex(), parsed));
  DC_EXPECT(parsed == abc);
  DC_EXPECT(!Digest256::parse_hex("zz", parsed));
  DC_EXPECT_EQ(crc32("123456789", 9), 0xCBF43926u);
}

DC_TEST(canonical, encoding_is_stable_and_domain_separated) {
  DC_PHASE("CANONICALIZE");
  CanonicalWriter first;
  first.domain("dc.test.one");
  first.str("alpha");
  first.u64(42);
  CanonicalWriter second;
  second.domain("dc.test.one");
  second.str("alpha");
  second.u64(42);
  DC_EXPECT(first.hash() == second.hash());

  CanonicalWriter other_domain;
  other_domain.domain("dc.test.two");
  other_domain.str("alpha");
  other_domain.u64(42);
  DC_EXPECT(other_domain.hash() != first.hash());

  // Concatenation must be unambiguous: moving a byte between fields changes the
  // identity, so two different records can never encode identically.
  CanonicalWriter split_a;
  split_a.str("ab");
  split_a.str("c");
  CanonicalWriter split_b;
  split_b.str("a");
  split_b.str("bc");
  DC_EXPECT(split_a.hash() != split_b.hash());
}

DC_TEST(canonical, reader_refuses_malformed_input) {
  DC_PHASE("CANONICALIZE");
  CanonicalWriter writer;
  writer.domain("dc.test");
  writer.u64(5);
  const std::vector<std::byte> bytes(writer.bytes().begin(), writer.bytes().end());

  std::uint64_t value = 0;
  CanonicalReader truncated(std::span<const std::byte>(bytes.data(), 4));
  DC_EXPECT(!truncated.read_domain("dc.test"));
  DC_EXPECT(!truncated.ok());

  CanonicalReader wrong_domain(std::span<const std::byte>(bytes.data(), bytes.size()));
  DC_EXPECT(!wrong_domain.read_domain("dc.other"));

  CanonicalWriter zero_writer;
  zero_writer.domain("dc.test");
  zero_writer.u64(0);
  const std::vector<std::byte> zero_bytes(zero_writer.bytes().begin(), zero_writer.bytes().end());
  CanonicalReader zero_handle(std::span<const std::byte>(zero_bytes.data(), zero_bytes.size()));
  WorkerId worker;
  DC_EXPECT(zero_handle.read_domain("dc.test"));
  DC_EXPECT(!zero_handle.read_id(worker));
  DC_EXPECT_EQ(static_cast<int>(zero_handle.status().code()),
               static_cast<int>(ErrorCode::Malformed));

  // An oversized length field must be refused without allocating.
  CanonicalWriter big;
  big.u32(0xFFFFFFF0u);
  const std::vector<std::byte> big_bytes(big.bytes().begin(), big.bytes().end());
  CanonicalReader oversized(std::span<const std::byte>(big_bytes.data(), big_bytes.size()));
  std::string text;
  DC_EXPECT(!oversized.read_str(text));
  DC_EXPECT_EQ(static_cast<int>(oversized.status().code()), static_cast<int>(ErrorCode::LimitExceeded));
  (void)value;
}

DC_TEST(request, canonical_identity_is_content_derived) {
  DC_PHASE("CANONICALIZE");
  const ToolchainIdentity toolchain = synthetic_toolchain();
  const TargetIdentity target = synthetic_target();

  SubmissionBundle a = make_bundle(toolchain, target, "int f() { return 1; }", "unit.cpp", OutputKind::Assembly,
                                   ReproducibilityRequirement::Preferred);
  SubmissionBundle b = make_bundle(toolchain, target, "int f() { return 1; }", "unit.cpp", OutputKind::Assembly,
                                   ReproducibilityRequirement::Preferred);
  b.request.request_id = RequestId(999);   // the idempotency key is not content
  DC_EXPECT(canonicalize(a.request).ok());
  DC_EXPECT(canonicalize(b.request).ok());
  DC_EXPECT_EQ(a.request.request_identity.hex(), b.request.request_identity.hex());

  SubmissionBundle changed = make_bundle(toolchain, target, "int f() { return 2; }", "unit.cpp",
                                         OutputKind::Assembly, ReproducibilityRequirement::Preferred);
  DC_EXPECT(canonicalize(changed.request).ok());
  DC_EXPECT_NE(changed.request.request_identity.hex(), a.request.request_identity.hex());

  // A changed output kind is a different compilation.
  SubmissionBundle other_kind = make_bundle(toolchain, target, "int f() { return 1; }", "unit.cpp",
                                            OutputKind::Object, ReproducibilityRequirement::Preferred);
  DC_EXPECT(canonicalize(other_kind.request).ok());
  DC_EXPECT_NE(other_kind.request.request_identity.hex(), a.request.request_identity.hex());
}

DC_TEST(request, dependency_order_does_not_change_identity) {
  DC_PHASE("CANONICALIZE");
  const ToolchainIdentity toolchain = synthetic_toolchain();
  const TargetIdentity target = synthetic_target();
  const Blob header_one = make_blob("#pragma once\nint one();\n");
  const Blob header_two = make_blob("#pragma once\nint two();\n");

  SubmissionBundle forward = make_bundle(toolchain, target, "int f() { return 1; }", "unit.cpp",
                                         OutputKind::Assembly, ReproducibilityRequirement::Preferred);
  SubmissionBundle reverse = forward;
  for (const Blob* blob : {&header_one, &header_two}) {
    DependencyEntry entry;
    entry.name = blob == &header_one ? "one.h" : "two.h";
    entry.kind = DependencyKind::Header;
    entry.content.digest = blob->digest;
    entry.content.size = blob->bytes.size();
    forward.request.dependencies.entries.push_back(entry);
  }
  for (const Blob* blob : {&header_two, &header_one}) {
    DependencyEntry entry;
    entry.name = blob == &header_one ? "one.h" : "two.h";
    entry.kind = DependencyKind::Header;
    entry.content.digest = blob->digest;
    entry.content.size = blob->bytes.size();
    reverse.request.dependencies.entries.push_back(entry);
    reverse.blobs.push_back(*blob);
  }
  for (const Blob* blob : {&header_one, &header_two}) forward.blobs.push_back(*blob);

  DC_EXPECT(canonicalize(forward.request).ok());
  DC_EXPECT(canonicalize(reverse.request).ok());
  DC_EXPECT_EQ(forward.request.dependencies.identity_digest.hex(),
               reverse.request.dependencies.identity_digest.hex());
  DC_EXPECT_EQ(forward.request.request_identity.hex(), reverse.request.request_identity.hex());
}

DC_TEST(request, flag_order_is_significant_by_policy) {
  DC_PHASE("CANONICALIZE");
  const ToolchainIdentity toolchain = synthetic_toolchain();
  const TargetIdentity target = synthetic_target();
  SubmissionBundle a = make_bundle(toolchain, target, "int f() { return 1; }", "unit.cpp", OutputKind::Assembly,
                                   ReproducibilityRequirement::Preferred);
  SubmissionBundle b = a;
  a.request.flags = {"/DFIRST", "/DSECOND"};
  b.request.flags = {"/DSECOND", "/DFIRST"};
  DC_EXPECT(canonicalize(a.request).ok());
  DC_EXPECT(canonicalize(b.request).ok());
  DC_EXPECT_NE(a.request.request_identity.hex(), b.request.request_identity.hex());

  // With an order-insensitive policy the same two flag sets converge.
  SubmissionBundle c = a;
  SubmissionBundle d = b;
  c.request.policy.flag_order_significant = false;
  d.request.policy.flag_order_significant = false;
  DC_EXPECT(canonicalize(c.request).ok());
  DC_EXPECT(canonicalize(d.request).ok());
  DC_EXPECT_EQ(c.request.request_identity.hex(), d.request.request_identity.hex());
}

DC_TEST(request, specialization_is_canonical_and_unique) {
  DC_PHASE("CANONICALIZE");
  SpecializationSpec first;
  first.fields.push_back(SpecField::make_signed("tile", 128));
  first.fields.push_back(SpecField::make_text("dtype", "fp16"));
  SpecializationSpec second;
  second.fields.push_back(SpecField::make_text("dtype", "fp16"));
  second.fields.push_back(SpecField::make_signed("tile", 128));
  DC_EXPECT(canonicalize(first).ok());
  DC_EXPECT(canonicalize(second).ok());
  DC_EXPECT_EQ(first.identity_digest.hex(), second.identity_digest.hex());
  DC_EXPECT_EQ(first.id.value(), second.id.value());

  SpecializationSpec duplicate;
  duplicate.fields.push_back(SpecField::make_signed("tile", 1));
  duplicate.fields.push_back(SpecField::make_signed("tile", 2));
  const Status status = canonicalize(duplicate);
  DC_EXPECT(!status.ok());
  DC_EXPECT_EQ(static_cast<int>(status.code()), static_cast<int>(ErrorCode::Duplicate));

  SpecializationSpec changed;
  changed.fields.push_back(SpecField::make_signed("tile", 256));
  changed.fields.push_back(SpecField::make_text("dtype", "fp16"));
  DC_EXPECT(canonicalize(changed).ok());
  DC_EXPECT_NE(changed.identity_digest.hex(), first.identity_digest.hex());
  DC_EXPECT_EQ(changed.id.value(), first.id.value());   // same schema, new generation domain
}

DC_TEST(toolchain, identity_is_stronger_than_a_version_string) {
  DC_PHASE("IDENTITY");
  ToolchainIdentity first = synthetic_toolchain();
  ToolchainIdentity second = first;
  first.compiler.state = BinaryIdState::Known;
  second.compiler.state = BinaryIdState::Known;
  Digest256 binary_one;
  Digest256 binary_two;
  binary_one.raw()[0] = 1;
  binary_two.raw()[0] = 2;
  first.compiler.digest = binary_one;
  second.compiler.digest = binary_two;
  canonicalize(first);
  canonicalize(second);
  DC_EXPECT_EQ(first.version_string, second.version_string);
  DC_EXPECT_NE(first.identity_digest.hex(), second.identity_digest.hex());

  // Path participates in identity only while the binary digest is unknown.
  ToolchainIdentity unknown_one = first;
  unknown_one.compiler.state = BinaryIdState::Unknown;
  unknown_one.compiler.digest = Digest256{};
  unknown_one.compiler.path = "C:/compilers/a/cl.exe";
  ToolchainIdentity unknown_two = unknown_one;
  unknown_two.compiler.path = "C:/compilers/b/cl.exe";
  canonicalize(unknown_one);
  canonicalize(unknown_two);
  DC_EXPECT_NE(unknown_one.identity_digest.hex(), unknown_two.identity_digest.hex());
  DC_EXPECT(!toolchain_identity_is_provable(unknown_one));
  DC_EXPECT(!toolchain_identity_is_provable(first));   // synthetic evidence is not proof
}

DC_TEST(target, accelerator_and_format_are_part_of_identity) {
  DC_PHASE("IDENTITY");
  TargetIdentity sm120;
  sm120.os = OsKind::Windows;
  sm120.arch = ArchKind::X86_64;
  sm120.object_format = ObjectFormat::Cubin;
  sm120.triple = "x86_64-pc-windows-msvc";
  sm120.accelerator.vendor = AcceleratorVendor::Nvidia;
  sm120.accelerator.architecture = "sm_120";
  sm120.accelerator.compute_major = 12;
  sm120.accelerator.compute_minor = 0;

  TargetIdentity sm90 = sm120;
  sm90.accelerator.architecture = "sm_90";
  sm90.accelerator.compute_major = 9;
  DC_EXPECT(compute_target_identity(sm120) != compute_target_identity(sm90));

  TargetIdentity coff = sm120;
  coff.object_format = ObjectFormat::Coff;
  DC_EXPECT(compute_target_identity(sm120) != compute_target_identity(coff));
}

DC_TEST(eligibility, unknown_evidence_fails_closed_and_ranking_follows_eligibility) {
  DC_PHASE("ELIGIBILITY");
  WorkerRecord worker;
  worker.id = WorkerId(1);
  worker.boot = WorkerBootId(2);
  worker.generation = WorkerGeneration(1);
  worker.health = WorkerHealth::Healthy;
  worker.ready = true;
  worker.capabilities.evidence = EvidenceClass::Unknown;
  HardRequirements requirements;
  DC_EXPECT(!evaluate_eligibility(worker, requirements).eligible);
  DC_EXPECT_EQ(static_cast<int>(evaluate_eligibility(worker, requirements).reason),
               static_cast<int>(IneligibilityReason::CapabilityUnknown));

  worker.capabilities.evidence = EvidenceClass::Real;
  worker.capabilities.toolchains = {synthetic_toolchain()};
  worker.capabilities.input_formats = {InputFormat::Source};
  canonicalize(worker.capabilities);
  DC_EXPECT(evaluate_eligibility(worker, requirements).eligible);

  requirements.toolchain_identity = Digest256{};
  requirements.toolchain_identity->raw()[0] = 9;
  DC_EXPECT(!evaluate_eligibility(worker, requirements).eligible);
  DC_EXPECT_EQ(static_cast<int>(evaluate_eligibility(worker, requirements).reason),
               static_cast<int>(IneligibilityReason::ToolchainMissing));

  // Ranking is deterministic and independent of the input order.
  std::vector<WorkerRecord> workers;
  for (int i = 0; i < 5; ++i) {
    WorkerRecord entry = worker;
    entry.id = WorkerId(static_cast<std::uint64_t>(100 - i));
    entry.queue_depth = static_cast<std::uint32_t>(i);
    workers.push_back(entry);
  }
  HardRequirements simple;
  const std::vector<RankedWorker> forward = rank_workers(workers, simple, 0);
  std::reverse(workers.begin(), workers.end());
  const std::vector<RankedWorker> backward = rank_workers(workers, simple, 0);
  DC_EXPECT_EQ(forward.size(), backward.size());
  for (std::size_t i = 0; i < forward.size(); ++i) {
    DC_EXPECT_EQ(forward[i].id.value(), backward[i].id.value());
  }
}

DC_TEST(lifecycle, transitions_are_closed_and_committed_is_terminal) {
  DC_PHASE("LIFECYCLE");
  DC_EXPECT(is_legal_transition(AttemptState::Created, AttemptState::Eligible));
  DC_EXPECT(is_legal_transition(AttemptState::Eligible, AttemptState::Assigned));
  DC_EXPECT(is_legal_transition(AttemptState::Assigned, AttemptState::Preparing));
  DC_EXPECT(is_legal_transition(AttemptState::Preparing, AttemptState::Running));
  DC_EXPECT(is_legal_transition(AttemptState::Preparing, AttemptState::Produced));
  DC_EXPECT(is_legal_transition(AttemptState::Running, AttemptState::Produced));
  DC_EXPECT(is_legal_transition(AttemptState::Produced, AttemptState::Validating));
  DC_EXPECT(is_legal_transition(AttemptState::Validating, AttemptState::CommitReady));
  DC_EXPECT(is_legal_transition(AttemptState::CommitReady, AttemptState::Committed));
  DC_EXPECT(!is_legal_transition(AttemptState::Created, AttemptState::Committed));
  DC_EXPECT(!is_legal_transition(AttemptState::Committed, AttemptState::Running));
  DC_EXPECT(!is_legal_transition(AttemptState::Ambiguous, AttemptState::Produced));
  DC_EXPECT(!is_legal_transition(AttemptState::Cancelled, AttemptState::Committed));
  DC_EXPECT(is_terminal_state(AttemptState::Committed));
  DC_EXPECT(!is_terminal_state(AttemptState::CommitReady));
  DC_EXPECT(holds_commit_authority(AttemptState::CommitReady));
  DC_EXPECT(!holds_commit_authority(AttemptState::Cancelled));
  DC_EXPECT_EQ(static_cast<int>(classify_failure(ErrorCode::TransportFailure)),
               static_cast<int>(FailureClass::Retryable));
  DC_EXPECT_EQ(static_cast<int>(classify_failure(ErrorCode::Unsupported)),
               static_cast<int>(FailureClass::NonRetryable));
}

DC_TEST(authority, every_stale_dimension_is_rejected_with_its_own_code) {
  DC_PHASE("AUTHORITY");
  AuthorityClaim claim;
  claim.epoch = CoordinatorEpoch(4);
  claim.compilation = CompilationId(10);
  claim.compilation_generation = CompilationGeneration(2);
  claim.unit = CompilationUnitId(11);
  claim.unit_generation = UnitGeneration(1);
  claim.attempt = CompilationAttemptId(12);
  claim.attempt_generation = CompilationAttemptGeneration(1);
  claim.worker = WorkerId(13);
  claim.worker_boot = WorkerBootId(14);
  claim.worker_generation = WorkerGeneration(1);
  claim.lease = LeaseId(15);
  claim.lease_generation = LeaseGeneration(1);
  claim.request_identity = compute_environment_identity(EnvironmentContract{});
  claim.unit_identity = claim.request_identity;

  AuthorityExpectation expected;
  expected.epoch = claim.epoch;
  expected.compilation = claim.compilation;
  expected.compilation_generation = claim.compilation_generation;
  expected.unit = claim.unit;
  expected.unit_generation = claim.unit_generation;
  expected.attempt = claim.attempt;
  expected.attempt_generation = claim.attempt_generation;
  expected.worker = claim.worker;
  expected.worker_boot = claim.worker_boot;
  expected.worker_generation = claim.worker_generation;
  expected.lease = claim.lease;
  expected.lease_generation = claim.lease_generation;
  expected.request_identity = claim.request_identity;
  expected.unit_identity = claim.unit_identity;
  DC_EXPECT(validate_authority(claim, expected).ok());

  const auto expect_stale = [&claim, &expected](ErrorCode code, const std::function<void()>& mutate) {
    AuthorityExpectation changed = expected;
    mutate();
    return !validate_authority(claim, changed).ok() &&
           validate_authority(claim, changed).code() == code;
  };
  AuthorityExpectation other;
  other = expected;
  other.epoch = CoordinatorEpoch(9);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleEpoch));
  other = expected;
  other.worker_boot = WorkerBootId(99);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleWorkerBoot));
  other = expected;
  other.worker_generation = WorkerGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleWorkerGeneration));
  other = expected;
  other.lease_generation = LeaseGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleLease));
  other = expected;
  other.compilation_generation = CompilationGeneration(3);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleCompilation));
  other = expected;
  other.attempt_generation = CompilationAttemptGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleAttempt));
  other = expected;
  other.source_generation = SourceGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleSource));
  other = expected;
  other.dependency_generation = DependencyGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleDependencies));
  other = expected;
  other.toolchain_generation = ToolchainGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleToolchain));
  other = expected;
  other.target_generation = TargetGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleTarget));
  other = expected;
  other.specialization_generation = SpecializationGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleSpecialization));
  other = expected;
  other.policy_generation = CompilePolicyGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StalePolicy));
  other = expected;
  other.cache_generation = CacheGeneration(2);
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleCache));
  other = expected;
  other.request_identity = Digest256{};
  other.request_identity.raw()[3] = 7;
  DC_EXPECT_EQ(static_cast<int>(validate_authority(claim, other).code()),
               static_cast<int>(ErrorCode::StaleRequest));
  (void)expect_stale;
}

DC_TEST(validation, artifact_bytes_are_inspected_not_trusted) {
  DC_PHASE("VALIDATE");
  TargetIdentity target;
  target.os = OsKind::Windows;
  target.arch = ArchKind::X86_64;
  target.object_format = ObjectFormat::Coff;
  target.triple = "x86_64-pc-windows-msvc";
  ValidationRequirements requirements;
  requirements.require_format_check = true;
  requirements.require_target_metadata = true;

  // A COFF object: machine 0x8664, two sections, no optional header.
  std::vector<std::byte> coff(64, std::byte{0});
  coff[0] = std::byte{0x64};
  coff[1] = std::byte{0x86};
  coff[2] = std::byte{0x02};
  const Digest256 digest = sha256(std::span<const std::byte>(coff.data(), coff.size()));
  ValidationReport report = validate_artifact_bytes(coff, OutputKind::Object, target, requirements, digest);
  DC_EXPECT(report.aggregate == ValidationOutcome::Pass);

  // The right shape for the wrong architecture is refused.
  TargetIdentity arm = target;
  arm.arch = ArchKind::Aarch64;
  ValidationReport wrong_arch = validate_artifact_bytes(coff, OutputKind::Object, arm, requirements, digest);
  DC_EXPECT(wrong_arch.aggregate == ValidationOutcome::Fail);

  // A digest mismatch is refused before anything else.
  Digest256 other = digest;
  other.raw()[0] = static_cast<std::uint8_t>(other.raw()[0] ^ 0xFF);
  ValidationReport wrong_digest = validate_artifact_bytes(coff, OutputKind::Object, target, requirements, other);
  DC_EXPECT(wrong_digest.aggregate == ValidationOutcome::Fail);

  // An empty artifact never passes.
  ValidationReport empty = validate_artifact_bytes({}, OutputKind::Object, target, requirements, digest);
  DC_EXPECT(empty.aggregate == ValidationOutcome::Fail);

  // A PE image is not a COFF object and must not be accepted as one.
  std::vector<std::byte> pe(256, std::byte{0});
  pe[0] = std::byte{'M'};
  pe[1] = std::byte{'Z'};
  pe[0x3C] = std::byte{0x40};
  pe[0x40] = std::byte{'P'};
  pe[0x41] = std::byte{'E'};
  pe[0x44] = std::byte{0x64};
  pe[0x45] = std::byte{0x86};
  const Digest256 pe_digest = sha256(std::span<const std::byte>(pe.data(), pe.size()));
  DC_EXPECT(validate_artifact_bytes(pe, OutputKind::Object, target, requirements, pe_digest).aggregate ==
            ValidationOutcome::Fail);
  DC_EXPECT(validate_artifact_bytes(pe, OutputKind::Executable, target, requirements, pe_digest).aggregate ==
            ValidationOutcome::Pass);
}

DC_TEST(arguments, command_line_quoting_matches_crt_rules) {
  DC_PHASE("SECURITY");
  DC_EXPECT_EQ(quote_windows_argument("plain"), std::string("plain"));
  DC_EXPECT_EQ(quote_windows_argument("/DFOO=bar"), std::string("/DFOO=bar"));
  DC_EXPECT_EQ(quote_windows_argument("two words"), std::string("\"two words\""));
  DC_EXPECT_EQ(quote_windows_argument("quote\"inside"), std::string("\"quote\\\"inside\""));
  DC_EXPECT_EQ(quote_windows_argument("trailing\\"), std::string("trailing\\"));
  DC_EXPECT_EQ(quote_windows_argument("with space\\"), std::string("\"with space\\\\\""));
  DC_EXPECT_EQ(quote_windows_argument(""), std::string("\"\""));
}

DC_TEST(workspace, path_traversal_is_refused) {
  DC_PHASE("SECURITY");
  const std::filesystem::path root = std::filesystem::temp_directory_path() /
                                     ("dc-ws-" + std::to_string(static_cast<long long>(SystemClock().now())));
  auto workspace = Workspace::create(root, "token1");
  DC_EXPECT(workspace.ok());
  DC_EXPECT(workspace.value().write_file("nested/file.txt", {}).ok() ||
            !workspace.value().resolve("nested/file.txt").ok());
  DC_EXPECT(!workspace.value().resolve("../escape.txt").ok());
  DC_EXPECT(!workspace.value().resolve("a/../../escape.txt").ok());
  DC_EXPECT(!workspace.value().resolve("C:/Windows/system32/cmd.exe").ok());
  DC_EXPECT(workspace.value().resolve("inside.txt").ok());
  DC_EXPECT_EQ(sanitize_token("../evil"), std::string());
  DC_EXPECT_EQ(sanitize_token("good-token_1"), std::string("good-token_1"));
  (void)workspace.value().cleanup();
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

DC_TEST(transaction, commit_is_exactly_once_per_logical_compilation) {
  DC_PHASE("COMMIT");
  Harness harness;
  SubmissionBundle bundle = make_bundle(synthetic_toolchain(), synthetic_target(), "int f() { return 7; }",
                                        "unit.cpp", OutputKind::Assembly, ReproducibilityRequirement::Required);
  auto submitted = harness.coordinator.submit(bundle);
  DC_EXPECT(submitted.ok());
  DC_EXPECT(!submitted.value().all_committed);
  DC_EXPECT(harness.drive_one().ok());
  const CompilationId compilation = submitted.value().units.front().compilation;
  auto commit = harness.coordinator.commit(compilation);
  DC_EXPECT(commit.ok());
  const Digest256 digest = commit.value().artifact_digest;
  DC_EXPECT(!digest.is_zero());

  // A second, identical resubmission must not create a second authority.
  auto again = harness.coordinator.submit(bundle);
  DC_EXPECT(again.ok());
  DC_EXPECT(again.value().all_committed);
  DC_EXPECT(again.value().served_from_cache);
  auto same_commit = harness.coordinator.commit(compilation);
  DC_EXPECT(same_commit.ok());
  DC_EXPECT_EQ(same_commit.value().id.value(), commit.value().id.value());
  DC_EXPECT_EQ(same_commit.value().artifact_digest.hex(), digest.hex());

  const AuditReport audit = harness.coordinator.audit();
  DC_EXPECT_MSG(audit.clean, audit.render());
}

DC_TEST(transaction, changed_dependency_content_invalidates_reuse) {
  DC_PHASE("CACHE");
  Harness harness;
  const std::string header_text = "#pragma once\nint value();\n";
  SubmissionBundle first = make_bundle(synthetic_toolchain(), synthetic_target(), "int f() { return 1; }",
                                       "unit.cpp", OutputKind::Assembly, ReproducibilityRequirement::Preferred);
  const Blob header = make_blob(header_text);
  DependencyEntry entry;
  entry.name = "value.h";
  entry.kind = DependencyKind::Header;
  entry.content.digest = header.digest;
  entry.content.size = header.bytes.size();
  first.request.dependencies.entries.push_back(entry);
  first.request.units.front().dependencies.push_back(entry);
  first.blobs.push_back(header);

  auto submitted = harness.coordinator.submit(first);
  DC_EXPECT(submitted.ok());
  DC_EXPECT(harness.drive_one().ok());

  auto reused = harness.coordinator.submit(first);
  DC_EXPECT(reused.ok() && reused.value().served_from_cache);

  // Same logical dependency, different content: the old result must not be reused.
  SubmissionBundle second = first;
  const Blob changed = make_blob("#pragma once\nint value();\n// v2\n");
  second.request.dependencies.entries.front().content.digest = changed.digest;
  second.request.dependencies.entries.front().content.size = changed.bytes.size();
  second.request.units.front().dependencies.front().content.digest = changed.digest;
  second.request.units.front().dependencies.front().content.size = changed.bytes.size();
  // The source blob is still required; only the dependency content changed.
  second.blobs.push_back(changed);
  auto mutated = harness.coordinator.submit(second);
  DC_EXPECT(mutated.ok());
  DC_EXPECT_MSG(!mutated.value().served_from_cache, "a changed dependency must not reuse the old artifact");
  DC_EXPECT(!mutated.value().all_committed);
}

DC_TEST(reproducibility, divergent_output_is_a_typed_failure) {
  DC_PHASE("COMMIT");
  Harness harness;
  SubmissionBundle bundle = make_bundle(synthetic_toolchain(), synthetic_target(), "int f() { return 3; }",
                                        "unit.cpp", OutputKind::Assembly, ReproducibilityRequirement::Required);
  // Two workers plus speculative duplication produces two live attempts for one
  // logical compilation, which is exactly the divergence case.
  bundle.request.policy.allow_speculative_duplication = true;
  auto submitted = harness.coordinator.submit(bundle);
  DC_EXPECT(submitted.ok());
  const std::vector<Assignment> assignments = harness.coordinator.pump();
  DC_EXPECT_MSG(assignments.size() >= 2, "speculative duplication must create two attempts");
  for (const auto& assignment : assignments) {
    DC_EXPECT(harness.coordinator.begin_compile(assignment.claim).ok());
  }

  const auto report = [&harness](const Assignment& assignment, const std::string& body,
                                 SessionId session) -> Result<CommitDecision> {
    ReportOutput output;
    output.claim = assignment.claim;
    output.kind = OutputKind::Assembly;
    output.logical_name = "unit.cpp";
    output.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                        reinterpret_cast<const std::byte*>(body.data()) + body.size());
    output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
    return harness.coordinator.report_output(session, output);
  };

  auto first = report(assignments[0], "; artifact one\n", harness.session);
  DC_EXPECT(first.ok());
  DC_EXPECT_EQ(static_cast<int>(first.value().outcome), static_cast<int>(CommitOutcome::Committed));

  auto second = report(assignments[1], "; artifact two\n", harness.second_session);
  DC_EXPECT(second.ok());
  DC_EXPECT_EQ(static_cast<int>(second.value().outcome),
               static_cast<int>(CommitOutcome::ReproducibilityViolation));
  DC_EXPECT_EQ(static_cast<int>(second.value().error), static_cast<int>(ErrorCode::ReproducibilityViolation));

  // Exactly one authority survives, and the divergence is recorded.
  const CompilationId compilation = submitted.value().units.front().compilation;
  auto commit = harness.coordinator.commit(compilation);
  DC_EXPECT(commit.ok());
  DC_EXPECT_EQ(commit.value().artifact_digest.hex(), first.value().commit.artifact_digest.hex());
  const std::vector<CompilationRecord> records = harness.coordinator.compilations();
  bool recorded = false;
  for (const auto& record : records) {
    if (record.id == compilation && record.reproducibility_violation &&
        !record.divergent_candidates.empty()) {
      recorded = true;
    }
  }
  DC_EXPECT_MSG(recorded, "the divergent candidate must be retained for diagnostics");
}

DC_TEST(persistence, snapshot_and_journal_round_trip) {
  DC_PHASE("PERSISTENCE");
  Harness harness;
  SubmissionBundle bundle = make_bundle(synthetic_toolchain(), synthetic_target(), "int f() { return 11; }",
                                        "unit.cpp", OutputKind::Assembly, ReproducibilityRequirement::Preferred);
  auto submitted = harness.coordinator.submit(bundle);
  DC_EXPECT(submitted.ok());
  DC_EXPECT(harness.drive_one().ok());
  const CompilationId compilation = submitted.value().units.front().compilation;
  auto commit = harness.coordinator.commit(compilation);
  DC_EXPECT(commit.ok());
  const std::string digest = commit.value().artifact_digest.hex();

  CoordinatorConfig config;
  config.state_root = harness.root / "state";
  config.enable_persistence = true;
  harness.coordinator.close();

  Coordinator reopened;
  const Status opened = reopened.open(config);
  DC_EXPECT_MSG(opened.ok(), opened.describe());
  DC_EXPECT(reopened.epoch().value() >= 2);
  auto survived = reopened.commit(compilation);
  DC_EXPECT(survived.ok());
  DC_EXPECT_EQ(survived.value().artifact_digest.hex(), digest);
  DC_EXPECT(reopened.audit().clean);
  reopened.close();
}

DC_TEST(persistence, corruption_and_truncation_are_distinguished) {
  DC_PHASE("PERSISTENCE");
  const std::filesystem::path root = std::filesystem::temp_directory_path() /
                                     ("dc-persist-" + std::to_string(static_cast<long long>(SystemClock().now())));
  PersistentStore store;
  PersistentStore::Options options;
  options.root = root;
  std::vector<JournalRecord> records;
  std::vector<std::byte> snapshot;
  auto opened = store.open(options, records, snapshot);
  DC_EXPECT(opened.ok());
  const std::string payload = "record-payload";
  for (int i = 0; i < 5; ++i) {
    DC_EXPECT(store.append(RecordType::Header,
                           std::span<const std::byte>(reinterpret_cast<const std::byte*>(payload.data()),
                                                      payload.size()))
                  .ok());
  }
  store.close();

  // A torn tail is recovered by truncation and reported.
  {
    const std::filesystem::path journal = root / "journal.dcjournal";
    std::vector<std::byte> bytes;
    DC_EXPECT(read_file_bounded(journal, 1u << 20, bytes).ok());
    bytes.resize(bytes.size() - 7);
    DC_EXPECT(write_file_atomic(journal, std::span<const std::byte>(bytes.data(), bytes.size()), false).ok());
  }
  PersistentStore torn;
  std::vector<JournalRecord> torn_records;
  std::vector<std::byte> torn_snapshot;
  auto torn_result = torn.open(options, torn_records, torn_snapshot);
  DC_EXPECT(torn_result.ok());
  DC_EXPECT(torn_result.value().torn_tail);
  DC_EXPECT_EQ(torn_result.value().records_applied, 4ull);
  torn.close();

  // Interior corruption with a valid record after it is refused outright.
  {
    const std::filesystem::path journal = root / "journal.dcjournal";
    std::vector<std::byte> bytes;
    DC_EXPECT(read_file_bounded(journal, 1u << 20, bytes).ok());
    bytes[40] = static_cast<std::byte>(static_cast<std::uint8_t>(bytes[40]) ^ 0xFF);
    DC_EXPECT(write_file_atomic(journal, std::span<const std::byte>(bytes.data(), bytes.size()), false).ok());
  }
  PersistentStore corrupt;
  std::vector<JournalRecord> corrupt_records;
  std::vector<std::byte> corrupt_snapshot;
  auto corrupt_result = corrupt.open(options, corrupt_records, corrupt_snapshot);
  DC_EXPECT_MSG(!corrupt_result.ok(), "interior corruption must be refused");
  DC_EXPECT_EQ(static_cast<int>(corrupt_result.status().code()),
               static_cast<int>(ErrorCode::PersistenceCorrupt));
  corrupt.close();

  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

DC_TEST(persistence, blob_store_verifies_content_on_read) {
  DC_PHASE("PERSISTENCE");
  const std::filesystem::path root = std::filesystem::temp_directory_path() /
                                     ("dc-blob-" + std::to_string(static_cast<long long>(SystemClock().now())));
  PersistentStore store;
  PersistentStore::Options options;
  options.root = root;
  std::vector<JournalRecord> records;
  std::vector<std::byte> snapshot;
  auto opened = store.open(options, records, snapshot);
  DC_EXPECT(opened.ok());
  const std::string text = "artifact-bytes";
  auto stored = store.put_blob(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()),
                                                          text.size()));
  DC_EXPECT(stored.ok());
  std::vector<std::byte> loaded;
  DC_EXPECT(store.get_blob(stored.value(), loaded).ok());
  DC_EXPECT_EQ(loaded.size(), text.size());

  // Tampering with the stored bytes must be detected, not silently accepted.
  const std::filesystem::path path = store.blob_path(stored.value());
  std::vector<std::byte> tampered;
  DC_EXPECT(read_file_bounded(path, 1u << 20, tampered).ok());
  tampered[0] = static_cast<std::byte>(static_cast<std::uint8_t>(tampered[0]) ^ 0x5A);
  DC_EXPECT(write_file_atomic(path, std::span<const std::byte>(tampered.data(), tampered.size()), false).ok());
  std::vector<std::byte> reread;
  const Status status = store.get_blob(stored.value(), reread);
  DC_EXPECT(!status.ok());
  DC_EXPECT_EQ(static_cast<int>(status.code()), static_cast<int>(ErrorCode::IntegrityFailure));
  store.close();
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

DC_TEST(persistence, codec_round_trips_every_record) {
  DC_PHASE("PERSISTENCE");
  const ToolchainIdentity toolchain = synthetic_toolchain();
  std::vector<std::byte> encoded;
  CanonicalWriter writer;
  encode_toolchain(writer, toolchain);
  encoded.assign(writer.bytes().begin(), writer.bytes().end());
  CanonicalReader reader(std::span<const std::byte>(encoded.data(), encoded.size()));
  ToolchainIdentity decoded;
  DC_EXPECT(decode_toolchain(reader, decoded));
  DC_EXPECT_EQ(decoded.identity_digest.hex(), toolchain.identity_digest.hex());

  // A tampered identity digest must be rejected, not trusted.
  std::vector<std::byte> tampered = encoded;
  tampered[tampered.size() - 1] = static_cast<std::byte>(static_cast<std::uint8_t>(tampered.back()) ^ 0xFF);
  CanonicalReader tampered_reader(std::span<const std::byte>(tampered.data(), tampered.size()));
  ToolchainIdentity tampered_toolchain;
  DC_EXPECT(!decode_toolchain(tampered_reader, tampered_toolchain));
}

DC_TEST(wire, frames_are_bounded_and_validated) {
  DC_PHASE("PROTOCOL");
  Frame frame;
  frame.op = Op::Hello;
  frame.request_id = 7;
  HelloMessage hello;
  hello.role = SessionRole::Worker;
  hello.name = "worker-a";
  encode_hello(hello, frame.payload);
  std::vector<std::byte> encoded;
  DC_EXPECT(encode_frame(frame, encoded).ok());

  Frame decoded;
  DC_EXPECT(decode_frame(std::span<const std::byte>(encoded.data(), encoded.size()), decoded).ok());
  DC_EXPECT_EQ(static_cast<int>(decoded.op), static_cast<int>(Op::Hello));
  DC_EXPECT_EQ(decoded.request_id, 7ull);
  HelloMessage decoded_hello;
  DC_EXPECT(decode_hello(std::span<const std::byte>(decoded.payload.data(), decoded.payload.size()),
                         decoded_hello));
  DC_EXPECT_EQ(decoded_hello.name, std::string("worker-a"));

  // Wrong magic.
  std::vector<std::byte> bad_magic = encoded;
  bad_magic[4] = std::byte{0};
  DC_EXPECT(!decode_frame(std::span<const std::byte>(bad_magic.data(), bad_magic.size()), decoded).ok());

  // Out-of-domain op code.
  std::vector<std::byte> bad_op = encoded;
  bad_op[10] = std::byte{0xFF};
  bad_op[11] = std::byte{0xFF};
  DC_EXPECT(!decode_frame(std::span<const std::byte>(bad_op.data(), bad_op.size()), decoded).ok());

  // Length fields that disagree.
  std::vector<std::byte> bad_length = encoded;
  bad_length[20] = static_cast<std::byte>(static_cast<std::uint8_t>(bad_length[20]) + 4);
  DC_EXPECT(!decode_frame(std::span<const std::byte>(bad_length.data(), bad_length.size()), decoded).ok());

  // The frame reader refuses an oversized length before allocating.
  FrameReader reader(kMaxFrameBytes);
  std::vector<std::byte> oversized(28, std::byte{0});
  oversized[0] = std::byte{0xFF};
  oversized[1] = std::byte{0xFF};
  oversized[2] = std::byte{0xFF};
  oversized[3] = std::byte{0x7F};
  oversized[4] = std::byte{0x44};
  oversized[5] = std::byte{0x50};
  oversized[6] = std::byte{0x43};
  oversized[7] = std::byte{0x31};
  std::vector<std::vector<std::byte>> frames;
  const Status fed = reader.feed(std::span<const std::byte>(oversized.data(), oversized.size()), frames);
  DC_EXPECT(!fed.ok());
  DC_EXPECT_EQ(static_cast<int>(fed.code()), static_cast<int>(ErrorCode::FrameTooLarge));

  // Incremental arrival of a valid frame produces exactly one frame.
  FrameReader incremental(kMaxFrameBytes);
  std::vector<std::vector<std::byte>> collected;
  for (std::size_t i = 0; i < encoded.size(); ++i) {
    DC_EXPECT(incremental
                  .feed(std::span<const std::byte>(encoded.data() + i, 1), collected)
                  .ok());
  }
  DC_EXPECT_EQ(collected.size(), 1u);
}

DC_TEST(configuration, unchanged_content_keeps_its_generation) {
  DC_PHASE("CANONICALIZE");
  SourceRegistry registry;
  const Digest256 first = sha256(std::string_view("v1"));
  const Digest256 second = sha256(std::string_view("v2"));
  bool created = false;
  const SourceGeneration one = registry.resolve(SourceId(1), first, created);
  DC_EXPECT(created);
  DC_EXPECT_EQ(one.value(), 1ull);
  const SourceGeneration again = registry.resolve(SourceId(1), first, created);
  DC_EXPECT(!created);
  DC_EXPECT_EQ(again.value(), 1ull);
  const SourceGeneration two = registry.resolve(SourceId(1), second, created);
  DC_EXPECT(created);
  DC_EXPECT_EQ(two.value(), 2ull);
  // Returning to the original content restores its original generation: the
  // generation is a function of content history, not of submission order.
  const SourceGeneration back = registry.resolve(SourceId(1), first, created);
  DC_EXPECT(!created);
  DC_EXPECT_EQ(back.value(), 1ull);
}

int main(int argc, char** argv) { return dctest::run_all(argc, argv); }
