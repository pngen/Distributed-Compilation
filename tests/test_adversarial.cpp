// Distributed Compilation - adversarial tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every case here deliberately attacks a boundary: stale authority, malformed
// protocol input, corrupted durability, hostile paths, and child processes that
// misbehave.
#ifdef _WIN32
#include <windows.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
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
  SessionId session;

  explicit Fixture(int workers) {
    root = std::filesystem::temp_directory_path() /
           ("dc-adv-" + std::to_string(static_cast<long long>(SystemClock().now())) + "-" +
            std::to_string(reinterpret_cast<std::uintptr_t>(this)));
    CoordinatorConfig config;
    config.state_root = root / "state";
    config.clock = std::make_shared<ManualClock>();
    // A deliberately small artifact bound so the limit is exercised.
    config.max_artifact_bytes = 1u << 20;
    if (!coordinator.open(config).ok()) std::abort();
    WorkerCapabilities capabilities;
    capabilities.toolchains = {synthetic_toolchain()};
    capabilities.targets = {synthetic_target()};
    capabilities.input_formats = {InputFormat::Source};
    capabilities.logical_cores = 8;
    capabilities.memory_bytes = 8ull * 1024 * 1024 * 1024;
    capabilities.scratch_bytes = 8ull * 1024 * 1024 * 1024;
    capabilities.max_artifact_bytes = 4ull * 1024 * 1024;
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
      registration.worker_id = WorkerId(3000 + static_cast<std::uint64_t>(i));
      registration.boot_id = WorkerBootId(4000 + static_cast<std::uint64_t>(i));
      registration.max_inflight = 8;
      registration.capabilities = capabilities;
      auto registered = coordinator.register_worker(registration);
      if (!registered.ok()) std::abort();
      (void)coordinator.mark_ready(registered.value().session);
      if (i == 0) session = registered.value().session;
    }
  }

  ~Fixture() {
    coordinator.close();
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
  }

  Assignment take_assignment() {
    const std::vector<Assignment> assignments = coordinator.pump();
    if (assignments.empty()) return Assignment{};
    return assignments.front();
  }
};

std::filesystem::path self_path() {
#ifdef _WIN32
  wchar_t buffer[32768] = {0};
  const unsigned long length = GetModuleFileNameW(nullptr, buffer, 32768);
  if (length == 0) return std::filesystem::current_path();
  return std::filesystem::path(buffer);
#else
  return std::filesystem::current_path();
#endif
}

}  // namespace

DC_TEST(adversarial, stale_claims_are_refused_at_every_dimension) {
  DC_PHASE("AUTHORITY");
  Fixture fixture(1);
  SubmissionBundle bundle = make_bundle("int f() { return 31; }\n", 9001);
  auto submitted = fixture.coordinator.submit(bundle);
  DC_EXPECT(submitted.ok());
  const Assignment assignment = fixture.take_assignment();
  DC_EXPECT(!assignment.attempt.is_zero());
  DC_EXPECT(fixture.coordinator.begin_compile(assignment.claim).ok());

  const std::string body = "; adversarial artifact\n";
  const auto report_with = [&](AuthorityClaim claim, SessionId session, std::string text) {
    ReportOutput output;
    output.claim = claim;
    output.kind = OutputKind::Assembly;
    output.logical_name = "unit.cpp";
    output.bytes.assign(reinterpret_cast<const std::byte*>(text.data()),
                        reinterpret_cast<const std::byte*>(text.data()) + text.size());
    output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
    return fixture.coordinator.report_output(session, output);
  };

  AuthorityClaim claim = assignment.claim;
  claim.epoch = CoordinatorEpoch(claim.epoch.value() + 5);
  auto decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleEpoch));

  claim = assignment.claim;
  claim.worker_boot = WorkerBootId(claim.worker_boot.value() + 1);
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleWorkerBoot));

  claim = assignment.claim;
  claim.lease_generation = LeaseGeneration(claim.lease_generation.value() + 1);
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleLease));

  claim = assignment.claim;
  claim.attempt_generation = CompilationAttemptGeneration(claim.attempt_generation.value() + 1);
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleAttempt));

  claim = assignment.claim;
  claim.compilation_generation = CompilationGeneration(claim.compilation_generation.value() + 1);
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleCompilation));

  claim = assignment.claim;
  claim.dependency_generation = DependencyGeneration(claim.dependency_generation.value() + 1);
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleDependencies));

  claim = assignment.claim;
  claim.toolchain_generation = ToolchainGeneration(claim.toolchain_generation.value() + 1);
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleToolchain));

  claim = assignment.claim;
  claim.target_generation = TargetGeneration(claim.target_generation.value() + 1);
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleTarget));

  claim = assignment.claim;
  claim.specialization_generation = SpecializationGeneration(claim.specialization_generation.value() + 1);
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()),
               static_cast<int>(ErrorCode::StaleSpecialization));

  claim = assignment.claim;
  claim.policy_generation = CompilePolicyGeneration(claim.policy_generation.value() + 1);
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StalePolicy));

  claim = assignment.claim;
  claim.request_identity = Digest256{};
  claim.request_identity.raw()[0] = 1;
  decision = report_with(claim, fixture.session, body);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleRequest));

  // The genuine claim still works after all of the above were refused.
  decision = report_with(assignment.claim, fixture.session, body);
  DC_EXPECT(decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.value().outcome), static_cast<int>(CommitOutcome::Committed));

  // Replaying that same completion afterwards must not create a second authority.
  decision = report_with(assignment.claim, fixture.session, body);
  DC_EXPECT(!decision.ok() || decision.value().outcome != CommitOutcome::Committed);
  DC_EXPECT_EQ(fixture.coordinator.commits().size(), 1u);
  DC_EXPECT(fixture.coordinator.violations().size() > 0);
  const AuditReport audit = fixture.coordinator.audit();
  DC_EXPECT_MSG(audit.clean, audit.render());
}

DC_TEST(adversarial, worker_restart_does_not_inherit_authority) {
  DC_PHASE("RESTART");
  Fixture fixture(1);
  SubmissionBundle bundle = make_bundle("int f() { return 32; }\n", 9002);
  auto submitted = fixture.coordinator.submit(bundle);
  DC_EXPECT(submitted.ok());
  const Assignment assignment = fixture.take_assignment();
  DC_EXPECT(fixture.coordinator.begin_compile(assignment.claim).ok());

  // The worker restarts: same identity, fresh boot, fresh generation.
  WorkerRegistration restart;
  restart.endpoint = "local";
  restart.host = "local";
  restart.worker_id = assignment.worker;
  restart.boot_id = WorkerBootId(assignment.worker_boot.value() + 77);
  restart.max_inflight = 4;
  restart.capabilities = synthetic_toolchain().family == CompilerFamily::Unknown ? WorkerCapabilities{}
                                                                                 : WorkerCapabilities{};
  restart.capabilities.toolchains = {synthetic_toolchain()};
  restart.capabilities.targets = {synthetic_target()};
  restart.capabilities.input_formats = {InputFormat::Source};
  restart.capabilities.logical_cores = 4;
  restart.capabilities.memory_bytes = 4ull * 1024 * 1024 * 1024;
  restart.capabilities.scratch_bytes = 4ull * 1024 * 1024 * 1024;
  restart.capabilities.max_artifact_bytes = 4ull * 1024 * 1024;
  restart.capabilities.filesystem_isolation = true;
  restart.capabilities.sandbox = true;
  restart.capabilities.deterministic_build = true;
  restart.capabilities.trusted = true;
  restart.capabilities.evidence = EvidenceClass::Synthetic;
  restart.capabilities.host = "local";
  canonicalize(restart.capabilities);
  auto registered = fixture.coordinator.register_worker(restart);
  DC_EXPECT(registered.ok());
  (void)fixture.coordinator.mark_ready(registered.value().session);

  // The old boot's claim is presented from the new session.
  const std::string body = "; late artifact\n";
  ReportOutput output;
  output.claim = assignment.claim;
  output.kind = OutputKind::Assembly;
  output.logical_name = "unit.cpp";
  output.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                      reinterpret_cast<const std::byte*>(body.data()) + body.size());
  output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
  auto decision = fixture.coordinator.report_output(registered.value().session, output);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::StaleWorkerBoot));
  DC_EXPECT_EQ(fixture.coordinator.commits().size(), 0u);
}

DC_TEST(adversarial, coordinator_restart_invalidates_old_sessions_and_leases) {
  DC_PHASE("RESTART");
  Fixture fixture(1);
  SubmissionBundle bundle = make_bundle("int f() { return 33; }\n", 9003);
  auto submitted = fixture.coordinator.submit(bundle);
  DC_EXPECT(submitted.ok());
  const Assignment assignment = fixture.take_assignment();
  DC_EXPECT(fixture.coordinator.begin_compile(assignment.claim).ok());
  const CoordinatorEpoch epoch_before = fixture.coordinator.epoch();

  CoordinatorConfig config;
  config.state_root = fixture.root / "state";
  config.enable_persistence = true;
  fixture.coordinator.close();
  Coordinator reopened;
  DC_EXPECT(reopened.open(config).ok());
  DC_EXPECT(reopened.epoch().value() > epoch_before.value());

  // Every lease from the previous epoch is revoked, and the in-flight attempt
  // is classified conservatively rather than resumed.
  for (const auto& lease : reopened.leases()) {
    DC_EXPECT_MSG(lease.revoked || lease.epoch == reopened.epoch(),
                  "a lease from the previous epoch must be revoked");
  }
  bool ambiguous_seen = false;
  for (const auto& attempt : reopened.attempts()) {
    if (attempt.state == AttemptState::Ambiguous) ambiguous_seen = true;
    DC_EXPECT(attempt.state != AttemptState::Running);
  }
  DC_EXPECT_MSG(ambiguous_seen, "an in-flight attempt must be classified ambiguous after a restart");

  // The stale claim cannot commit under the new epoch.
  const std::string body = "; pre-restart artifact\n";
  ReportOutput output;
  output.claim = assignment.claim;
  output.kind = OutputKind::Assembly;
  output.logical_name = "unit.cpp";
  output.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                      reinterpret_cast<const std::byte*>(body.data()) + body.size());
  output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
  auto decision = reopened.report_output(assignment.session, output);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(reopened.commits().size(), 0u);
  DC_EXPECT(reopened.audit().clean);
  reopened.close();
}

DC_TEST(adversarial, oversized_and_replayed_protocol_input_is_refused) {
  DC_PHASE("PROTOCOL");
  DC_EXPECT(initialize_network().ok());
  auto listener = Listener::bind("127.0.0.1", 0, 8);
  DC_EXPECT(listener.ok());
  const std::uint16_t port = listener.value().port();

  std::atomic<bool> server_done{false};
  std::atomic<bool> server_rejected{false};
  std::thread server([&listener, &server_done, &server_rejected]() {
    auto accepted = listener.value().accept();
    if (!accepted.ok()) {
      server_done.store(true);
      return;
    }
    FrameReader reader(kMaxFrameBytes);
    std::byte buffer[4096];
    for (;;) {
      auto received = accepted.value().recv_some(std::span<std::byte>(buffer, sizeof(buffer)));
      if (received.outcome != Socket::RecvOutcome::Data) continue;
      std::vector<std::vector<std::byte>> frames;
      const Status status = reader.feed(std::span<const std::byte>(buffer, received.bytes), frames);
      if (!status.ok()) {
        server_rejected.store(true);
        break;
      }
      if (!frames.empty()) break;
    }
    accepted.value().close();
    server_done.store(true);
  });

  auto client = Socket::connect("127.0.0.1", port, 5000);
  DC_EXPECT(client.ok());
  // A frame header claiming an enormous payload must be refused before any
  // allocation proportional to that claim happens.
  std::vector<std::byte> hostile(28, std::byte{0});
  const std::uint32_t declared = 0x7FFFFFF0u;
  for (int i = 0; i < 4; ++i) hostile[static_cast<std::size_t>(i)] = static_cast<std::byte>((declared >> (i * 8)) & 0xFF);
  hostile[4] = std::byte{0x44};
  hostile[5] = std::byte{0x50};
  hostile[6] = std::byte{0x43};
  hostile[7] = std::byte{0x31};
  DC_EXPECT(client.value().send_all(std::span<const std::byte>(hostile.data(), hostile.size())).ok());
  for (int i = 0; i < 200 && !server_done.load(); ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  DC_EXPECT_MSG(server_rejected.load(), "the server must refuse an oversized frame");
  client.value().close();
  server.join();
  listener.value().close();
  shutdown_network();

  // A well-formed frame carrying an out-of-domain enum is refused by the codec.
  Frame frame;
  frame.op = Op::Hello;
  frame.request_id = 1;
  frame.payload = {std::byte{3}};   // domain tag length with no tag bytes
  std::vector<std::byte> encoded;
  DC_EXPECT(encode_frame(frame, encoded).ok());
  Frame decoded;
  DC_EXPECT(decode_frame(std::span<const std::byte>(encoded.data(), encoded.size()), decoded).ok());
  HelloMessage hello;
  DC_EXPECT(!decode_hello(std::span<const std::byte>(decoded.payload.data(), decoded.payload.size()), hello));
}

DC_TEST(adversarial, corrupt_snapshot_and_schema_mismatch_are_refused) {
  DC_PHASE("PERSISTENCE");
  const std::filesystem::path root = std::filesystem::temp_directory_path() /
                                     ("dc-corrupt-" + std::to_string(static_cast<long long>(SystemClock().now())));
  {
    PersistentStore store;
    PersistentStore::Options options;
    options.root = root;
    std::vector<JournalRecord> records;
    std::vector<std::byte> snapshot;
    DC_EXPECT(store.open(options, records, snapshot).ok());
    const std::string payload = "snapshot-body";
    DC_EXPECT(store
                  .append(RecordType::Header,
                          std::span<const std::byte>(reinterpret_cast<const std::byte*>(payload.data()),
                                                     payload.size()))
                  .ok());
    DC_EXPECT(store
                  .write_snapshot(std::span<const std::byte>(reinterpret_cast<const std::byte*>(payload.data()),
                                                             payload.size()))
                  .ok());
    store.close();
  }

  const std::filesystem::path snapshot_path = root / "snapshot.dcsnap";
  std::vector<std::byte> original;
  DC_EXPECT(read_file_bounded(snapshot_path, 1u << 20, original).ok());

  // A flipped payload byte must be caught by the snapshot digest.
  {
    std::vector<std::byte> tampered = original;
    tampered.back() = static_cast<std::byte>(static_cast<std::uint8_t>(tampered.back()) ^ 0xFF);
    DC_EXPECT(write_file_atomic(snapshot_path, std::span<const std::byte>(tampered.data(), tampered.size()),
                                false)
                  .ok());
    PersistentStore store;
    PersistentStore::Options options;
    options.root = root;
    std::vector<JournalRecord> records;
    std::vector<std::byte> snapshot;
    auto opened = store.open(options, records, snapshot);
    DC_EXPECT(!opened.ok());
    DC_EXPECT_EQ(static_cast<int>(opened.status().code()), static_cast<int>(ErrorCode::IntegrityFailure));
    store.close();
  }

  // An unknown schema version must be refused rather than guessed at.
  {
    std::vector<std::byte> wrong_schema = original;
    wrong_schema[4] = std::byte{99};
    wrong_schema[5] = std::byte{0};
    DC_EXPECT(write_file_atomic(snapshot_path,
                                std::span<const std::byte>(wrong_schema.data(), wrong_schema.size()), false)
                  .ok());
    PersistentStore store;
    PersistentStore::Options options;
    options.root = root;
    std::vector<JournalRecord> records;
    std::vector<std::byte> snapshot;
    auto opened = store.open(options, records, snapshot);
    DC_EXPECT(!opened.ok());
    DC_EXPECT_EQ(static_cast<int>(opened.status().code()), static_cast<int>(ErrorCode::SchemaMismatch));
    store.close();
  }

  // A truncated snapshot header must be refused, not partially decoded.
  {
    std::vector<std::byte> truncated(original.begin(), original.begin() + 20);
    DC_EXPECT(write_file_atomic(snapshot_path,
                                std::span<const std::byte>(truncated.data(), truncated.size()), false)
                  .ok());
    PersistentStore store;
    PersistentStore::Options options;
    options.root = root;
    std::vector<JournalRecord> records;
    std::vector<std::byte> snapshot;
    auto opened = store.open(options, records, snapshot);
    DC_EXPECT(!opened.ok());
    store.close();
  }

  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

DC_TEST(adversarial, hostile_paths_and_limits_are_enforced) {
  DC_PHASE("SECURITY");
  DC_EXPECT_EQ(sanitize_token(""), std::string());
  DC_EXPECT_EQ(sanitize_token(".."), std::string());
  DC_EXPECT_EQ(sanitize_token("a/b"), std::string());
  DC_EXPECT_EQ(sanitize_token("a\\b"), std::string());
  DC_EXPECT_EQ(sanitize_token(std::string(200, 'a')), std::string());
  DC_EXPECT_EQ(sanitize_token("ok-1_2"), std::string("ok-1_2"));

  Fixture fixture(1);
  // A request whose source blob does not match its declared digest is refused.
  SubmissionBundle bundle = make_bundle("int f() { return 34; }\n", 9004);
  SubmissionBundle tampered = bundle;
  tampered.blobs.front().bytes.push_back(std::byte{'x'});
  auto submitted = fixture.coordinator.submit(tampered);
  DC_EXPECT(!submitted.ok());
  DC_EXPECT_EQ(static_cast<int>(submitted.status().code()), static_cast<int>(ErrorCode::IntegrityFailure));

  // A request referencing content that was never supplied is refused.
  SubmissionBundle missing = bundle;
  missing.blobs.clear();
  auto missing_result = fixture.coordinator.submit(missing);
  DC_EXPECT(!missing_result.ok());

  // An artifact larger than the configured bound is refused.
  auto accepted = fixture.coordinator.submit(bundle);
  DC_EXPECT(accepted.ok());
  const Assignment assignment = fixture.take_assignment();
  DC_EXPECT(fixture.coordinator.begin_compile(assignment.claim).ok());
  ReportOutput huge;
  huge.claim = assignment.claim;
  huge.kind = OutputKind::Assembly;
  huge.logical_name = "unit.cpp";
  huge.bytes.assign(8u * 1024u * 1024u, std::byte{'a'});
  huge.declared_digest = sha256(std::span<const std::byte>(huge.bytes.data(), huge.bytes.size()));
  auto decision = fixture.coordinator.report_output(fixture.session, huge);
  DC_EXPECT(!decision.ok());
  DC_EXPECT_EQ(static_cast<int>(decision.status().code()), static_cast<int>(ErrorCode::LimitExceeded));
}

DC_TEST(adversarial, compiler_output_is_bounded_and_a_crashed_child_is_reported) {
  DC_PHASE("COMPILE");
  const std::filesystem::path exe = self_path();
  DC_EXPECT(std::filesystem::exists(exe));

  // A child that emits far more than the capture bound must be drained and
  // truncated rather than allowed to exhaust memory or block forever.
  ProcessSpec chatty;
  chatty.executable = exe;
  chatty.arguments = {"--emit-bytes", "33554432"};   // 32 MiB of stdout
  chatty.inherit_environment = true;
  chatty.max_output_bytes = 1u << 20;
  chatty.timeout_millis = 120000;
  const ProcessResult result = run_process(chatty);
  DC_EXPECT(result.started);
  DC_EXPECT_EQ(result.exit_code, 0);
  DC_EXPECT(result.stdout_text.size() <= (1u << 20));
  DC_EXPECT_MSG(result.stdout_truncated, "capture must report truncation");

  // A child that cannot be started is reported, never treated as success.
  ProcessSpec missing;
  missing.executable = exe.string() + ".does-not-exist";
  missing.inherit_environment = true;
  const ProcessResult missing_result = run_process(missing);
  DC_EXPECT(!missing_result.started);
  DC_EXPECT(!missing_result.succeeded());

  // A cancelled child is terminated promptly instead of running to completion.
  std::atomic<bool> cancel{false};
  ProcessSpec long_running;
  long_running.executable = exe;
  long_running.arguments = {"--sleep-ms", "60000"};
  long_running.inherit_environment = true;
  long_running.timeout_millis = 120000;
  long_running.cancel_flag = &cancel;
  auto started = ChildProcess::start(long_running);
  DC_EXPECT(started.ok());
  // Give the child a moment to be scheduled, then cancel it.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  cancel.store(true);
  const auto cancel_started = std::chrono::steady_clock::now();
  const ProcessResult cancelled = started.value()->wait(120000);
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - cancel_started)
                           .count();
  DC_EXPECT(cancelled.started);
  DC_EXPECT_MSG(elapsed < 30000, "cancellation must stop the child promptly");
  DC_EXPECT(cancelled.exit_code != 0);
}

DC_TEST(adversarial, fan_in_incomplete_blocks_commit) {
  DC_PHASE("COMMIT");
  Fixture fixture(1);
  SubmissionBundle bundle;
  bundle.request.toolchain = synthetic_toolchain();
  bundle.request.target = synthetic_target();
  bundle.request.request_id = RequestId(9005);
  bundle.request.policy.require_provable_toolchain = false;
  const Blob first = make_blob("int a() { return 1; }\n");
  const Blob second = make_blob("int b() { return 2; }\n");
  for (const Blob& blob : {first, second}) {
    CompilationUnitSpec unit;
    unit.index = static_cast<std::uint32_t>(bundle.request.units.size());
    unit.logical_name = unit.index == 0 ? "a.cpp" : "b.cpp";
    unit.kind = UnitKind::Compile;
    unit.output_kind = OutputKind::Assembly;
    UnitSource source;
    source.logical_name = unit.logical_name;
    source.format = InputFormat::Source;
    source.language_mode = "c++20";
    source.content.digest = blob.digest;
    source.content.size = blob.bytes.size();
    unit.sources.push_back(source);
    bundle.request.units.push_back(unit);
    bundle.blobs.push_back(blob);
  }
  CompilationUnitSpec link;
  link.index = 2;
  link.logical_name = "link:final";
  link.kind = UnitKind::Link;
  link.output_kind = OutputKind::Assembly;
  link.child_units = {0, 1};
  link.mandatory = true;
  bundle.request.units.push_back(link);

  auto submitted = fixture.coordinator.submit(bundle);
  DC_EXPECT(submitted.ok());
  const CompilationId root = submitted.value().units.back().compilation;

  // Pump once: both compile units are assigned, the link unit must not be.
  const std::vector<Assignment> assignments = fixture.coordinator.pump();
  DC_EXPECT_MSG(assignments.size() >= 2, "both compile units must be assigned");
  for (const auto& assignment : assignments) {
    DC_EXPECT_MSG(assignment.compilation != root, "the link unit was assigned before its fan-in completed");
  }

  // Only one of the two mandatory children is completed.
  const Assignment first_assignment = assignments.front();
  DC_EXPECT(!first_assignment.attempt.is_zero());
  DC_EXPECT(fixture.coordinator.begin_compile(first_assignment.claim).ok());
  const std::string body = "; child artifact\n";
  ReportOutput output;
  output.claim = first_assignment.claim;
  output.kind = OutputKind::Assembly;
  output.logical_name = "a.cpp";
  output.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                      reinterpret_cast<const std::byte*>(body.data()) + body.size());
  output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
  auto decision = fixture.coordinator.report_output(fixture.session, output);
  DC_EXPECT(decision.ok());

  // The link unit cannot commit while a mandatory child is outstanding.
  auto commit = fixture.coordinator.commit(root);
  DC_EXPECT(!commit.ok());
  DC_EXPECT(fixture.coordinator.audit().clean);

  // Failing the remaining mandatory child must fail the parent rather than
  // leaving it waiting for a gate that can never open.
  for (std::size_t i = 1; i < assignments.size(); ++i) {
    const Assignment& pending = assignments[i];
    if (pending.compilation == root) continue;
    DC_EXPECT(fixture.coordinator.begin_compile(pending.claim).ok());
    AttemptFailure failure;
    failure.claim = pending.claim;
    failure.code = ErrorCode::Unsupported;
    failure.detail = "simulated deterministic refusal";
    DC_EXPECT(fixture.coordinator.fail_attempt(pending.session, failure).ok());
  }
  auto root_record = fixture.coordinator.compilation(root);
  DC_EXPECT(root_record.ok());
  DC_EXPECT_MSG(root_record.value().state == CompilationState::Failed,
                "an impossible fan-in must fail the parent: " +
                    std::string(to_string(root_record.value().state)));
  DC_EXPECT_EQ(static_cast<int>(root_record.value().failure), static_cast<int>(ErrorCode::FanInIncomplete));
  DC_EXPECT(fixture.coordinator.audit().clean);
}

#include <cstdio>

int main(int argc, char** argv) {
  if (argc > 2 && std::string(argv[1]) == "--sleep-ms") {
    std::this_thread::sleep_for(std::chrono::milliseconds(std::stoll(argv[2])));
    return 0;
  }
  if (argc > 2 && std::string(argv[1]) == "--emit-bytes") {
    const std::size_t count = static_cast<std::size_t>(std::stoull(argv[2]));
    const std::string chunk(4096, 'x');
    std::size_t total = 0;
    while (total < count) {
      const std::size_t take = std::min<std::size_t>(chunk.size(), count - total);
      std::fwrite(chunk.data(), 1, take, stdout);
      total += take;
    }
    std::fflush(stdout);
    return 0;
  }
  return dctest::run_all(argc, argv);
}
