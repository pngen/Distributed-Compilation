// Distributed Compilation - dc_worker: executes assigned compilation units.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// The worker owns no authority. It advertises evidence-backed capabilities,
// executes what it is assigned under a lease, and reports bytes. The
// coordinator decides whether those bytes become authoritative.
#ifdef _WIN32
#define FD_SETSIZE 1024
#include <winsock2.h>
#endif

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "app_common.hpp"
#include "dc/compiler.hpp"
#include "dc/net.hpp"
#include "dc/process.hpp"
#include "dc/wire.hpp"

namespace {

using namespace dc;

// One slot per assigned attempt. The worker thread that performs the compile is
// detached and tracked by this slot: a std::thread object that is destroyed
// while still joinable calls std::terminate, which would kill the worker the
// moment its first compile finished. Shutdown drains the slot map instead.
struct ActiveCompile {
  std::atomic<bool> cancel{false};
  std::uint64_t attempt = 0;
};

}  // namespace

int main(int argc, char** argv) {
  using namespace dc::app;

  Arguments arguments = Arguments::parse(argc, argv, 1);
  if (arguments.has("help")) {
    emit("usage: dc_worker --coordinator host:port [--name <id>] [--max-inflight N] [--scratch <dir>]\n"
         "                 [--cuda-arch sm_120] [--synthetic] [--no-cuda] [--verbose]");
    return 0;
  }

  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  const std::string endpoint = arguments.get("coordinator", "127.0.0.1:9600");
  if (!parse_endpoint(endpoint, host, port)) {
    emit_error("dc_worker: --coordinator must be host:port");
    return 2;
  }

  service_log_path() = arguments.get("log");
  const std::string worker_name = arguments.get("name", "worker");
  const std::uint32_t max_inflight =
      static_cast<std::uint32_t>(arguments.get_int("max-inflight", 2));
  std::filesystem::path scratch = arguments.get("scratch");
  if (scratch.empty()) scratch = unique_temp_path("dc-worker-scratch");
  Status scratch_status = ensure_directory(scratch);
  if (!scratch_status.ok()) {
    emit_error("dc_worker: cannot create scratch: " + scratch_status.describe());
    return 3;
  }

  DiscoveryOptions discovery;
  discovery.msvc_roots = default_msvc_roots();
  discovery.cuda_roots = arguments.has("no-cuda") ? std::vector<std::filesystem::path>{} : default_cuda_roots();
  discovery.include_synthetic = arguments.has("synthetic");
  if (arguments.has("synthetic-profile")) {
    discovery.synthetic_profiles = arguments.all("synthetic-profile");
  }
  for (const auto& architecture : arguments.all("cuda-arch")) {
    discovery.cuda_architectures.push_back(architecture);
  }
  if (discovery.cuda_architectures.empty()) discovery.cuda_architectures.push_back("sm_120");
  const bool verbose = arguments.has("verbose");

  const DiscoveryResult discovered = discover_toolchains(discovery);
  for (const auto& note : discovered.notes) {
    if (verbose) emit("dc_worker: discovery: " + note);
  }

  WorkerCapabilities capabilities;
  capabilities.host = arguments.get("host", "local");
  capabilities.toolchains = discovered.toolchains;
  capabilities.targets = discovered.targets;
  capabilities.logical_cores = std::thread::hardware_concurrency();
  if (capabilities.logical_cores == 0) capabilities.logical_cores = 1;
  capabilities.memory_bytes = 8ull * 1024 * 1024 * 1024;
  capabilities.scratch_bytes = 16ull * 1024 * 1024 * 1024;
  capabilities.max_artifact_bytes = 128ull * 1024 * 1024;
  capabilities.filesystem_isolation = true;
  capabilities.sandbox = true;
  capabilities.deterministic_build = true;
  capabilities.remote_cache_access = false;
  capabilities.artifact_store_access = false;
  capabilities.trusted = true;

  bool any_real = false;
  for (const auto& toolchain : capabilities.toolchains) {
    if (toolchain.evidence == EvidenceClass::Real) any_real = true;
    capabilities.plugins.insert(capabilities.plugins.end(), toolchain.plugins.begin(), toolchain.plugins.end());
    for (const auto& sdk : toolchain.sdk) {
      bool present = false;
      for (const auto& existing : capabilities.sdks) {
        if (existing.name == sdk.name && existing.version == sdk.version) present = true;
      }
      if (!present) capabilities.sdks.push_back(sdk);
    }
  }
  for (const auto& target : capabilities.targets) {
    (void)target;
    capabilities.input_formats.push_back(InputFormat::Source);
    capabilities.input_formats.push_back(InputFormat::Object);
  }
  if (capabilities.input_formats.empty()) {
    capabilities.input_formats.push_back(InputFormat::Source);
  }
  capabilities.evidence = any_real ? EvidenceClass::Real
                                   : (capabilities.toolchains.empty() ? EvidenceClass::Unknown
                                                                      : EvidenceClass::Synthetic);
  canonicalize(capabilities);

  Status network = initialize_network();
  if (!network.ok()) {
    emit_error("dc_worker: " + network.describe());
    return 4;
  }

  auto connected = Socket::connect(host, port, 10000);
  if (!connected.ok()) {
    emit_error("dc_worker: cannot connect to " + endpoint + ": " + connected.status().describe());
    shutdown_network();
    return 5;
  }
  Socket socket = std::move(connected.value());

  // One lock covers both encoding and transmission. Holding it across the send
  // is what keeps the frame stream ordered: a heartbeat thread and a compile
  // thread that merely copied their bytes under the lock and then raced to send
  // would interleave partial frames and corrupt the session.
  std::mutex send_mutex;
  std::atomic<bool> stopping{false};

  const auto send_frame = [&](Op op, std::uint64_t request_id, const std::vector<std::byte>& payload) {
    Frame frame;
    frame.op = op;
    frame.request_id = request_id;
    frame.payload = payload;
    std::vector<std::byte> encoded;
    if (!encode_frame(frame, encoded).ok()) return false;
    std::lock_guard<std::mutex> guard(send_mutex);
    return socket.send_all(std::span<const std::byte>(encoded.data(), encoded.size())).ok();
  };

  // Identity: the worker id is stable across restarts (it names the machine
  // slot); the boot id is fresh for every process start so that a restarted
  // worker can never inherit the previous boot's compile authority.
  const auto stable_hash = [](const std::string& text) {
    CanonicalWriter w;
    w.domain("dc.worker-id.v1");
    w.str(text);
    return w.hash();
  };
  const Digest256 name_digest = stable_hash(worker_name + "@" + endpoint);
  std::uint64_t name_bits = 0;
  std::memcpy(&name_bits, name_digest.data(), sizeof(name_bits));
  const WorkerId worker_id(mix64(name_bits));

  CanonicalWriter boot_writer;
  boot_writer.domain("dc.worker-boot.v1");
  boot_writer.str(worker_name);
  boot_writer.i64(SystemClock().now());
  boot_writer.u64(static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())));
  boot_writer.u64(reinterpret_cast<std::uintptr_t>(&capabilities));
  std::uint64_t boot_bits = 0;
  std::memcpy(&boot_bits, boot_writer.hash().data(), sizeof(boot_bits));
  const WorkerBootId boot_id(mix64(boot_bits));

  {
    HelloMessage hello;
    hello.role = SessionRole::Worker;
    hello.name = worker_name;
    std::vector<std::byte> payload;
    encode_hello(hello, payload);
    if (!send_frame(Op::Hello, 1, payload)) {
      emit_error("dc_worker: handshake failed");
      shutdown_network();
      return 6;
    }
  }

  RegisterWorkerMessage registration;
  registration.endpoint = endpoint;
  registration.host = capabilities.host;
  registration.worker_id = worker_id;
  registration.boot_id = boot_id;
  registration.max_inflight = max_inflight;
  registration.capabilities = capabilities;
  {
    std::vector<std::byte> payload;
    if (!encode_register_worker(registration, payload)) {
      emit_error("dc_worker: cannot encode registration");
      shutdown_network();
      return 6;
    }
    if (!send_frame(Op::RegisterWorker, 2, payload)) {
      emit_error("dc_worker: registration send failed");
      shutdown_network();
      return 6;
    }
  }

  SessionId session;
  std::atomic<bool> ready{false};
  std::map<std::uint64_t, std::shared_ptr<ActiveCompile>> active;
  std::mutex active_mutex;

  const std::string ready_file = arguments.get("ready-file");
  const std::string claim_log = arguments.get("claim-log");
  const auto publish = [&ready_file](const std::string& line) {
    if (ready_file.empty()) return;
    const std::string text = line + "\n";
    (void)write_file_atomic(
        ready_file,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()), false);
  };
  const auto record_claim = [&claim_log](const Assignment& assignment) {
    if (claim_log.empty()) return;
    const std::string line = "CLAIM attempt=" + std::to_string(assignment.attempt.value()) +
                             " compilation=" + std::to_string(assignment.compilation.value()) +
                             " unit=" + std::to_string(assignment.unit.value()) +
                             " boot=" + std::to_string(assignment.worker_boot.value()) +
                             " worker=" + std::to_string(assignment.worker.value()) +
                             " lease=" + std::to_string(assignment.lease.id.value()) + "\n";
    FILE* file = nullptr;
#ifdef _WIN32
    if (fopen_s(&file, claim_log.c_str(), "ab") != 0) file = nullptr;
#else
    file = std::fopen(claim_log.c_str(), "ab");
#endif
    if (file != nullptr) {
      std::fwrite(line.data(), 1, line.size(), file);
      std::fflush(file);
      std::fclose(file);
    }
  };

  const std::string ready_line = "DC_WORKER_READY name=" + worker_name +
                                 " worker=" + std::to_string(worker_id.value()) +
                                 " boot=" + std::to_string(boot_id.value()) + " tools=" +
                                 std::to_string(capabilities.toolchains.size()) + " targets=" +
                                 std::to_string(capabilities.targets.size()) + " evidence=" +
                                 std::string(to_string(capabilities.evidence));
  emit(ready_line);
  std::fflush(stdout);
  publish(ready_line);

  std::thread heartbeat([&]() {
    while (!stopping.load()) {
      for (int i = 0; i < 20 && !stopping.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      if (stopping.load()) break;
      std::vector<std::byte> empty;
      (void)send_frame(Op::Heartbeat, 0, empty);
    }
  });

  const auto start_compile = [&](const Assignment& assignment) {
    auto slot = std::make_shared<ActiveCompile>();
    slot->attempt = assignment.attempt.value();
    {
      std::lock_guard<std::mutex> guard(active_mutex);
      active[assignment.attempt.value()] = slot;
    }
    std::thread([&, assignment, slot]() {
      const ToolchainIdentity* toolchain = nullptr;
      for (const auto& candidate : capabilities.toolchains) {
        if (candidate.identity_digest == assignment.toolchain.identity_digest) {
          toolchain = &candidate;
          break;
        }
      }
      if (toolchain == nullptr) {
        AttemptFailure failure;
        failure.claim = assignment.claim;
        failure.code = ErrorCode::StaleToolchain;
        failure.detail = "assigned toolchain is no longer advertised by this worker";
        std::vector<std::byte> payload;
        if (encode_fail_attempt(failure, payload)) (void)send_frame(Op::FailAttempt, 0, payload);
        std::lock_guard<std::mutex> guard(active_mutex);
        active.erase(assignment.attempt.value());
        return;
      }

      emit("DC_WORKER_COMPILE_START attempt=" + std::to_string(assignment.attempt.value()) + " unit=" +
           assignment.logical_name + " toolchain=" + std::string(to_string(toolchain->family)));
      std::vector<std::byte> begin_payload;
      encode_authority_claim(assignment.claim, begin_payload);
      (void)send_frame(Op::BeginCompile, 0, begin_payload);

      auto compiled = run_compile_unit(assignment, *toolchain, scratch, &slot->cancel);
      if (!compiled.ok()) {
        AttemptFailure failure;
        failure.claim = assignment.claim;
        failure.code = compiled.status().code();
        failure.detail = compiled.status().detail();
        failure.produced_candidate = false;
        emit("DC_WORKER_COMPILE_FAILED attempt=" + std::to_string(assignment.attempt.value()) + " code=" +
             std::string(to_string(compiled.status().code())) + " detail=" + failure.detail);
        std::vector<std::byte> payload;
        if (encode_fail_attempt(failure, payload)) (void)send_frame(Op::FailAttempt, 0, payload);
        std::lock_guard<std::mutex> guard(active_mutex);
        active.erase(assignment.attempt.value());
        return;
      }
      CompileRunResult result = compiled.value();
      if (slot->cancel.load()) {
        AttemptFailure failure;
        failure.claim = assignment.claim;
        failure.code = ErrorCode::Cancelled;
        failure.detail = "compile cancelled by the coordinator";
        std::vector<std::byte> payload;
        if (encode_fail_attempt(failure, payload)) (void)send_frame(Op::FailAttempt, 0, payload);
        std::lock_guard<std::mutex> guard(active_mutex);
        active.erase(assignment.attempt.value());
        return;
      }

      ReportOutput output;
      output.claim = assignment.claim;
      output.kind = assignment.output_kind;
      output.logical_name = assignment.logical_name;
      output.bytes = std::move(result.artifact);
      output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
      output.compiler_invocation = result.invocation;
      output.compiler_version_string = result.compiler_version;
      output.compiler_wall_millis = result.wall_millis;
      output.exit_code = result.exit_code;
      emit("DC_WORKER_REPORTING attempt=" + std::to_string(assignment.attempt.value()) + " bytes=" +
           std::to_string(output.bytes.size()) + " digest=" + output.declared_digest.hex().substr(0, 16) +
           " exit=" + std::to_string(result.exit_code) + " millis=" + std::to_string(result.wall_millis) +
           " code=" + std::string(to_string(compiled.status().code())) + " detail=[" + result.detail + "]");
      emit("DC_WORKER_INVOCATION " + result.invocation);
      if (!result.stdout_text.empty()) emit("DC_WORKER_STDOUT " + result.stdout_text.substr(0, 800));
      if (!result.stderr_text.empty()) emit("DC_WORKER_STDERR " + result.stderr_text.substr(0, 800));
      std::vector<std::byte> payload;
      if (encode_report_output(output, payload)) {
        (void)send_frame(Op::ReportOutput, 0, payload);
      }
      std::lock_guard<std::mutex> guard(active_mutex);
      active.erase(assignment.attempt.value());
    }).detach();
    return slot;
  };

  FrameReader reader(kMaxFrameBytes);
  bool running = true;
  while (running && !stopping.load()) {
    std::byte buffer[64 * 1024];
    auto received = socket.recv_some(std::span<std::byte>(buffer, sizeof(buffer)));
    if (received.outcome == Socket::RecvOutcome::WouldBlock) {
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
      continue;
    }
    if (received.outcome == Socket::RecvOutcome::Closed || received.outcome == Socket::RecvOutcome::Failed) {
      emit("DC_WORKER_DISCONNECTED");
      std::fflush(stdout);
      break;
    }
    std::vector<std::vector<std::byte>> frames;
    Status fed = reader.feed(std::span<const std::byte>(buffer, received.bytes), frames);
    if (!fed.ok()) {
      emit_error("dc_worker: protocol violation: " + fed.describe());
      break;
    }
    for (const auto& raw : frames) {
      Frame frame;
      if (!decode_frame(std::span<const std::byte>(raw.data(), raw.size()), frame).ok()) continue;
      if (verbose) emit("dc_worker: <- " + std::string(to_string(frame.op)));

      if (frame.op == Op::Response) {
        ResponseMessage response;
        if (!decode_response(std::span<const std::byte>(frame.payload.data(), frame.payload.size()), response)) {
          continue;
        }
        if (response.op == Op::RegisterWorker && response.code == ErrorCode::Ok) {
          ReadyMessage ready_message;
          if (decode_ready(std::span<const std::byte>(response.payload.data(), response.payload.size()),
                           ready_message)) {
            session = ready_message.session;
            const std::string registered_line =
                "DC_WORKER_REGISTERED name=" + worker_name + " worker=" +
                std::to_string(worker_id.value()) + " boot=" + std::to_string(boot_id.value()) +
                " session=" + std::to_string(session.value()) + " generation=" +
                std::to_string(ready_message.generation.value()) + " epoch=" +
                std::to_string(ready_message.epoch.value());
            emit(registered_line);
            std::fflush(stdout);
            publish(registered_line);
            std::vector<std::byte> empty;
            (void)send_frame(Op::WorkerReady, 3, empty);
            ready.store(true);
          }
        } else if (response.op == Op::ReportOutput) {
          CommitResponse decision;
          if (decode_commit_response(std::span<const std::byte>(response.payload.data(),
                                                               response.payload.size()),
                                     decision)) {
            emit("DC_WORKER_COMMIT compilation=" + std::to_string(decision.commit.compilation.value()) +
                 " outcome=" + std::string(to_string(decision.outcome)) + " detail=" + decision.detail);
            std::fflush(stdout);
          }
        } else if (response.op == Op::BeginCompile && response.code != ErrorCode::Ok) {
          emit("DC_WORKER_BEGIN_REFUSED code=" + std::string(to_string(response.code)) +
               " detail=" + response.detail);
          std::fflush(stdout);
        }
        continue;
      }

      if (frame.op == Op::Assign) {
        Assignment assignment;
        if (!decode_assignment(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                               assignment)) {
          emit_error("dc_worker: malformed ASSIGN");
          continue;
        }
        emit("DC_WORKER_ASSIGNED attempt=" + std::to_string(assignment.attempt.value()) +
             " unit=" + assignment.logical_name + " kind=" + std::string(to_string(assignment.kind)) +
             " compilation=" + std::to_string(assignment.compilation.value()));
        std::fflush(stdout);
        record_claim(assignment);
        (void)start_compile(assignment);
        continue;
      }
      if (frame.op == Op::CancelAttempt) {
        ControlMessage control;
        if (!decode_control(std::span<const std::byte>(frame.payload.data(), frame.payload.size()), control)) {
          continue;
        }
        std::shared_ptr<ActiveCompile> slot;
        {
          std::lock_guard<std::mutex> guard(active_mutex);
          auto found = active.find(control.attempt.value());
          if (found != active.end()) slot = found->second;
        }
        if (slot) {
          slot->cancel.store(true);
          emit("DC_WORKER_CANCEL attempt=" + std::to_string(control.attempt.value()) +
               " reason=" + control.reason);
          std::fflush(stdout);
        }
        continue;
      }
      if (frame.op == Op::CommitArtifact) {
        CommitMessage message;
        if (!decode_commit_message(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                                   message)) {
          continue;
        }
        emit("DC_WORKER_ARTIFACT_AUTHORITATIVE compilation=" +
             std::to_string(message.control.compilation.value()) + " digest=" +
             message.control.artifact_digest.hex().substr(0, 16));
        std::fflush(stdout);
        continue;
      }
      if (frame.op == Op::ValidateOutput) {
        ValidateMessage message;
        if (!decode_validate(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                             message)) {
          continue;
        }
        // Re-run discovery so the answer reflects what is on disk right now,
        // not what was advertised when the worker first connected.
        const DiscoveryResult fresh = discover_toolchains(discovery);
        WorkerCapabilities refreshed = capabilities;
        refreshed.toolchains = fresh.toolchains;
        refreshed.targets = fresh.targets;
        canonicalize(refreshed);
        ValidateResponseMessage response;
        response.mode = message.mode;
        response.evidence = refreshed.evidence;
        response.capabilities_digest = refreshed.digest;
        response.subject = message.subject;
        response.detail = refreshed.digest == capabilities.digest ? "capabilities unchanged"
                                                                  : "capabilities changed since registration";
        std::vector<std::byte> payload;
        if (encode_validate_response(response, payload)) {
          (void)send_frame(Op::ValidateResponse, 0, payload);
        }
        continue;
      }
      if (frame.op == Op::Shutdown) {
        emit("DC_WORKER_SHUTDOWN");
        std::fflush(stdout);
        running = false;
        break;
      }
    }
  }

  stopping.store(true);
  {
    std::lock_guard<std::mutex> guard(active_mutex);
    for (auto& kv : active) {
      if (kv.second) kv.second->cancel.store(true);
    }
  }
  if (heartbeat.joinable()) heartbeat.join();
  // Drain in-flight compiles. Cancellation makes this bounded: each compile
  // terminates its child tree and returns.
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    for (;;) {
      {
        std::lock_guard<std::mutex> guard(active_mutex);
        if (active.empty()) break;
      }
      if (std::chrono::steady_clock::now() > deadline) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }

  socket.close();
  (void)remove_tree_quiet(scratch);
  shutdown_network();
  emit("DC_WORKER_STOP");
  std::fflush(stdout);
  return 0;
}
