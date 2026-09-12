// Distributed Compilation - dc_coordinator: the distributed compilation control plane.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifdef _WIN32
#define FD_SETSIZE 1024
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <algorithm>
#include <atomic>
#include <csignal>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "app_common.hpp"
#include "dc/coordinator.hpp"
#include "dc/net.hpp"
#include "dc/persistence.hpp"
#include "dc/wire.hpp"

namespace {

std::atomic<bool> g_stop{false};

// Per-connection outbound backlog bound. Requests and artifact transfers are
// both framed, and a worker that stops reading must not be able to pin memory.
constexpr std::size_t kMaxOutboundBytes = 64u * 1024u * 1024u;

void handle_signal(int) { g_stop.store(true); }

struct Connection {
  dc::Socket socket;
  dc::FrameReader reader{dc::kMaxFrameBytes};
  std::vector<std::byte> outgoing;
  std::size_t outgoing_sent = 0;
  dc::SessionId session;
  dc::SessionRole role = dc::SessionRole::Client;
  bool handshaked = false;
  bool closing = false;
  std::string peer;
};

std::string usage() {
  return "usage: dc_coordinator --state <dir> [--listen 127.0.0.1:0] [--snapshot-every N]\n"
         "                      [--no-fsync] [--no-persistence] [--max-artifact-bytes N]\n"
         "                      [--idle-exit-millis N] [--verbose]";
}

}  // namespace

int main(int argc, char** argv) {
  using namespace dc;
  using namespace dc::app;

  Arguments arguments = Arguments::parse(argc, argv, 1);
  if (arguments.has("help")) {
    emit(usage());
    return 0;
  }

  service_log_path() = arguments.get("log");
  const std::string state_dir = arguments.get("state");
  if (state_dir.empty()) {
    emit_error("dc_coordinator: --state <dir> is required");
    emit_error(usage());
    return 2;
  }

  CoordinatorConfig config;
  config.state_root = state_dir;
  config.host_name = arguments.get("host-name", "local");
  config.enable_persistence = !arguments.has("no-persistence");
  config.fsync_records = !arguments.has("no-fsync");
  if (arguments.has("snapshot-every")) {
    config.snapshot_every_records = static_cast<std::uint64_t>(arguments.get_int("snapshot-every", 16384));
  }
  if (arguments.has("max-artifact-bytes")) {
    config.max_artifact_bytes = static_cast<std::uint64_t>(arguments.get_int("max-artifact-bytes", 134217728));
    config.max_blob_bytes = config.max_artifact_bytes;
  }
  if (arguments.has("max-attempts")) {
    config.max_attempts_hard_cap = static_cast<std::uint32_t>(arguments.get_int("max-attempts", 16));
  }

  Coordinator coordinator;
  Status opened = coordinator.open(config);
  if (!opened.ok()) {
    emit_error("dc_coordinator: cannot open state: " + opened.describe());
    return 3;
  }

  Status network = initialize_network();
  if (!network.ok()) {
    emit_error("dc_coordinator: " + network.describe());
    coordinator.close();
    return 4;
  }

  std::string address = "127.0.0.1";
  std::uint16_t port = 0;
  const std::string listen = arguments.get("listen");
  if (!listen.empty() && !parse_endpoint(listen, address, port)) {
    emit_error("dc_coordinator: --listen must be host:port");
    shutdown_network();
    coordinator.close();
    return 2;
  }

  auto listener_result = Listener::bind(address, port, 64);
  if (!listener_result.ok()) {
    emit_error("dc_coordinator: cannot bind: " + listener_result.status().describe());
    shutdown_network();
    coordinator.close();
    return 5;
  }
  Listener listener = std::move(listener_result.value());
  Listener& listener_ref = listener;
  const std::string ready_line =
      "DC_COORDINATOR_READY host=" + address + " port=" + std::to_string(listener_ref.port()) +
      " epoch=" + std::to_string(coordinator.epoch().value()) +
      " state=" + std::filesystem::absolute(config.state_root).string();
  emit(ready_line);
  std::fflush(stdout);
  {
    const std::string ready_file = arguments.get("ready-file");
    if (!ready_file.empty()) {
      const std::string text = ready_line + "\n";
      Status written = write_file_atomic(
          ready_file,
          std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()), false);
      if (!written.ok()) emit_error("dc_coordinator: cannot write the readiness file: " + written.describe());
    }
  }

  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);

  std::vector<std::unique_ptr<Connection>> connections;
  const std::uint64_t idle_exit_millis = static_cast<std::uint64_t>(arguments.get_int("idle-exit-millis", 0));
  const bool verbose = arguments.has("verbose");
  std::uint64_t idle_since = 0;
  const auto now_millis = []() {
    return static_cast<std::uint64_t>(SystemClock().now());
  };

  const auto queue_frame = [](Connection& connection, Op op, std::uint64_t request_id,
                              const std::vector<std::byte>& payload) {
    Frame frame;
    frame.op = op;
    frame.request_id = request_id;
    frame.payload = payload;
    std::vector<std::byte> encoded;
    if (!encode_frame(frame, encoded).ok()) return;
    connection.outgoing.insert(connection.outgoing.end(), encoded.begin(), encoded.end());
  };

  const auto send_response = [&queue_frame](Connection& connection, std::uint64_t request_id, Op op,
                                            const Status& status, const std::vector<std::byte>& payload) {
    ResponseMessage response;
    response.op = op;
    response.code = status.code();
    response.detail = status.detail();
    response.payload = payload;
    std::vector<std::byte> encoded;
    if (!encode_response(response, encoded).ok()) return;
    queue_frame(connection, Op::Response, request_id, encoded);
  };

  bool running = true;
  while (running) {
    fd_set read_set;
    fd_set write_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    const SOCKET listen_native = static_cast<SOCKET>(listener_ref.native());
    FD_SET(listen_native, &read_set);
    SOCKET max_handle = listen_native;
    for (auto& connection : connections) {
      if (!connection->socket.valid()) continue;
      const SOCKET native = static_cast<SOCKET>(connection->socket.native());
      if (!connection->closing) FD_SET(native, &read_set);
      if (connection->outgoing_sent < connection->outgoing.size()) FD_SET(native, &write_set);
      if (native > max_handle) max_handle = native;
    }
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    const int selected = ::select(static_cast<int>(max_handle + 1), &read_set, &write_set, nullptr, &timeout);
    if (selected < 0) {
      if (g_stop.load()) break;
      continue;
    }

    if (FD_ISSET(listen_native, &read_set)) {
      auto accepted = listener_ref.accept();
      if (accepted.ok()) {
        auto connection = std::make_unique<Connection>();
        connection->socket = std::move(accepted.value());
        connection->peer = connection->socket.peer();
        (void)connection->socket.set_nonblocking(true);
        connections.push_back(std::move(connection));
      }
    }

    for (auto& connection : connections) {
      if (connection->socket.valid() && FD_ISSET(static_cast<SOCKET>(connection->socket.native()), &write_set)) {
        const std::span<const std::byte> pending(connection->outgoing.data() + connection->outgoing_sent,
                                                connection->outgoing.size() - connection->outgoing_sent);
        // One non-blocking attempt per select pass. A blocking or spinning send
        // here would stop the coordinator from accepting new sessions.
        const Socket::SendResult sent = connection->socket.send_some(pending);
        if (!sent.status.ok()) {
          connection->closing = true;
        } else {
          connection->outgoing_sent += sent.bytes;
        }
        if (connection->outgoing_sent >= connection->outgoing.size()) {
          connection->outgoing.clear();
          connection->outgoing_sent = 0;
        } else if (connection->outgoing.size() > kMaxOutboundBytes) {
          // Backpressure: a peer that cannot drain a bounded backlog is
          // disconnected rather than allowed to exhaust coordinator memory.
          connection->closing = true;
        }
      }
      if (!connection->socket.valid() || connection->closing) continue;
      if (!FD_ISSET(static_cast<SOCKET>(connection->socket.native()), &read_set)) continue;

      std::byte buffer[64 * 1024];
      auto received = connection->socket.recv_some(std::span<std::byte>(buffer, sizeof(buffer)));
      if (received.outcome == Socket::RecvOutcome::Closed ||
          received.outcome == Socket::RecvOutcome::Failed) {
        connection->closing = true;
        continue;
      }
      if (received.outcome != Socket::RecvOutcome::Data) continue;

      std::vector<std::vector<std::byte>> frames;
      Status fed = connection->reader.feed(std::span<const std::byte>(buffer, received.bytes), frames);
      if (!fed.ok()) {
        if (verbose) emit_error("dc_coordinator: protocol violation from " + connection->peer + ": " + fed.describe());
        connection->closing = true;
        continue;
      }

      for (const auto& raw : frames) {
        Frame frame;
        Status decoded = decode_frame(std::span<const std::byte>(raw.data(), raw.size()), frame);
        if (!decoded.ok()) {
          send_response(*connection, 0, Op::Error, decoded, {});
          continue;
        }
        if (verbose) {
          emit("dc_coordinator: <- " + std::string(to_string(frame.op)) + " from " + connection->peer);
        }

        auto payload_out = std::make_shared<std::vector<std::byte>>();
        Status status = Status::success();
        bool shutdown_after_reply = false;

        switch (frame.op) {
          case Op::Hello: {
            HelloMessage hello;
            if (!decode_hello(std::span<const std::byte>(frame.payload.data(), frame.payload.size()), hello)) {
              status = Status::error(ErrorCode::Malformed, "malformed HELLO");
              break;
            }
            connection->role = hello.role;
            connection->handshaked = true;
            break;
          }
          case Op::RegisterWorker: {
            RegisterWorkerMessage message;
            if (!decode_register_worker(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                                        message)) {
              status = Status::error(ErrorCode::Malformed, "malformed REGISTER_WORKER");
              break;
            }
            WorkerRegistration registration;
            registration.endpoint = message.endpoint;
            registration.host = message.host;
            registration.worker_id = message.worker_id;
            registration.boot_id = message.boot_id;
            registration.capabilities = message.capabilities;
            registration.max_inflight = message.max_inflight;
            auto registered = coordinator.register_worker(registration);
            if (!registered.ok()) {
              status = registered.status();
              break;
            }
            connection->session = registered.value().session;
            ReadyMessage ready;
            ready.session = registered.value().session;
            ready.worker = registered.value().worker;
            ready.boot = registered.value().boot;
            ready.generation = registered.value().generation;
            ready.epoch = registered.value().epoch;
            ready.detail = registered.value().detail;
            encode_ready(ready, *payload_out);
            break;
          }
          case Op::AdvertiseToolchain: {
            if (connection->session.is_zero()) {
              status = Status::error(ErrorCode::Unauthorized, "ADVERTISE_TOOLCHAIN before registration");
              break;
            }
            WorkerCapabilities capabilities;
            CanonicalReader capabilities_reader(
                std::span<const std::byte>(frame.payload.data(), frame.payload.size()));
            if (!decode_capabilities(capabilities_reader, capabilities)) {
              status = Status::error(ErrorCode::Malformed, "malformed capabilities");
              break;
            }
            status = coordinator.advertise_capabilities(connection->session, capabilities);
            break;
          }
          case Op::WorkerReady: {
            if (connection->session.is_zero()) {
              status = Status::error(ErrorCode::Unauthorized, "WORKER_READY before registration");
              break;
            }
            status = coordinator.mark_ready(connection->session);
            break;
          }
          case Op::Heartbeat: {
            if (!connection->session.is_zero()) (void)coordinator.heartbeat(connection->session);
            break;
          }
          case Op::BeginCompile: {
            AuthorityClaim claim;
            if (!decode_authority_claim(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                                        claim)) {
              status = Status::error(ErrorCode::Malformed, "malformed BEGIN_COMPILE");
              break;
            }
            status = coordinator.begin_compile(claim);
            break;
          }
          case Op::ReportOutput: {
            ReportOutput output;
            if (!decode_report_output(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                                      output)) {
              status = Status::error(ErrorCode::Malformed, "malformed REPORT_OUTPUT");
              break;
            }
            auto decision = coordinator.report_output(connection->session, output);
            if (!decision.ok()) {
              status = decision.status();
              break;
            }
            CommitResponse response;
            response.outcome = decision.value().outcome;
            response.error = decision.value().error;
            response.detail = decision.value().detail;
            response.commit = decision.value().commit;
            response.validation = decision.value().validation;
            response.artifact_authoritative = decision.value().artifact_authoritative;
            if (response.commit.id.is_zero()) response.commit.id = ArtifactCommitId(1);
            encode_commit_response(response, *payload_out);
            break;
          }
          case Op::FailAttempt: {
            AttemptFailure failure;
            if (!decode_fail_attempt(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                                     failure)) {
              status = Status::error(ErrorCode::Malformed, "malformed FAIL_ATTEMPT");
              break;
            }
            status = coordinator.fail_attempt(connection->session, failure);
            break;
          }
          case Op::ValidateResponse: {
            ValidateResponseMessage message;
            if (!decode_validate_response(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                                          message)) {
              status = Status::error(ErrorCode::Malformed, "malformed VALIDATE_RESPONSE");
              break;
            }
            status = coordinator.handle_validate_response(connection->session, message.mode, message.evidence,
                                                          message.capabilities_digest, message.detail);
            break;
          }
          case Op::SubmitCompilation: {
            SubmitMessage message;
            if (!decode_submit(std::span<const std::byte>(frame.payload.data(), frame.payload.size()), message)) {
              status = Status::error(ErrorCode::Malformed, "malformed SUBMIT_COMPILATION");
              break;
            }
            if (message.request.units.size() > coordinator.config().max_units) {
              status = Status::error(ErrorCode::LimitExceeded, "unit count exceeds the configured bound");
              break;
            }
            SubmissionBundle bundle;
            bundle.request = message.request;
            bundle.blobs = std::move(message.blobs);
            bundle.dry_run = message.dry_run;
            bundle.force_rebuild = message.force_rebuild;
            auto submitted = coordinator.submit(bundle);
            if (!submitted.ok()) {
              status = submitted.status();
              break;
            }
            SubmissionResponse response;
            response.request_id = submitted.value().request_id;
            response.request_identity = submitted.value().request_identity;
            response.units = submitted.value().units;
            response.all_committed = submitted.value().all_committed;
            response.served_from_cache = submitted.value().served_from_cache;
            response.duplicate_request = submitted.value().duplicate_request;
            encode_submission_response(response, *payload_out);
            break;
          }
          case Op::CacheQuery: {
            CacheQueryMessage message;
            if (!decode_cache_query(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                                    message)) {
              status = Status::error(ErrorCode::Malformed, "malformed CACHE_QUERY");
              break;
            }
            auto decision = coordinator.cache_query(message.unit_identity);
            if (!decision.ok()) {
              status = decision.status();
              break;
            }
            CacheReportMessage report;
            report.decision = decision.value();
            auto entry = coordinator.cache_entry(decision.value().entry);
            if (entry.ok()) report.entry = entry.value();
            std::vector<std::byte> inner;
            encode_cache_report(report, inner);
            Connection* target = connection.get();
            queue_frame(*target, Op::CacheReport, frame.request_id, inner);
            continue;
          }
          case Op::Audit: {
            const AuditReport report = coordinator.audit();
            const std::string text = report.render();
            payload_out->assign(reinterpret_cast<const std::byte*>(text.data()),
                                reinterpret_cast<const std::byte*>(text.data()) + text.size());
            if (!report.clean) status = Status::error(ErrorCode::ValidationFailure, "audit findings present");
            break;
          }
          case Op::Snapshot: {
            status = coordinator.snapshot();
            break;
          }
          case Op::CancelAttempt: {
            ControlMessage control;
            if (!decode_control(std::span<const std::byte>(frame.payload.data(), frame.payload.size()),
                                control)) {
              status = Status::error(ErrorCode::Malformed, "malformed CANCEL_ATTEMPT");
              break;
            }
            status = coordinator.cancel(control.compilation, control.reason);
            break;
          }
          case Op::Shutdown: {
            (void)coordinator.shutdown_sessions();
            shutdown_after_reply = true;
            break;
          }
          case Op::Query: {
            QueryMessage message;
            if (!decode_query(std::span<const std::byte>(frame.payload.data(), frame.payload.size()), message)) {
              status = Status::error(ErrorCode::Malformed, "malformed QUERY");
              break;
            }
            std::string text;
            switch (message.kind) {
              case 0: {
                auto record = coordinator.compilation(CompilationId(message.id));
                if (!record.ok()) {
                  status = record.status();
                  break;
                }
                text = render_compilation(record.value());
                break;
              }
              case 1: {
                auto record = coordinator.attempt(CompilationAttemptId(message.id));
                if (!record.ok()) {
                  status = record.status();
                  break;
                }
                text = render_attempt(record.value());
                break;
              }
              case 2: {
                text = coordinator.audit().render();
                break;
              }
              case 3: {
                for (const auto& worker : coordinator.workers()) text += render_worker(worker);
                break;
              }
              case 4: {
                auto decision = coordinator.cache_query(message.identity);
                if (!decision.ok()) {
                  status = decision.status();
                  break;
                }
                text = render_cache_decision(decision.value());
                break;
              }
              case 5: {
                auto record = coordinator.job(message.identity);
                if (!record.ok()) {
                  status = record.status();
                  break;
                }
                text = "job " + record.value().request_identity.hex() + " units " +
                       std::to_string(record.value().units.size()) + " committed " +
                       (record.value().committed ? "yes" : "no") + "\n";
                break;
              }
              case 6: {
                for (const auto& provenance : coordinator.provenances()) {
                  text += render_provenance(provenance);
                }
                break;
              }
              case 7: {
                for (const auto& commit : coordinator.commits()) text += render_commit(commit);
                break;
              }
              case 9: {
                // Full explainability: cache decision, attempts, validation
                // evidence, provenance and reproducibility state for one
                // compilation, in a deterministic order.
                text = coordinator.explain(CompilationId(message.id)).render();
                break;
              }
              case 8: {
                auto record = coordinator.artifact_bytes(CompilationId(message.id));
                if (!record.ok()) {
                  status = record.status();
                  break;
                }
                payload_out->assign(record.value().begin(), record.value().end());
                break;
              }
              default:
                status = Status::error(ErrorCode::Unsupported, "unsupported query kind");
                break;
            }
            if (status.ok() && message.kind != 8) {  // 8 returns raw artifact bytes
              payload_out->assign(reinterpret_cast<const std::byte*>(text.data()),
                                  reinterpret_cast<const std::byte*>(text.data()) + text.size());
            }
            break;
          }
          case Op::Assign:
          case Op::CommitArtifact:
          case Op::ValidateOutput:
          case Op::CacheReport:
          case Op::Response:
          case Op::Error:
          case Op::Invalid:
          default:
            status = Status::error(ErrorCode::ProtocolViolation,
                                   "op " + std::string(to_string(frame.op)) + " is not accepted by the coordinator");
            break;
        }

        send_response(*connection, frame.request_id, frame.op, status, *payload_out);
        if (shutdown_after_reply) {
          running = false;
          break;
        }
      }
    }

    // Schedule work and deliver assignments and control messages.
    const std::vector<Assignment> assignments = coordinator.pump();
    for (const auto& assignment : assignments) {
      for (auto& connection : connections) {
        if (connection->session != assignment.session) continue;
        std::vector<std::byte> payload;
        if (encode_assignment(assignment, payload).ok()) {
          queue_frame(*connection, Op::Assign, 0, payload);
        }
        break;
      }
    }
    for (const auto& control : coordinator.drain_controls()) {
      std::vector<std::byte> payload;
      Op op = Op::CancelAttempt;
      if (control.kind == ControlKind::Shutdown) {
        op = Op::Shutdown;
        if (!encode_control(control, payload).ok()) continue;
      } else if (control.kind == ControlKind::CommitNotification) {
        op = Op::CommitArtifact;
        CommitMessage message;
        message.control = control;
        auto commit = coordinator.commit(control.compilation);
        if (commit.ok()) message.commit = commit.value();
        if (!encode_commit_message(message, payload).ok()) continue;
      } else {
        if (!encode_control(control, payload).ok()) continue;
      }
      for (auto& connection : connections) {
        if (connection->session != control.session) continue;
        queue_frame(*connection, op, 0, payload);
        break;
      }
    }

    // Reap closed connections.
    for (auto it = connections.begin(); it != connections.end();) {
      Connection& connection = **it;
      if (connection.closing || !connection.socket.valid()) {
        if (!connection.session.is_zero()) {
          (void)coordinator.disconnect_session(connection.session, "connection closed");
        }
        connection.socket.close();
        it = connections.erase(it);
        continue;
      }
      ++it;
    }

    if (g_stop.load()) running = false;
    if (idle_exit_millis > 0) {
      if (connections.empty()) {
        if (idle_since == 0) idle_since = now_millis();
        if (now_millis() - idle_since > idle_exit_millis) running = false;
      } else {
        idle_since = 0;
      }
    }
  }

  for (auto& connection : connections) {
    if (!connection->session.is_zero()) {
      (void)coordinator.disconnect_session(connection->session, "coordinator shutdown");
    }
    connection->socket.close();
  }
  connections.clear();
  (void)coordinator.snapshot();
  listener_ref.close();
  emit("DC_COORDINATOR_STOP epoch=" + std::to_string(coordinator.epoch().value()));
  std::fflush(stdout);
  coordinator.close();
  shutdown_network();
  return 0;
}
