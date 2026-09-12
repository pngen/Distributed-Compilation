// Distributed Compilation - CLI/worker client transport helper.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_APP_CLIENT_HPP
#define DC_APP_CLIENT_HPP

#include <atomic>
#include <string>
#include <vector>

#include "dc/net.hpp"
#include "dc/wire.hpp"

namespace dc {
namespace app {

class Client {
 public:
  Client() = default;
  ~Client() = default;

  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;
  Client(Client&&) noexcept = default;
  Client& operator=(Client&&) noexcept = default;

  static Result<Client> connect(const std::string& endpoint, SessionRole role, const std::string& name);

  bool valid() const { return socket_.valid(); }
  Status close();

  // Sends a request and waits for the matching RESPONSE frame. Frames that are
  // not responses (an unexpected ASSIGN, for example) are reported as a
  // protocol violation rather than being silently dropped.
  Result<ResponseMessage> call(Op op, const std::vector<std::byte>& payload);

  // Waits for a specific unsolicited op (used for CACHE_REPORT).
  Result<std::vector<std::byte>> await(Op expected, std::uint32_t timeout_millis);

  Socket& socket() { return socket_; }

 private:
  Result<Frame> read_frame(std::uint32_t timeout_millis);

  Socket socket_;
  FrameReader reader_{kMaxFrameBytes};
  std::uint64_t next_request_id_ = 1;
};

inline Result<Client> Client::connect(const std::string& endpoint, SessionRole role, const std::string& name) {
  std::string host;
  std::uint16_t port = 0;
  const std::size_t colon = endpoint.rfind(':');
  if (colon == std::string::npos) {
    return Result<Client>(Status::error(ErrorCode::InvalidArgument, "endpoint must be host:port"));
  }
  host = endpoint.substr(0, colon);
  try {
    port = static_cast<std::uint16_t>(std::stoi(endpoint.substr(colon + 1)));
  } catch (...) {
    return Result<Client>(Status::error(ErrorCode::InvalidArgument, "endpoint port is not numeric"));
  }
  Status network = initialize_network();
  if (!network.ok()) return Result<Client>(network);
  auto connected = Socket::connect(host, port, 10000);
  if (!connected.ok()) return Result<Client>(connected.status());
  Client client;
  client.socket_ = std::move(connected.value());
  client.socket_.set_nonblocking(false);

  HelloMessage hello;
  hello.role = role;
  hello.name = name;
  std::vector<std::byte> payload;
  encode_hello(hello, payload);
  Frame frame;
  frame.op = Op::Hello;
  frame.request_id = 1;
  frame.payload = payload;
  std::vector<std::byte> encoded;
  if (!encode_frame(frame, encoded).ok()) {
    return Result<Client>(Status::error(ErrorCode::Internal, "cannot encode hello"));
  }
  Status sent = client.socket_.send_all(std::span<const std::byte>(encoded.data(), encoded.size()));
  if (!sent.ok()) return Result<Client>(sent);
  auto response = client.read_frame(10000);
  if (!response.ok()) return Result<Client>(response.status());
  if (response.value().op == Op::Response) {
    ResponseMessage message;
    if (decode_response(std::span<const std::byte>(response.value().payload.data(),
                                                   response.value().payload.size()),
                        message) &&
        message.code != ErrorCode::Ok) {
      return Result<Client>(Status::error(message.code, message.detail));
    }
  }
  return Result<Client>(std::move(client));
}

inline Result<Frame> Client::read_frame(std::uint32_t timeout_millis) {
  const std::uint64_t deadline = static_cast<std::uint64_t>(SystemClock().now()) + timeout_millis;
  for (;;) {
    std::vector<std::vector<std::byte>> frames;
    std::vector<std::byte> pending;
    // Drain anything the reader already buffered before touching the socket.
    Status fed = reader_.feed({}, frames);
    if (!fed.ok()) return Result<Frame>(fed);
    if (!frames.empty()) {
      Frame frame;
      Status decoded = decode_frame(std::span<const std::byte>(frames.front().data(), frames.front().size()),
                                    frame);
      if (!decoded.ok()) return Result<Frame>(decoded);
      return Result<Frame>(std::move(frame));
    }
    if (static_cast<std::uint64_t>(SystemClock().now()) > deadline) {
      return Result<Frame>(Status::error(ErrorCode::Timeout, "no response from the coordinator"));
    }
    std::byte buffer[64 * 1024];
    auto received = socket_.recv_some(std::span<std::byte>(buffer, sizeof(buffer)));
    if (received.outcome == Socket::RecvOutcome::WouldBlock) {
      continue;
    }
    if (received.outcome == Socket::RecvOutcome::Closed) {
      return Result<Frame>(Status::error(ErrorCode::ConnectionClosed, "coordinator closed the connection"));
    }
    if (received.outcome == Socket::RecvOutcome::Failed) {
      return Result<Frame>(received.status);
    }
    Status status = reader_.feed(std::span<const std::byte>(buffer, received.bytes), frames);
    if (!status.ok()) return Result<Frame>(status);
    if (frames.empty()) continue;
    Frame frame;
    Status decoded = decode_frame(std::span<const std::byte>(frames.front().data(), frames.front().size()), frame);
    if (!decoded.ok()) return Result<Frame>(decoded);
    return Result<Frame>(std::move(frame));
  }
}

inline Result<ResponseMessage> Client::call(Op op, const std::vector<std::byte>& payload) {
  Frame frame;
  frame.op = op;
  frame.request_id = next_request_id_++;
  frame.payload = payload;
  std::vector<std::byte> encoded;
  Status status = encode_frame(frame, encoded);
  if (!status.ok()) return Result<ResponseMessage>(status);
  status = socket_.send_all(std::span<const std::byte>(encoded.data(), encoded.size()));
  if (!status.ok()) return Result<ResponseMessage>(status);

  for (;;) {
    auto received = read_frame(60000);
    if (!received.ok()) return Result<ResponseMessage>(received.status());
    Frame response = std::move(received.value());
    if (response.op == Op::CacheReport) {
      ResponseMessage wrapper;
      wrapper.op = Op::CacheReport;
      wrapper.payload = std::move(response.payload);
      return Result<ResponseMessage>(std::move(wrapper));
    }
    if (response.op != Op::Response && response.op != Op::Error) {
      return Result<ResponseMessage>(Status::error(
          ErrorCode::ProtocolViolation,
          "unexpected " + std::string(to_string(response.op)) + " while waiting for a response"));
    }
    ResponseMessage message;
    if (!decode_response(std::span<const std::byte>(response.payload.data(), response.payload.size()),
                         message)) {
      return Result<ResponseMessage>(Status::error(ErrorCode::Malformed, "malformed response frame"));
    }
    return Result<ResponseMessage>(std::move(message));
  }
}

inline Result<std::vector<std::byte>> Client::await(Op expected, std::uint32_t timeout_millis) {
  auto received = read_frame(timeout_millis);
  if (!received.ok()) return Result<std::vector<std::byte>>(received.status());
  if (received.value().op != expected) {
    return Result<std::vector<std::byte>>(
        Status::error(ErrorCode::ProtocolViolation,
                      "expected " + std::string(to_string(expected)) + " but received " +
                          std::string(to_string(received.value().op))));
  }
  return Result<std::vector<std::byte>>(std::move(received.value().payload));
}

inline Status Client::close() {
  Status status = socket_.close();
  shutdown_network();
  return status;
}

}  // namespace app
}  // namespace dc

#endif  // DC_APP_CLIENT_HPP
