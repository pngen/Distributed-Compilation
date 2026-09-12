// Distributed Compilation - framed TCP transport implementation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/net.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace dc {
namespace {

#ifdef _WIN32
using native_socket = SOCKET;
constexpr native_socket kInvalidSocket = INVALID_SOCKET;
std::atomic<int> g_network_users{0};

int last_socket_error() { return WSAGetLastError(); }

Status socket_error_status(const char* what) {
  return Status::error(ErrorCode::TransportFailure,
                       std::string(what) + " failed with error " + std::to_string(last_socket_error()));
}

bool would_block(int error) { return error == WSAEWOULDBLOCK; }
#else
using native_socket = int;
constexpr native_socket kInvalidSocket = -1;
std::atomic<int> g_network_users{0};

int last_socket_error() { return errno; }

Status socket_error_status(const char* what) {
  return Status::error(ErrorCode::TransportFailure,
                       std::string(what) + " failed: " + std::strerror(last_socket_error()));
}

bool would_block(int error) { return error == EAGAIN || error == EWOULDBLOCK; }
#endif

constexpr std::uint32_t kWireMagic = 0x31435044u;   // "DPC1"
constexpr std::size_t kFrameHeaderBytes = 28;

void put_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFFu));
}

std::uint32_t get_u32(const std::byte* p) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[i])) << (i * 8);
  }
  return value;
}

}  // namespace

Status initialize_network() {
#ifdef _WIN32
  if (g_network_users.fetch_add(1) == 0) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      g_network_users.fetch_sub(1);
      return Status::error(ErrorCode::TransportFailure, "WSAStartup failed");
    }
  }
#else
  g_network_users.fetch_add(1);
#endif
  return Status::success();
}

void shutdown_network() {
#ifdef _WIN32
  if (g_network_users.fetch_sub(1) == 1) {
    WSACleanup();
  }
#else
  g_network_users.fetch_sub(1);
#endif
}

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------
Socket::Socket() : handle_(static_cast<std::intptr_t>(kInvalidSocket)) {}

Socket::Socket(std::intptr_t handle) : handle_(handle) {}

Socket::~Socket() { (void)close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) {
  other.handle_ = static_cast<std::intptr_t>(kInvalidSocket);
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    (void)close();
    handle_ = other.handle_;
    other.handle_ = static_cast<std::intptr_t>(kInvalidSocket);
  }
  return *this;
}

bool Socket::valid() const noexcept { return handle_ != static_cast<std::intptr_t>(kInvalidSocket) && handle_ >= 0; }

std::intptr_t Socket::native() const { return handle_; }

Status Socket::close() {
  if (!valid()) return Status::success();
  const native_socket handle = static_cast<native_socket>(handle_);
  handle_ = static_cast<std::intptr_t>(kInvalidSocket);
#ifdef _WIN32
  if (closesocket(handle) != 0) return socket_error_status("closesocket");
#else
  if (::close(handle) != 0) return socket_error_status("close");
#endif
  return Status::success();
}

Status Socket::set_nonblocking(bool enabled) {
  if (!valid()) return Status::error(ErrorCode::InvalidArgument, "socket is not open");
#ifdef _WIN32
  u_long mode = enabled ? 1u : 0u;
  if (ioctlsocket(static_cast<native_socket>(handle_), FIONBIO, &mode) != 0) {
    return socket_error_status("ioctlsocket");
  }
#else
  const int flags = fcntl(static_cast<native_socket>(handle_), F_GETFL, 0);
  if (flags < 0) return socket_error_status("fcntl(F_GETFL)");
  const int updated = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
  if (fcntl(static_cast<native_socket>(handle_), F_SETFL, updated) < 0) {
    return socket_error_status("fcntl(F_SETFL)");
  }
#endif
  return Status::success();
}

Status Socket::set_nodelay(bool enabled) {
  if (!valid()) return Status::error(ErrorCode::InvalidArgument, "socket is not open");
  const int value = enabled ? 1 : 0;
  if (setsockopt(static_cast<native_socket>(handle_), IPPROTO_TCP, TCP_NODELAY,
                 reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return socket_error_status("setsockopt(TCP_NODELAY)");
  }
  return Status::success();
}

Result<Socket> Socket::connect(const std::string& host, std::uint16_t port, std::uint32_t timeout_millis) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  if (getaddrinfo(host.c_str(), service.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Result<Socket>(Status::error(ErrorCode::TransportFailure, "cannot resolve " + host));
  }

  Socket socket;
  Status last_status = Status::error(ErrorCode::TransportFailure, "no address succeeded");
  for (addrinfo* entry = results; entry != nullptr; entry = entry->ai_next) {
    const native_socket handle = ::socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
    if (handle == kInvalidSocket) continue;
    socket.close();
    socket = Socket(static_cast<std::intptr_t>(handle));
    (void)socket.set_nonblocking(true);
    const int rc = ::connect(handle, entry->ai_addr, static_cast<int>(entry->ai_addrlen));
    if (rc == 0) {
      last_status = Status::success();
      break;
    }
    const int error = last_socket_error();
    if (!would_block(error)
#ifdef _WIN32
        && error != WSAEINPROGRESS
#else
        && error != EINPROGRESS
#endif
    ) {
      last_status = socket_error_status("connect");
      socket.close();
      continue;
    }
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(handle, &write_set);
    timeval timeout{};
    timeout.tv_sec = static_cast<long>(timeout_millis / 1000);
    timeout.tv_usec = static_cast<long>((timeout_millis % 1000) * 1000);
    const int selected = ::select(static_cast<int>(handle + 1), nullptr, &write_set, nullptr, &timeout);
    if (selected <= 0) {
      last_status = Status::error(ErrorCode::Timeout, "connect timed out");
      socket.close();
      continue;
    }
    int socket_error = 0;
#ifdef _WIN32
    int length = sizeof(socket_error);
#else
    socklen_t length = sizeof(socket_error);
#endif
    if (getsockopt(handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error), &length) != 0 ||
        socket_error != 0) {
      last_status = Status::error(ErrorCode::TransportFailure, "connect failed");
      socket.close();
      continue;
    }
    last_status = Status::success();
    break;
  }
  freeaddrinfo(results);
  if (!last_status.ok()) return Result<Socket>(last_status);
  (void)socket.set_nonblocking(false);
  (void)socket.set_nodelay(true);
  return Result<Socket>(std::move(socket));
}

Status Socket::send_all(std::span<const std::byte> bytes) {
  if (!valid()) return Status::error(ErrorCode::InvalidArgument, "socket is not open");
  std::size_t sent = 0;
  while (sent < bytes.size()) {
    const int chunk = static_cast<int>(std::min<std::size_t>(bytes.size() - sent, 1u << 20));
    const int rc = ::send(static_cast<native_socket>(handle_),
                          reinterpret_cast<const char*>(bytes.data() + sent), chunk, 0);
    if (rc <= 0) {
      const int error = last_socket_error();
      if (would_block(error)) continue;
      return socket_error_status("send");
    }
    sent += static_cast<std::size_t>(rc);
  }
  return Status::success();
}

Socket::SendResult Socket::send_some(std::span<const std::byte> bytes) {
  SendResult result;
  if (!valid()) {
    result.status = Status::error(ErrorCode::InvalidArgument, "socket is not open");
    return result;
  }
  if (bytes.empty()) return result;
  const int chunk = static_cast<int>(std::min<std::size_t>(bytes.size(), 1u << 20));
  const int rc = ::send(static_cast<native_socket>(handle_), reinterpret_cast<const char*>(bytes.data()), chunk, 0);
  if (rc > 0) {
    result.bytes = static_cast<std::size_t>(rc);
    return result;
  }
  if (rc == 0) {
    result.status = Status::error(ErrorCode::ConnectionClosed, "send returned zero");
    return result;
  }
  const int error = last_socket_error();
  if (would_block(error)) {
    result.would_block = true;
    return result;
  }
  result.status = socket_error_status("send");
  return result;
}

Socket::RecvResult Socket::recv_some(std::span<std::byte> buffer) {
  RecvResult result;
  if (!valid()) {
    result.outcome = RecvOutcome::Failed;
    result.status = Status::error(ErrorCode::InvalidArgument, "socket is not open");
    return result;
  }
  if (buffer.empty()) {
    result.outcome = RecvOutcome::WouldBlock;
    return result;
  }
  const int chunk = static_cast<int>(std::min<std::size_t>(buffer.size(), 1u << 20));
  const int rc = ::recv(static_cast<native_socket>(handle_), reinterpret_cast<char*>(buffer.data()), chunk, 0);
  if (rc > 0) {
    result.outcome = RecvOutcome::Data;
    result.bytes = static_cast<std::size_t>(rc);
    return result;
  }
  if (rc == 0) {
    result.outcome = RecvOutcome::Closed;
    return result;
  }
  const int error = last_socket_error();
  if (would_block(error)) {
    result.outcome = RecvOutcome::WouldBlock;
    return result;
  }
  result.outcome = RecvOutcome::Failed;
  result.status = socket_error_status("recv");
  return result;
}

std::string Socket::peer() const {
  if (!valid()) return {};
  sockaddr_storage storage{};
#ifdef _WIN32
  int length = sizeof(storage);
#else
  socklen_t length = sizeof(storage);
#endif
  if (getpeername(static_cast<native_socket>(handle_), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return {};
  }
  char host[64] = {0};
  char service[16] = {0};
  if (getnameinfo(reinterpret_cast<sockaddr*>(&storage), length, host, sizeof(host), service, sizeof(service),
                  NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return {};
  }
  return std::string(host) + ":" + service;
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------
Listener::Listener() = default;

Listener::~Listener() { (void)close(); }

Listener::Listener(Listener&& other) noexcept : handle_(other.handle_), port_(other.port_) {
  other.handle_ = -1;
  other.port_ = 0;
}

Listener& Listener::operator=(Listener&& other) noexcept {
  if (this != &other) {
    (void)close();
    handle_ = other.handle_;
    port_ = other.port_;
    other.handle_ = -1;
    other.port_ = 0;
  }
  return *this;
}

Result<Listener> Listener::bind(const std::string& address, std::uint16_t port, int backlog) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  const char* node = address.empty() ? nullptr : address.c_str();
  if (getaddrinfo(node, service.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Result<Listener>(Status::error(ErrorCode::TransportFailure, "cannot resolve bind address"));
  }
  const native_socket handle = ::socket(results->ai_family, results->ai_socktype, results->ai_protocol);
  if (handle == kInvalidSocket) {
    freeaddrinfo(results);
    return Result<Listener>(socket_error_status("socket"));
  }
  const int reuse = 1;
  (void)setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
  if (::bind(handle, results->ai_addr, static_cast<int>(results->ai_addrlen)) != 0) {
    const Status status = socket_error_status("bind");
    freeaddrinfo(results);
#ifdef _WIN32
    closesocket(handle);
#else
    ::close(handle);
#endif
    return Result<Listener>(status);
  }
  freeaddrinfo(results);
  if (::listen(handle, backlog) != 0) {
    const Status status = socket_error_status("listen");
#ifdef _WIN32
    closesocket(handle);
#else
    ::close(handle);
#endif
    return Result<Listener>(status);
  }

  sockaddr_storage storage{};
#ifdef _WIN32
  int length = sizeof(storage);
#else
  socklen_t length = sizeof(storage);
#endif
  std::uint16_t bound_port = port;
  if (getsockname(handle, reinterpret_cast<sockaddr*>(&storage), &length) == 0) {
    if (storage.ss_family == AF_INET) {
      bound_port = ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port);
    }
  }
  Listener listener;
  listener.handle_ = static_cast<std::intptr_t>(handle);
  listener.port_ = bound_port;
  return Result<Listener>(std::move(listener));
}

Result<Socket> Listener::accept() {
  if (handle_ < 0) return Result<Socket>(Status::error(ErrorCode::InvalidArgument, "listener is not open"));
  const native_socket client = ::accept(static_cast<native_socket>(handle_), nullptr, nullptr);
  if (client == kInvalidSocket) return Result<Socket>(socket_error_status("accept"));
  Socket socket(static_cast<std::intptr_t>(client));
  (void)socket.set_nodelay(true);
  return Result<Socket>(std::move(socket));
}

Status Listener::close() {
  if (handle_ < 0) return Status::success();
  const native_socket handle = static_cast<native_socket>(handle_);
  handle_ = -1;
#ifdef _WIN32
  if (closesocket(handle) != 0) return socket_error_status("closesocket");
#else
  if (::close(handle) != 0) return socket_error_status("close");
#endif
  return Status::success();
}

// ---------------------------------------------------------------------------
// FrameReader
// ---------------------------------------------------------------------------
FrameReader::FrameReader(std::size_t max_frame_bytes) : max_frame_bytes_(max_frame_bytes) {}

void FrameReader::clear() { buffer_.clear(); }

Status FrameReader::feed(std::span<const std::byte> bytes, std::vector<std::vector<std::byte>>& out_frames) {
  buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
  for (;;) {
    if (buffer_.size() < kFrameHeaderBytes) return Status::success();
    const std::byte* header = buffer_.data();
    const std::uint32_t total_length = get_u32(header);
    if (get_u32(header + 4) != kWireMagic) {
      buffer_.clear();
      return Status::error(ErrorCode::ProtocolViolation, "frame magic mismatch");
    }
    if (total_length < kFrameHeaderBytes - 4 || total_length > max_frame_bytes_) {
      buffer_.clear();
      return Status::error(ErrorCode::FrameTooLarge, "frame length out of bounds");
    }
    const std::size_t frame_bytes = static_cast<std::size_t>(total_length) + 4;
    if (buffer_.size() < frame_bytes) return Status::success();
    out_frames.emplace_back(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(frame_bytes));
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(frame_bytes));
    ++frames_;
  }
}

}  // namespace dc
