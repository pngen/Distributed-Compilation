// Distributed Compilation - framed TCP transport.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_NET_HPP
#define DC_NET_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "dc/types.hpp"

namespace dc {

// Initialises the platform network stack. Idempotent.
Status initialize_network();
void shutdown_network();

class Socket {
 public:
  Socket();
  ~Socket();

  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  static Result<Socket> connect(const std::string& host, std::uint16_t port, std::uint32_t timeout_millis);

  bool valid() const noexcept;
  Status close();
  Status set_nonblocking(bool enabled);
  Status set_nodelay(bool enabled);

  Status send_all(std::span<const std::byte> bytes);

  struct SendResult {
    std::size_t bytes = 0;
    bool would_block = false;
    Status status;
  };

  // Single non-blocking send attempt. A reactor must use this rather than
  // send_all: send_all spins until the peer drains, which would wedge the
  // accept loop and stop the coordinator from serving anyone else.
  SendResult send_some(std::span<const std::byte> bytes);

  enum class RecvOutcome : std::uint8_t { Data = 0, WouldBlock = 1, Closed = 2, Failed = 3 };

  struct RecvResult {
    RecvOutcome outcome = RecvOutcome::WouldBlock;
    std::size_t bytes = 0;
    Status status;
  };

  // Distinguishes "would block" from "peer closed" explicitly: a reactor that
  // conflated the two would fence healthy workers on every idle poll.
  RecvResult recv_some(std::span<std::byte> buffer);

  std::string peer() const;
  std::intptr_t native() const;

 private:
  friend class Listener;
  explicit Socket(std::intptr_t handle);
  std::intptr_t handle_;
};

class Listener {
 public:
  Listener();
  ~Listener();

  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;
  Listener(Listener&& other) noexcept;
  Listener& operator=(Listener&& other) noexcept;

  static Result<Listener> bind(const std::string& address, std::uint16_t port, int backlog);
  Result<Socket> accept();
  Status close();
  std::uint16_t port() const noexcept { return port_; }
  std::intptr_t native() const noexcept { return handle_; }
  bool valid() const noexcept { return handle_ >= 0; }

 private:
  std::intptr_t handle_ = -1;
  std::uint16_t port_ = 0;
};

// A bounded, incremental frame reader. It never allocates more than the
// configured maximum frame size, and it distinguishes "need more bytes" from
// "the peer sent something malformed".
class FrameReader {
 public:
  explicit FrameReader(std::size_t max_frame_bytes);

  // Appends bytes and yields every complete frame. Returns a failure only for a
  // protocol violation (bad magic, bad length, oversized frame).
  Status feed(std::span<const std::byte> bytes, std::vector<std::vector<std::byte>>& out_frames);
  void clear();

  std::size_t buffered() const noexcept { return buffer_.size(); }
  std::size_t frame_count() const noexcept { return frames_; }

 private:
  std::size_t max_frame_bytes_;
  std::size_t frames_ = 0;
  std::vector<std::byte> buffer_;
};

}  // namespace dc

#endif  // DC_NET_HPP
