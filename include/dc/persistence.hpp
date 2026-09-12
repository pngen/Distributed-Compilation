// Distributed Compilation - durable state: snapshot, append journal, blob store.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Durability contract
// -------------------
//   * Every journal append is flushed and fsync'd before the caller is told it
//     succeeded. A commit acknowledgement therefore always corresponds to state
//     a restarted coordinator can recover.
//   * A snapshot is written to a temporary file, fsync'd, then atomically
//     renamed over the previous snapshot. A crash never leaves a torn snapshot
//     in place.
//   * Journal records captured in a snapshot are skipped during replay by
//     sequence number, so a crash between "snapshot written" and "journal
//     truncated" is harmless.
//   * Corruption and truncation are distinguished: a torn tail is recovered by
//     truncation and reported; a structurally corrupt record with valid records
//     after it is refused outright.
#ifndef DC_PERSISTENCE_HPP
#define DC_PERSISTENCE_HPP

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "dc/model.hpp"
#include "dc/types.hpp"

namespace dc {

enum class RecordType : std::uint16_t {
  SchemaInfo = 1,
  Header = 2,
  RegistryEntry = 3,
  Worker = 4,
  Compilation = 5,
  Attempt = 6,
  Commit = 7,
  Provenance = 8,
  Validation = 9,
  CacheEntry = 10,
  NegativeCache = 11,
  Job = 12,
  Lease = 13,
  Intermediate = 14,
  Artifact = 15,
};

std::string_view to_string(RecordType type) noexcept;

// One decoded journal record. Payload bytes are owned by the record.
struct JournalRecord {
  RecordType type = RecordType::SchemaInfo;
  Seq seq = 0;
  std::vector<std::byte> payload;
};

struct RecoveryReport {
  bool opened = false;
  bool snapshot_loaded = false;
  bool torn_tail = false;
  bool truncated_in_place = false;
  std::uint64_t snapshot_seq = 0;
  std::uint64_t records_applied = 0;
  std::uint64_t records_skipped = 0;
  std::uint64_t bytes_reclaimed = 0;
  std::vector<std::string> notes;
};

class PersistentStore {
 public:
  struct Options {
    std::filesystem::path root;
    bool fsync_records = true;
    std::uint64_t max_record_bytes = 64ull * 1024 * 1024;
    std::uint64_t max_snapshot_bytes = 512ull * 1024 * 1024;
    std::uint64_t max_replay_records = 4ull * 1024 * 1024;
  };

  PersistentStore();
  ~PersistentStore();

  PersistentStore(const PersistentStore&) = delete;
  PersistentStore& operator=(const PersistentStore&) = delete;

  // Opens (creating if needed) the state directory and returns every journal
  // record that must be replayed on top of the snapshot.
  Result<RecoveryReport> open(const Options& options, std::vector<JournalRecord>& out_records,
                              std::vector<std::byte>& out_snapshot);

  void close();
  bool is_open() const noexcept;

  Seq last_seq() const noexcept { return seq_; }
  const std::filesystem::path& root() const noexcept { return root_; }
  std::filesystem::path blob_path(const Digest256& digest) const;

  // Appends a record. Returns only after the bytes are durable.
  Status append(RecordType type, std::span<const std::byte> payload);

  // Writes a full snapshot durably and forgets journal records it contains.
  Status write_snapshot(std::span<const std::byte> payload);

  // Blob store operations. Content is verified against its digest on both
  // ingest and load; a mismatch is IntegrityFailure, never a silent success.
  Result<Digest256> put_blob(std::span<const std::byte> bytes);
  Status get_blob(const Digest256& digest, std::vector<std::byte>& out) const;
  bool has_blob(const Digest256& digest) const;
  Status remove_blob(const Digest256& digest);

 private:
  Status append_raw(const JournalRecord& record);
  Status truncate_journal();

  struct Impl;
  std::unique_ptr<Impl> impl_;
  std::filesystem::path root_;
  Seq seq_ = 0;
  Options options_;
};

// ---------------------------------------------------------------------------
// Filesystem helpers used by persistence, workspaces and artifact transfer.
// ---------------------------------------------------------------------------
Status read_file_bounded(const std::filesystem::path& path, std::uint64_t max_bytes,
                         std::vector<std::byte>& out);
Status write_file_atomic(const std::filesystem::path& path, std::span<const std::byte> bytes, bool fsync);
Status ensure_directory(const std::filesystem::path& path);
Status remove_tree_quiet(const std::filesystem::path& path);
bool path_is_within(const std::filesystem::path& child, const std::filesystem::path& parent);

}  // namespace dc

#endif  // DC_PERSISTENCE_HPP
