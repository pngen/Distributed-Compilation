// Distributed Compilation - durable snapshot, journal and content-addressed blobs.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/persistence.hpp"

#include <algorithm>
#include <cstring>
#include <system_error>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace dc {
namespace {

constexpr std::uint32_t kRecordMagic = 0x4443304Au;    // "J0CD"
constexpr std::uint32_t kSnapshotMagic = 0x44433053u;  // "S0CD"
constexpr std::size_t kRecordHeaderBytes = 24;
constexpr std::size_t kSnapshotHeaderBytes = 56;
constexpr std::uint64_t kMaxJournalBytes = 256ull * 1024 * 1024;

void put_u16(std::vector<std::byte>& out, std::uint16_t value) {
  out.push_back(static_cast<std::byte>(value & 0xFFu));
  out.push_back(static_cast<std::byte>((value >> 8) & 0xFFu));
}

void put_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFFu));
}

void put_u64(std::vector<std::byte>& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFFu));
}

std::uint16_t get_u16(const std::byte* p) {
  return static_cast<std::uint16_t>(static_cast<std::uint8_t>(p[0]) |
                                    (static_cast<std::uint16_t>(static_cast<std::uint8_t>(p[1])) << 8));
}

std::uint32_t get_u32(const std::byte* p) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[i])) << (i * 8);
  }
  return value;
}

std::uint64_t get_u64(const std::byte* p) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(p[i])) << (i * 8);
  }
  return value;
}

Status flush_and_sync(FILE* file) {
  if (std::fflush(file) != 0) return Status::error(ErrorCode::IoError, "flush failed");
#ifdef _WIN32
  if (_commit(_fileno(file)) != 0) return Status::error(ErrorCode::IoError, "commit failed");
#else
  if (fsync(fileno(file)) != 0) return Status::error(ErrorCode::IoError, "fsync failed");
#endif
  return Status::success();
}

}  // namespace

std::string_view to_string(RecordType type) noexcept {
  switch (type) {
    case RecordType::SchemaInfo: return "SchemaInfo";
    case RecordType::Header: return "Header";
    case RecordType::RegistryEntry: return "RegistryEntry";
    case RecordType::Worker: return "Worker";
    case RecordType::Compilation: return "Compilation";
    case RecordType::Attempt: return "Attempt";
    case RecordType::Commit: return "Commit";
    case RecordType::Provenance: return "Provenance";
    case RecordType::Validation: return "Validation";
    case RecordType::CacheEntry: return "CacheEntry";
    case RecordType::NegativeCache: return "NegativeCache";
    case RecordType::Job: return "Job";
    case RecordType::Lease: return "Lease";
    case RecordType::Intermediate: return "Intermediate";
    case RecordType::Artifact: return "Artifact";
  }
  return "Unknown";
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------
Status ensure_directory(const std::filesystem::path& path) {
  std::error_code ec;
  if (path.empty()) return Status::success();
  if (std::filesystem::exists(path, ec)) {
    if (ec) return Status::error(ErrorCode::IoError, ec.message());
    if (!std::filesystem::is_directory(path, ec)) {
      return Status::error(ErrorCode::IoError, "path exists and is not a directory: " + path.string());
    }
    return Status::success();
  }
  std::filesystem::create_directories(path, ec);
  if (ec) return Status::error(ErrorCode::IoError, "cannot create directory: " + ec.message());
  return Status::success();
}

Status remove_tree_quiet(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::remove_all(path, ec);
  // Absence is success. A permission failure is reported, since leaving stale
  // state behind silently is exactly the failure this runtime must not have.
  if (ec && std::filesystem::exists(path)) {
    return Status::error(ErrorCode::IoError, "cannot remove tree: " + ec.message());
  }
  return Status::success();
}

bool path_is_within(const std::filesystem::path& child, const std::filesystem::path& parent) {
  std::error_code ec;
  const auto normal_child = std::filesystem::weakly_canonical(child, ec);
  if (ec) return false;
  const auto normal_parent = std::filesystem::weakly_canonical(parent, ec);
  if (ec) return false;
  auto child_it = normal_child.begin();
  for (auto parent_it = normal_parent.begin(); parent_it != normal_parent.end(); ++parent_it, ++child_it) {
    if (child_it == normal_child.end()) return false;
    if (*child_it != *parent_it) return false;
  }
  return true;
}

Status read_file_bounded(const std::filesystem::path& path, std::uint64_t max_bytes,
                         std::vector<std::byte>& out) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  if (ec) return Status::error(ErrorCode::NotFound, "cannot stat file: " + ec.message());
  if (size > max_bytes) {
    return Status::error(ErrorCode::LimitExceeded, "file exceeds bounded read limit: " + path.string());
  }
  FILE* file = nullptr;
#ifdef _WIN32
  if (_wfopen_s(&file, path.wstring().c_str(), L"rb") != 0) file = nullptr;
#else
  file = std::fopen(path.string().c_str(), "rb");
#endif
  if (file == nullptr) return Status::error(ErrorCode::IoError, "cannot open file: " + path.string());
  out.assign(static_cast<std::size_t>(size), std::byte{0});
  std::size_t read_total = 0;
  if (size > 0) {
    read_total = std::fread(out.data(), 1, out.size(), file);
  }
  std::fclose(file);
  if (read_total != out.size()) return Status::error(ErrorCode::IoError, "short read: " + path.string());
  return Status::success();
}

Status write_file_atomic(const std::filesystem::path& path, std::span<const std::byte> bytes, bool fsync) {
  std::error_code ec;
  if (path.has_parent_path()) {
    Status dir_status = ensure_directory(path.parent_path());
    if (!dir_status.ok()) return dir_status;
  }
  std::filesystem::path temp = path;
  temp += L".tmp";
  FILE* file = nullptr;
#ifdef _WIN32
  if (_wfopen_s(&file, temp.wstring().c_str(), L"wb") != 0) file = nullptr;
#else
  file = std::fopen(temp.string().c_str(), "wb");
#endif
  if (file == nullptr) return Status::error(ErrorCode::IoError, "cannot create temp file: " + temp.string());
  if (!bytes.empty()) {
    const std::size_t written = std::fwrite(bytes.data(), 1, bytes.size(), file);
    if (written != bytes.size()) {
      std::fclose(file);
      std::filesystem::remove(temp, ec);
      return Status::error(ErrorCode::IoError, "short write: " + temp.string());
    }
  }
  if (fsync) {
    Status sync_status = flush_and_sync(file);
    if (!sync_status.ok()) {
      std::fclose(file);
      std::filesystem::remove(temp, ec);
      return sync_status;
    }
  } else if (std::fflush(file) != 0) {
    std::fclose(file);
    std::filesystem::remove(temp, ec);
    return Status::error(ErrorCode::IoError, "flush failed");
  }
  std::fclose(file);

  std::filesystem::rename(temp, path, ec);
  if (ec) {
    std::filesystem::remove(temp, ec);
    return Status::error(ErrorCode::IoError, "atomic replace failed: " + ec.message());
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// PersistentStore
// ---------------------------------------------------------------------------
struct PersistentStore::Impl {
  FILE* journal = nullptr;
};

PersistentStore::PersistentStore() : impl_(std::make_unique<Impl>()) {}

PersistentStore::~PersistentStore() { close(); }

bool PersistentStore::is_open() const noexcept { return impl_ && impl_->journal != nullptr; }

void PersistentStore::close() {
  if (impl_ && impl_->journal != nullptr) {
    std::fflush(impl_->journal);
    std::fclose(impl_->journal);
    impl_->journal = nullptr;
  }
}

std::filesystem::path PersistentStore::blob_path(const Digest256& digest) const {
  const std::string hex = digest.hex();
  return root_ / "artifacts" / hex.substr(0, 2) / (hex + ".bin");
}

Result<RecoveryReport> PersistentStore::open(const Options& options, std::vector<JournalRecord>& out_records,
                                             std::vector<std::byte>& out_snapshot) {
  RecoveryReport report;
  options_ = options;
  root_ = options.root;
  out_records.clear();
  out_snapshot.clear();

  Status dir_status = ensure_directory(root_);
  if (!dir_status.ok()) return Result<RecoveryReport>(dir_status);
  Status artifacts_status = ensure_directory(root_ / "artifacts");
  if (!artifacts_status.ok()) return Result<RecoveryReport>(artifacts_status);

  const std::filesystem::path snapshot_path = root_ / "snapshot.dcsnap";
  const std::filesystem::path journal_path = root_ / "journal.dcjournal";

  seq_ = 0;

  std::error_code ec;
  if (std::filesystem::exists(snapshot_path, ec)) {
    std::vector<std::byte> raw;
    Status read_status = read_file_bounded(snapshot_path, options.max_snapshot_bytes, raw);
    if (!read_status.ok()) return Result<RecoveryReport>(read_status);
    if (raw.size() < kSnapshotHeaderBytes) {
      return Result<RecoveryReport>(
          Status::error(ErrorCode::PersistenceCorrupt, "snapshot header is truncated"));
    }
    const std::byte* p = raw.data();
    if (get_u32(p) != kSnapshotMagic) {
      return Result<RecoveryReport>(Status::error(ErrorCode::PersistenceCorrupt, "snapshot magic mismatch"));
    }
    const std::uint16_t schema = get_u16(p + 4);
    if (schema != DC_SCHEMA_VERSION) {
      return Result<RecoveryReport>(Status::error(
          ErrorCode::SchemaMismatch,
          "snapshot schema " + std::to_string(schema) + " does not match runtime schema " +
              std::to_string(DC_SCHEMA_VERSION)));
    }
    const std::uint64_t snapshot_seq = get_u64(p + 8);
    const std::uint64_t payload_len = get_u64(p + 16);
    if (payload_len > options.max_snapshot_bytes ||
        payload_len != static_cast<std::uint64_t>(raw.size() - kSnapshotHeaderBytes)) {
      return Result<RecoveryReport>(
          Status::error(ErrorCode::PersistenceCorrupt, "snapshot length field is inconsistent"));
    }
    Digest256 stored;
    std::memcpy(stored.data(), p + 24, Digest256::kBytes);
    const std::span<const std::byte> payload(raw.data() + kSnapshotHeaderBytes,
                                             static_cast<std::size_t>(payload_len));
    const Digest256 actual = sha256(payload);
    if (actual != stored) {
      return Result<RecoveryReport>(
          Status::error(ErrorCode::IntegrityFailure, "snapshot digest mismatch"));
    }
    out_snapshot.assign(payload.begin(), payload.end());
    report.snapshot_loaded = true;
    report.snapshot_seq = snapshot_seq;
    seq_ = snapshot_seq;
    report.notes.push_back("snapshot loaded at seq " + std::to_string(snapshot_seq));
  }

  // Journal replay.
  std::vector<std::byte> journal_bytes;
  bool journal_exists = std::filesystem::exists(journal_path, ec);
  if (journal_exists) {
    const auto size = std::filesystem::file_size(journal_path, ec);
    if (ec) return Result<RecoveryReport>(Status::error(ErrorCode::IoError, ec.message()));
    if (size > 0) {
      if (size > kMaxJournalBytes) {
        return Result<RecoveryReport>(
            Status::error(ErrorCode::LimitExceeded, "journal exceeds bounded replay limit"));
      }
      Status read_status = read_file_bounded(journal_path, kMaxJournalBytes, journal_bytes);
      if (!read_status.ok()) return Result<RecoveryReport>(read_status);
    }
  }

  std::size_t offset = 0;
  std::size_t last_good_offset = 0;
  std::uint64_t applied = 0;
  std::uint64_t skipped = 0;
  bool damaged = false;
  std::string damage_detail;

  while (offset < journal_bytes.size()) {
    const std::size_t available = journal_bytes.size() - offset;
    if (available < kRecordHeaderBytes) {
      damaged = true;
      damage_detail = "journal header truncated";
      break;
    }
    const std::byte* p = journal_bytes.data() + offset;
    if (get_u32(p) != kRecordMagic) {
      damaged = true;
      damage_detail = "journal record magic mismatch";
      break;
    }
    const std::uint16_t schema = get_u16(p + 4);
    const std::uint16_t raw_type = get_u16(p + 6);
    const std::uint64_t record_seq = get_u64(p + 8);
    const std::uint32_t payload_len = get_u32(p + 16);
    const std::uint32_t stored_crc = get_u32(p + 20);

    if (schema != DC_SCHEMA_VERSION) {
      damaged = true;
      damage_detail = "journal schema mismatch";
      break;
    }
    if (raw_type == 0 || raw_type > static_cast<std::uint16_t>(RecordType::Artifact)) {
      damaged = true;
      damage_detail = "journal record type out of domain";
      break;
    }
    if (payload_len > options.max_record_bytes) {
      damaged = true;
      damage_detail = "journal record exceeds bounded size";
      break;
    }
    if (available < kRecordHeaderBytes + payload_len) {
      damaged = true;
      damage_detail = "journal record payload truncated";
      break;
    }
    const std::byte* payload = p + kRecordHeaderBytes;
    if (crc32(payload, payload_len) != stored_crc) {
      damaged = true;
      damage_detail = "journal record checksum mismatch";
      break;
    }

    if (record_seq > seq_) {
      if (applied >= options.max_replay_records) {
        return Result<RecoveryReport>(
            Status::error(ErrorCode::LimitExceeded, "journal replay record budget exceeded"));
      }
      JournalRecord record;
      record.type = static_cast<RecordType>(raw_type);
      record.seq = record_seq;
      record.payload.assign(payload, payload + payload_len);
      out_records.push_back(std::move(record));
      seq_ = record_seq;
      ++applied;
    } else {
      ++skipped;
    }

    offset += kRecordHeaderBytes + payload_len;
    last_good_offset = offset;
  }

  if (damaged) {
    // Distinguish a genuinely corrupt interior record from a torn tail: if a
    // structurally valid record exists after the damage, the file is corrupt
    // and must not be silently repaired.
    bool valid_record_after = false;
    for (std::size_t scan = offset + 1; scan + kRecordHeaderBytes <= journal_bytes.size(); ++scan) {
      const std::byte* p = journal_bytes.data() + scan;
      if (get_u32(p) != kRecordMagic) continue;
      const std::uint32_t payload_len = get_u32(p + 16);
      const std::uint32_t stored_crc = get_u32(p + 20);
      if (payload_len > options.max_record_bytes) continue;
      if (scan + kRecordHeaderBytes + payload_len > journal_bytes.size()) continue;
      if (crc32(p + kRecordHeaderBytes, payload_len) == stored_crc) {
        valid_record_after = true;
        break;
      }
    }
    if (valid_record_after) {
      return Result<RecoveryReport>(Status::error(
          ErrorCode::PersistenceCorrupt,
          "journal is corrupt: " + damage_detail + " with valid records after the damage"));
    }
    report.torn_tail = true;
    report.notes.push_back("torn journal tail recovered: " + damage_detail);
    report.bytes_reclaimed = static_cast<std::uint64_t>(journal_bytes.size() - last_good_offset);
  }

  report.records_applied = applied;
  report.records_skipped = skipped;

  // Open the journal for appending, truncating a torn tail in place.
  FILE* journal = nullptr;
#ifdef _WIN32
  if (_wfopen_s(&journal, journal_path.wstring().c_str(), L"w+b") != 0) journal = nullptr;
#else
  journal = std::fopen(journal_path.string().c_str(), "w+b");
#endif
  if (journal == nullptr) {
    return Result<RecoveryReport>(Status::error(ErrorCode::IoError, "cannot open journal for append"));
  }
  if (last_good_offset > 0) {
    if (std::fwrite(journal_bytes.data(), 1, last_good_offset, journal) != last_good_offset) {
      std::fclose(journal);
      return Result<RecoveryReport>(Status::error(ErrorCode::IoError, "cannot rewrite recovered journal"));
    }
  }
  if (report.torn_tail) {
    Status sync_status = flush_and_sync(journal);
    if (!sync_status.ok()) {
      std::fclose(journal);
      return Result<RecoveryReport>(sync_status);
    }
    report.truncated_in_place = true;
  } else {
    std::fseek(journal, 0, SEEK_END);
  }
  impl_->journal = journal;

  report.opened = true;
  return Result<RecoveryReport>(report);
}

Status PersistentStore::append_raw(const JournalRecord& record) {
  if (!is_open()) return Status::error(ErrorCode::PersistenceClosed, "persistent store is not open");
  if (record.payload.size() > options_.max_record_bytes) {
    return Status::error(ErrorCode::LimitExceeded, "journal record exceeds bounded size");
  }
  std::vector<std::byte> header;
  header.reserve(kRecordHeaderBytes);
  put_u32(header, kRecordMagic);
  put_u16(header, static_cast<std::uint16_t>(DC_SCHEMA_VERSION));
  put_u16(header, static_cast<std::uint16_t>(record.type));
  put_u64(header, record.seq);
  put_u32(header, static_cast<std::uint32_t>(record.payload.size()));
  put_u32(header, crc32(record.payload.data(), record.payload.size()));

  std::fseek(impl_->journal, 0, SEEK_END);
  if (std::fwrite(header.data(), 1, header.size(), impl_->journal) != header.size()) {
    return Status::error(ErrorCode::IoError, "journal header write failed");
  }
  if (!record.payload.empty()) {
    if (std::fwrite(record.payload.data(), 1, record.payload.size(), impl_->journal) != record.payload.size()) {
      return Status::error(ErrorCode::IoError, "journal payload write failed");
    }
  }
  if (options_.fsync_records) {
    Status sync_status = flush_and_sync(impl_->journal);
    if (!sync_status.ok()) return sync_status;
  } else if (std::fflush(impl_->journal) != 0) {
    return Status::error(ErrorCode::IoError, "journal flush failed");
  }
  return Status::success();
}

Status PersistentStore::append(RecordType type, std::span<const std::byte> payload) {
  JournalRecord record;
  record.type = type;
  record.seq = seq_ + 1;
  record.payload.assign(payload.begin(), payload.end());
  Status status = append_raw(record);
  if (!status.ok()) return status;
  seq_ = record.seq;
  return Status::success();
}

Status PersistentStore::truncate_journal() {
  if (!is_open()) return Status::error(ErrorCode::PersistenceClosed, "persistent store is not open");
  const std::filesystem::path journal_path = root_ / "journal.dcjournal";
  std::fclose(impl_->journal);
  impl_->journal = nullptr;
  FILE* journal = nullptr;
#ifdef _WIN32
  if (_wfopen_s(&journal, journal_path.wstring().c_str(), L"w+b") != 0) journal = nullptr;
#else
  journal = std::fopen(journal_path.string().c_str(), "w+b");
#endif
  if (journal == nullptr) return Status::error(ErrorCode::IoError, "cannot reopen journal");
  impl_->journal = journal;
  return Status::success();
}

Status PersistentStore::write_snapshot(std::span<const std::byte> payload) {
  if (!is_open()) return Status::error(ErrorCode::PersistenceClosed, "persistent store is not open");
  if (payload.size() > options_.max_snapshot_bytes) {
    return Status::error(ErrorCode::LimitExceeded, "snapshot exceeds bounded size");
  }
  std::vector<std::byte> blob;
  blob.reserve(kSnapshotHeaderBytes + payload.size());
  put_u32(blob, kSnapshotMagic);
  put_u16(blob, static_cast<std::uint16_t>(DC_SCHEMA_VERSION));
  put_u16(blob, 0);
  put_u64(blob, seq_);
  put_u64(blob, static_cast<std::uint64_t>(payload.size()));
  const Digest256 digest = sha256(payload);
  for (std::size_t i = 0; i < Digest256::kBytes; ++i) {
    blob.push_back(static_cast<std::byte>(digest.data()[i]));
  }
  blob.insert(blob.end(), payload.begin(), payload.end());

  Status write_status = write_file_atomic(root_ / "snapshot.dcsnap", blob, true);
  if (!write_status.ok()) return write_status;
  return truncate_journal();
}

Result<Digest256> PersistentStore::put_blob(std::span<const std::byte> bytes) {
  const Digest256 digest = sha256(bytes);
  const std::filesystem::path path = blob_path(digest);
  std::error_code ec;
  if (std::filesystem::exists(path, ec)) {
    // Already stored. Re-verify rather than trusting the filename: a truncated
    // or tampered blob must be repaired, not silently reused.
    std::vector<std::byte> existing;
    Status read_status = read_file_bounded(path, options_.max_snapshot_bytes, existing);
    if (read_status.ok() && sha256(existing) == digest) {
      return Result<Digest256>(digest);
    }
  }
  Status write_status = write_file_atomic(path, bytes, true);
  if (!write_status.ok()) return Result<Digest256>(write_status);
  return Result<Digest256>(digest);
}

Status PersistentStore::get_blob(const Digest256& digest, std::vector<std::byte>& out) const {
  Status read_status = read_file_bounded(blob_path(digest), options_.max_snapshot_bytes, out);
  if (!read_status.ok()) return read_status;
  if (sha256(out) != digest) {
    return Status::error(ErrorCode::IntegrityFailure, "stored blob does not match its digest");
  }
  return Status::success();
}

bool PersistentStore::has_blob(const Digest256& digest) const {
  std::error_code ec;
  return std::filesystem::exists(blob_path(digest), ec) && !ec;
}

Status PersistentStore::remove_blob(const Digest256& digest) {
  std::error_code ec;
  std::filesystem::remove(blob_path(digest), ec);
  if (ec) return Status::error(ErrorCode::IoError, ec.message());
  return Status::success();
}

}  // namespace dc
