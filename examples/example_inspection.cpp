// Distributed Compilation - example: offline state inspection.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Opens a coordinator state directory the way an operator would, reports what
// the journal and snapshot contain, and refuses to guess if the state is
// damaged.
#include <cstdio>
#include <filesystem>
#include <string>

#include "dc/persistence.hpp"

using namespace dc;

int main(int argc, char** argv) {
  const std::filesystem::path root = argc > 1 ? std::filesystem::path(argv[1])
                                              : std::filesystem::path(".dcstate");
  std::printf("state root: %s\n", std::filesystem::absolute(root).string().c_str());

  PersistentStore store;
  PersistentStore::Options options;
  options.root = root;
  std::vector<JournalRecord> records;
  std::vector<std::byte> snapshot;
  auto opened = store.open(options, records, snapshot);
  if (!opened.ok()) {
    std::printf("state could not be opened: %s\n", opened.status().describe().c_str());
    return 1;
  }
  const RecoveryReport& report = opened.value();
  std::printf("snapshot loaded: %s\n", report.snapshot_loaded ? "yes" : "no");
  std::printf("snapshot sequence: %llu\n", static_cast<unsigned long long>(report.snapshot_seq));
  std::printf("snapshot bytes: %llu\n", static_cast<unsigned long long>(snapshot.size()));
  std::printf("journal records applied: %llu\n", static_cast<unsigned long long>(report.records_applied));
  std::printf("journal records skipped: %llu\n", static_cast<unsigned long long>(report.records_skipped));
  std::printf("torn tail recovered: %s\n", report.torn_tail ? "yes" : "no");
  for (const auto& note : report.notes) std::printf("note: %s\n", note.c_str());

  std::uint64_t total_payload = 0;
  for (const auto& record : records) {
    total_payload += record.payload.size();
    std::printf("record seq=%llu type=%s bytes=%llu\n", static_cast<unsigned long long>(record.seq),
                std::string(to_string(record.type)).c_str(),
                static_cast<unsigned long long>(record.payload.size()));
  }
  std::printf("replayed payload bytes: %llu\n", static_cast<unsigned long long>(total_payload));
  store.close();
  return 0;
}
