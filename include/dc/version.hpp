// Distributed Compilation - vendor-neutral C++20 runtime for distributed compilation authority.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_VERSION_HPP
#define DC_VERSION_HPP

#define DC_VERSION_MAJOR 1
#define DC_VERSION_MINOR 0
#define DC_VERSION_PATCH 0
#define DC_VERSION_STRING "1.0.0"

// Persistence schema version. Any change to the on-disk record or snapshot layout
// must bump this value; the loader refuses to decode unknown schema versions
// rather than guessing.
#define DC_SCHEMA_VERSION 1

// Wire protocol version.
#define DC_PROTOCOL_VERSION 1

namespace dc {

struct Version {
  int major = DC_VERSION_MAJOR;
  int minor = DC_VERSION_MINOR;
  int patch = DC_VERSION_PATCH;
};

inline Version version() noexcept { return Version{}; }

}  // namespace dc

#endif  // DC_VERSION_HPP
