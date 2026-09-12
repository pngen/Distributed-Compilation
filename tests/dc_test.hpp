// Distributed Compilation - test harness with case names and phase markers.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every case announces itself before it runs and reports immediately after, so
// a suite that stops identifies the exact case and the phase it stopped in
// rather than presenting an opaque hang.
#ifndef DC_TEST_HPP
#define DC_TEST_HPP

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace dctest {

struct Registry {
  struct Case {
    std::string suite;
    std::string name;
    std::function<void()> body;
  };

  std::vector<Case> cases;
  std::string current_suite;
  std::string current_case;
  std::string phase = "SETUP";
  int failures = 0;
  int passed = 0;
  int skipped = 0;
  std::string only;
  std::string from;

  static Registry& instance() {
    static Registry registry;
    return registry;
  }
};

inline void emit_line(const std::string& line) {
  std::fwrite(line.data(), 1, line.size(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
}

inline void phase(const std::string& value) {
  Registry::instance().phase = value;
  emit_line("[PHASE] " + value);
}

inline void fail(const std::string& message, const char* file, int line) {
  Registry& registry = Registry::instance();
  ++registry.failures;
  emit_line("[FAIL] " + registry.current_suite + "." + registry.current_case + " (" + registry.phase +
            ") " + message + " at " + file + ":" + std::to_string(line));
}

inline void expect(bool condition, const std::string& message, const char* file, int line) {
  if (condition) return;
  fail(message, file, line);
}

template <class A, class B>
void expect_eq(const A& actual, const B& expected, const std::string& message, const char* file, int line) {
  if (actual == expected) return;
  fail(message, file, line);
}

struct Registrar {
  Registrar(const std::string& suite, const std::string& name, std::function<void()> body) {
    Registry::instance().cases.push_back(Registry::Case{suite, name, std::move(body)});
  }
};

inline int run_all(int argc, char** argv) {
  Registry& registry = Registry::instance();
  if (argc > 1) registry.only = argv[1];
  if (argc > 2) registry.from = argv[2];

  bool running = registry.from.empty();
  int executed = 0;
  for (const auto& test : registry.cases) {
    if (!registry.from.empty() && test.name == registry.from) running = true;
    if (!running) continue;
    if (!registry.only.empty() && test.name != registry.only) continue;

    registry.current_suite = test.suite;
    registry.current_case = test.name;
    registry.phase = "SETUP";
    emit_line("[BEGIN] " + test.suite + "." + test.name);
    const int failures_before = registry.failures;
    try {
      test.body();
    } catch (const std::exception& error) {
      fail(std::string("uncaught exception: ") + error.what(), __FILE__, __LINE__);
    } catch (...) {
      fail("uncaught non-standard exception", __FILE__, __LINE__);
    }
    ++executed;
    if (registry.failures == failures_before) {
      ++registry.passed;
      emit_line("[PASS] " + test.suite + "." + test.name);
    }
  }
  if (registry.only.empty()) {
    for (const auto& test : registry.cases) {
      if (std::find_if(registry.cases.begin(), registry.cases.end(), [&test](const Registry::Case& c) {
            return c.name == test.name;
          }) == registry.cases.end()) {
        ++registry.skipped;
      }
    }
  }
  emit_line("DC_TESTS cases=" + std::to_string(executed) + " passed=" + std::to_string(registry.passed) +
            " failed=" + std::to_string(registry.failures) +
            (registry.failures == 0 ? " ok=yes" : " ok=no"));
  return registry.failures == 0 ? 0 : 1;
}

}  // namespace dctest

#define DC_TEST(suite, name)                                                              \
  static void dc_test_##suite##_##name();                                                 \
  static ::dctest::Registrar dc_registrar_##suite##_##name(#suite, #name,                 \
                                                           dc_test_##suite##_##name);      \
  static void dc_test_##suite##_##name()

#define DC_EXPECT(condition) ::dctest::expect((condition), #condition, __FILE__, __LINE__)
#define DC_EXPECT_MSG(condition, message) ::dctest::expect((condition), (message), __FILE__, __LINE__)
#define DC_EXPECT_EQ(actual, expected)   ::dctest::expect_eq((actual), (expected), #actual " == " #expected, __FILE__, __LINE__)
#define DC_EXPECT_NE(actual, expected)   ::dctest::expect(!((actual) == (expected)), #actual " != " #expected, __FILE__, __LINE__)
#define DC_PHASE(value) ::dctest::phase(value)

#endif  // DC_TEST_HPP
