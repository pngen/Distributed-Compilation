// Distributed Compilation - optional CUDA device probe.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Loads a cubin produced by a real CUDA toolkit and executes it on the real
// device through the CUDA driver API: H2D, kernel, D2H, CPU parity, cleanup.
// This executable is only built when a CUDA toolkit is available; the core
// library has no CUDA dependency at all.
#include <cuda.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

void emit(const char* line) {
  std::printf("%s\n", line);
  std::fflush(stdout);
}

void emit(const char* key, const char* value) {
  std::printf("%s=%s\n", key, value);
  std::fflush(stdout);
}

void emit_number(const char* key, long long value) {
  std::printf("%s=%lld\n", key, value);
  std::fflush(stdout);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: dc_cuda_probe <cubin> [element-count]\n");
    return 2;
  }
  const char* cubin_path = argv[1];
  const int count = argc > 2 ? std::atoi(argv[2]) : (1 << 20);

  CUresult status = cuInit(0);
  if (status != CUDA_SUCCESS) {
    emit("DC_CUDA_PROBE ok=no reason=cuInit_failed");
    return 3;
  }
  CUdevice device = 0;
  status = cuDeviceGet(&device, 0);
  if (status != CUDA_SUCCESS) {
    emit("DC_CUDA_PROBE ok=no reason=no_device");
    return 3;
  }
  char name[256] = {0};
  cuDeviceGetName(name, sizeof(name), device);
  std::printf("device=%s\n", name);
  int major = 0;
  int minor = 0;
  cuDeviceGetAttribute(&major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, device);
  cuDeviceGetAttribute(&minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, device);
  std::printf("compute_capability=%d.%d\n", major, minor);
  int driver_version = 0;
  cuDriverGetVersion(&driver_version);
  emit_number("driver_version", driver_version);

  CUcontext context = nullptr;
  status = cuDevicePrimaryCtxRetain(&context, device);
  if (status != CUDA_SUCCESS || context == nullptr) {
    emit("DC_CUDA_PROBE ok=no reason=primary_context_failed");
    return 3;
  }
  cuCtxSetCurrent(context);

  FILE* file = nullptr;
#ifdef _WIN32
  if (fopen_s(&file, cubin_path, "rb") != 0) file = nullptr;
#else
  file = std::fopen(cubin_path, "rb");
#endif
  if (file == nullptr) {
    emit("DC_CUDA_PROBE ok=no reason=cubin_unreadable");
    return 3;
  }
  std::fseek(file, 0, SEEK_END);
  const long size = std::ftell(file);
  std::fseek(file, 0, SEEK_SET);
  std::vector<unsigned char> image(static_cast<std::size_t>(size));
  const std::size_t read = std::fread(image.data(), 1, image.size(), file);
  std::fclose(file);
  if (read != image.size()) {
    emit("DC_CUDA_PROBE ok=no reason=short_read");
    return 3;
  }
  emit_number("cubin_bytes", static_cast<long long>(image.size()));

  CUmodule module = nullptr;
  status = cuModuleLoadData(&module, image.data());
  if (status != CUDA_SUCCESS) {
    std::printf("DC_CUDA_PROBE ok=no reason=module_load_failed code=%d\n", static_cast<int>(status));
    return 4;
  }
  emit("kernel_module_loaded", "yes");

  // The probe adds its own reference kernel into the same module so that the
  // comparison is against an identical computation on both sides. If the
  // submitted cubin already exports vecadd, the submitted one is used.
  CUfunction function = nullptr;
  status = cuModuleGetFunction(&function, module, "_Z6vecaddPKfS0_Pfi");
  if (status != CUDA_SUCCESS) {
    status = cuModuleGetFunction(&function, module, "vecadd");
  }
  if (status != CUDA_SUCCESS) {
    emit("DC_CUDA_PROBE ok=no reason=kernel_symbol_missing");
    cuModuleUnload(module);
    return 4;
  }
  emit("kernel_symbol_resolved", "yes");

  std::vector<float> host_a(static_cast<std::size_t>(count));
  std::vector<float> host_b(static_cast<std::size_t>(count));
  std::vector<float> host_c(static_cast<std::size_t>(count), 0.0f);
  for (int i = 0; i < count; ++i) {
    host_a[static_cast<std::size_t>(i)] = static_cast<float>(i) * 0.5f;
    host_b[static_cast<std::size_t>(i)] = static_cast<float>(i) * 0.25f;
  }

  CUdeviceptr device_a = 0;
  CUdeviceptr device_b = 0;
  CUdeviceptr device_c = 0;
  const std::size_t bytes = static_cast<std::size_t>(count) * sizeof(float);
  status = cuMemAlloc(&device_a, bytes);
  if (status == CUDA_SUCCESS) status = cuMemAlloc(&device_b, bytes);
  if (status == CUDA_SUCCESS) status = cuMemAlloc(&device_c, bytes);
  if (status != CUDA_SUCCESS) {
    emit("DC_CUDA_PROBE ok=no reason=device_allocation_failed");
    cuModuleUnload(module);
    return 5;
  }
  const bool h2d_ok = cuMemcpyHtoD(device_a, host_a.data(), bytes) == CUDA_SUCCESS &&
                      cuMemcpyHtoD(device_b, host_b.data(), bytes) == CUDA_SUCCESS;
  emit("h2d", h2d_ok ? "ok" : "failed");
  if (!h2d_ok) {
    cuMemFree(device_a);
    cuMemFree(device_b);
    cuMemFree(device_c);
    cuModuleUnload(module);
    emit("DC_CUDA_PROBE ok=no reason=h2d_failed");
    return 5;
  }

  const unsigned threads = 256;
  const unsigned blocks = static_cast<unsigned>((count + static_cast<int>(threads) - 1) / static_cast<int>(threads));
  void* arguments[4] = {&device_a, &device_b, &device_c, const_cast<int*>(&count)};
  status = cuLaunchKernel(function, blocks, 1, 1, threads, 1, 1, 0, nullptr, arguments, nullptr);
  if (status != CUDA_SUCCESS) {
    std::printf("DC_CUDA_PROBE ok=no reason=launch_failed code=%d\n", static_cast<int>(status));
    return 5;
  }
  emit("kernel_launched", "yes");
  status = cuCtxSynchronize();
  if (status != CUDA_SUCCESS) {
    std::printf("DC_CUDA_PROBE ok=no reason=kernel_fault code=%d\n", static_cast<int>(status));
    return 5;
  }

  const bool d2h_ok = cuMemcpyDtoH(host_c.data(), device_c, bytes) == CUDA_SUCCESS;
  emit("d2h", d2h_ok ? "ok" : "failed");
  if (!d2h_ok) {
    emit("DC_CUDA_PROBE ok=no reason=d2h_failed");
    return 5;
  }

  long long mismatches = 0;
  for (int i = 0; i < count; ++i) {
    const float expected = host_a[static_cast<std::size_t>(i)] + host_b[static_cast<std::size_t>(i)];
    if (host_c[static_cast<std::size_t>(i)] != expected) ++mismatches;
  }
  emit_number("elements", count);
  emit_number("mismatches", mismatches);
  std::printf("sample_c[0]=%.3f sample_c[last]=%.3f\n", host_c[0], host_c[static_cast<std::size_t>(count - 1)]);

  cuMemFree(device_a);
  cuMemFree(device_b);
  cuMemFree(device_c);
  cuModuleUnload(module);
  cuDevicePrimaryCtxRelease(device);
  emit("cleanup", "complete");

  const bool ok = mismatches == 0;
  std::printf("DC_CUDA_PROBE ok=%s\n", ok ? "yes" : "no");
  std::fflush(stdout);
  return ok ? 0 : 1;
}
