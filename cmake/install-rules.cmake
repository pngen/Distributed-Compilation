# Distributed Compilation - installation rules.
# Copyright 2026 Summon Software Labs. Apache License 2.0.
#
# Included at the end of the top-level CMakeLists so that every installable
# target already exists when these rules are evaluated.

install(TARGETS dc_core
  EXPORT DistributedCompilationTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/dc
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(DC_BUILD_APPS)
  install(TARGETS dc_coordinator dc_worker dc_cli
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
if(TARGET dc_cuda_probe)
  install(TARGETS dc_cuda_probe RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(EXPORT DistributedCompilationTargets
  FILE DistributedCompilationTargets.cmake
  NAMESPACE dc::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/DistributedCompilation
)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/DistributedCompilationConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/DistributedCompilationConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/DistributedCompilation
)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/DistributedCompilationConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/DistributedCompilationConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/DistributedCompilationConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/DistributedCompilation
)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/README.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/DistributedCompilation
  OPTIONAL
)
