cmake_minimum_required(VERSION 3.21)
project(parakeet_crypto VERSION 0.7.1 LANGUAGES CXX)

set(CMAKE_POLICY_DEFAULT_CMP0048 NEW)

option(PARAKEET_CRYPTO_BUILD_TESTING "Build library tests" ON)
option(PARAKEET_CRYPTO_BUILD_EXAMPLES "Build examples" ON)

option(PARAKEET_CRYPTO_LOGGING_ENABLE_DEBUG "Enabled debug logging" OFF)
option(PARAKEET_CRYPTO_LOGGING_ENABLE_INFO "Enabled info logging" ON)
option(PARAKEET_CRYPTO_LOGGING_ENABLE_WARN "Enabled warning logging" ON)
option(PARAKEET_CRYPTO_LOGGING_ENABLE_ERROR "Enabled error logging" ON)

include(cmake/CPM-Loader.cmake)
include(cmake/git-info.cmake)

CPMAddPackage(
    NAME zlib 
    GITHUB_REPOSITORY madler/zlib
    GIT_TAG "v1.2.13"
    DOWNLOAD_ONLY YES
)

if (zlib_ADDED)
    add_subdirectory("${zlib_SOURCE_DIR}" "${zlib_BINARY_DIR}")

    add_library(ZLIB::ZLIB ALIAS zlibstatic)
    target_include_directories(zlib
      PUBLIC
        $<BUILD_INTERFACE:${zlib_SOURCE_DIR}>
    )
    target_include_directories(zlibstatic
      PUBLIC
        $<BUILD_INTERFACE:${zlib_SOURCE_DIR}>
    )
    install(TARGETS zlib zlibstatic EXPORT zlib-targets
        RUNTIME DESTINATION "${INSTALL_BIN_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}" )
    install(FILES ${ZLIB_PUBLIC_HDRS} EXPORT zlib-targets DESTINATION "${INSTALL_INC_DIR}")
    install(FILES zlib.3 EXPORT zlib-targets DESTINATION "${INSTALL_MAN_DIR}/man3")
    install(FILES ${ZLIB_PC} EXPORT zlib-targets DESTINATION "${INSTALL_PKGCONFIG_DIR}")
    install(EXPORT zlib-targets DESTINATION lib)
    configure_file("${zlib_SOURCE_DIR}/zconf.h.included" "${zlib_SOURCE_DIR}/zconf.h" COPYONLY)
endif()

CPMAddPackage(
    NAME tc-tea
    GITHUB_REPOSITORY jixunmoe/libtc_tea
    GIT_TAG v0.1.4-RC1
    OPTIONS
        "TC_TEA_BUILD_TESTING OFF"
)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS YES CACHE BOOL "Export all symbols")

configure_file (
    "${PROJECT_SOURCE_DIR}/src/version.cpp.in"
    "${PROJECT_BINARY_DIR}/src/version.cpp"
    @ONLY
)
configure_file (
    "${PROJECT_SOURCE_DIR}/src/utils/logger_config.h.in"
    "${PROJECT_BINARY_DIR}/src/utils/logger_config.h"
    @ONLY
)

file(GLOB_RECURSE SOURCES
    "src/*.h"
    "src/*.cpp"
    "${PROJECT_BINARY_DIR}/src/*.h"
    "${PROJECT_BINARY_DIR}/src/*.cpp"
)

file(GLOB_RECURSE INCLUDE_HEADERS
    "include/*.h"
    "${PROJECT_BINARY_DIR}/include/*.h"
)

# Add source to this project's executable.
add_library(parakeet_crypto STATIC ${SOURCES} ${INCLUDE_HEADERS})
set_target_properties(parakeet_crypto PROPERTIES
    CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON EXPORT_COMPILE_COMMANDS ON)
add_library(parakeet::crypto ALIAS parakeet_crypto)
if(MSVC)
    target_compile_options(parakeet_crypto PRIVATE "/MP")
else()
    target_link_libraries(parakeet_crypto PRIVATE m)
endif()
target_include_directories(parakeet_crypto
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        src
        "${PROJECT_BINARY_DIR}/src"
)


target_link_libraries(parakeet_crypto
    PRIVATE 
        # cryptopp::cryptopp
        tc-tea::tc-tea
        ZLIB::ZLIB
)

include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/parakeet_crypto)

install(TARGETS parakeet_crypto
    EXPORT parakeet_crypto-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
set_target_properties(parakeet_crypto PROPERTIES EXPORT_NAME ParakeetCrypto)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT parakeet_crypto-targets
FILE
    ParakeetCryptoTargets.cmake
NAMESPACE
    ParakeetCrypto::
DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/cmake/parakeet_crypto
)

# Tests!
if(PARAKEET_CRYPTO_BUILD_TESTING)
    enable_testing()
    CPMAddPackage(
      NAME googletest
      GITHUB_REPOSITORY google/googletest
      GIT_TAG release-1.12.1
      VERSION 1.12.1
      OPTIONS
          "INSTALL_GTEST OFF"
          "gtest_force_shared_crt ON"
    )
    include(GoogleTest)

    configure_file (
        "${PROJECT_SOURCE_DIR}/src/test/test_env.h.in"
        "${PROJECT_BINARY_DIR}/src/test/test_env.h"
        @ONLY
    )

    file(GLOB_RECURSE TESTS_SOURCE src/*.test.cc src/*.test.hh)
    add_executable(parakeet_crypto_test ${TESTS_SOURCE})
    target_include_directories(parakeet_crypto_test PRIVATE src "${PROJECT_BINARY_DIR}/src")
    target_compile_features(parakeet_crypto_test PUBLIC cxx_std_17)
    target_link_libraries(parakeet_crypto_test 
        PRIVATE
            GTest::gmock
            GTest::gtest
            GTest::gmock_main
            GTest::gtest_main
            # cryptopp::cryptopp
            parakeet_crypto
    )
    set_target_properties(parakeet_crypto_test PROPERTIES
        CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON EXPORT_COMPILE_COMMANDS ON)

    gtest_discover_tests(parakeet_crypto_test)
endif()

if(PARAKEET_CRYPTO_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
