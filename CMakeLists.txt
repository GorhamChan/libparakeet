cmake_minimum_required(VERSION 3.21)
project(parakeet_crypro)

option(PARAKEET_CRYPTO_BUILD_TESTING "Build library tests" ON)

find_program(CCACHE_TOOL_PATH ccache) # Optional

include(cmake/CPM-Loader.cmake)

CPMAddPackage(
  NAME cryptopp-cmake
  GITHUB_REPOSITORY abdes/cryptopp-cmake
  GIT_TAG CRYPTOPP_8_7_0
  OPTIONS
    "CRYPTOPP_INSTALL OFF"
    "CRYPTOPP_BUILD_TESTING OFF"
)

if (!MSVC)
	link_libraries(m)

  # Enable Ccache.
  if (CCACHE_TOOL_PATH)
    CPMAddPackage(
      NAME Ccache.cmake
      GITHUB_REPOSITORY TheLartians/Ccache.cmake
      VERSION 1.2
    )
  endif()
endif()

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS YES CACHE BOOL "Export all symbols")

file(GLOB_RECURSE SOURCES src/*.cpp src/*.h)

# Add source to this project's executable.
add_library (parakeet_crypro STATIC ${SOURCES})
target_include_directories(
  parakeet_crypro
  PUBLIC 
    $<INSTALL_INTERFACE:include>    
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE
    src
)
target_link_libraries(parakeet_crypro PRIVATE cryptopp::cryptopp)
target_compile_features(parakeet_crypro PRIVATE cxx_constexpr cxx_std_20)
set_property(TARGET parakeet_crypro PROPERTY POSITION_INDEPENDENT_CODE 1)

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

  file(GLOB_RECURSE TESTS_SOURCE src/*.test.cc src/*.test.hh)
  add_executable(parakeet_crypto_test ${TESTS_SOURCE})
  target_link_libraries(parakeet_crypto_test GTest::gmock GTest::gtest GTest::gmock_main GTest::gtest_main)
  target_link_libraries(parakeet_crypto_test ${PROJECT_NAME})
  target_include_directories(parakeet_crypto_test PRIVATE src)
  target_compile_features(parakeet_crypto_test PRIVATE cxx_std_20)

  include(GoogleTest)
  gtest_discover_tests(parakeet_crypto_test)
endif()
