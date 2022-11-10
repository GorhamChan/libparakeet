cmake_minimum_required(VERSION 3.21)
project(parakeet_crypro)
set (CMAKE_CXX_STANDARD 20)

include(cmake/CPM-Loader.cmake)

CPMAddPackage("gh:abdes/cryptopp-cmake#CRYPTOPP_8_7_0")

if (!MSVC)
	link_libraries(m)
endif()

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS YES CACHE BOOL "Export all symbols")

file(GLOB_RECURSE SOURCES src/*.cpp src/*.h)

# Add source to this project's executable.
add_library (${PROJECT_NAME} STATIC ${SOURCES})
target_include_directories(
  ${PROJECT_NAME} 
  PRIVATE
  "src" 
)
target_include_directories(${PROJECT_NAME} PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(${PROJECT_NAME} OBJECT cryptopp::cryptopp)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_constexpr)
set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE 1)

# Tests!
enable_testing()
find_package(GTest CONFIG)

if(TARGET GTest::gtest)
  file(GLOB_RECURSE TESTS_SOURCE *.test.cc *.test.hh)
  add_executable(${PROJECT_NAME}_test ${TESTS_SOURCE})
  target_link_libraries(${PROJECT_NAME}_test GTest::gmock GTest::gtest GTest::gmock_main GTest::gtest_main)
  target_link_libraries(${PROJECT_NAME}_test ${PROJECT_NAME})
  target_include_directories(${PROJECT_NAME}_test PRIVATE src)

  include(GoogleTest)
  gtest_discover_tests(${PROJECT_NAME}_test)
endif()
