cmake_minimum_required(VERSION 3.21)
project(qrc-decode)

add_executable(${PROJECT_NAME} src/qrc-cli.cpp)
target_link_libraries(${PROJECT_NAME} parakeet::crypto)
target_include_directories(${PROJECT_NAME}
    PRIVATE
        $<TARGET_PROPERTY:parakeet::crypto,INCLUDE_DIRECTORIES>
)
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON EXPORT_COMPILE_COMMANDS ON)
