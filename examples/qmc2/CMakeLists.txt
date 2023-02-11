cmake_minimum_required(VERSION 3.21)
project(qmc2)

add_executable(qmc2 src/qmc2-example.cpp)
target_link_libraries(qmc2 ParakeetCrypto::core)
target_include_directories(qmc2
    PRIVATE
        $<TARGET_PROPERTY:ParakeetCrypto::core,INCLUDE_DIRECTORIES>
)
set_target_properties(qmc2 PROPERTIES
    CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON EXPORT_COMPILE_COMMANDS ON)
