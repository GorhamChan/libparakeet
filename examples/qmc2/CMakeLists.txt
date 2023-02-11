cmake_minimum_required(VERSION 3.21)
project(qmc2)

add_executable(qmc2 src/qmc2-example.cpp)
target_link_libraries(qmc2 parakeet_crypro)
include_directories(qmc2
    PRIVATE
        $<TARGET_PROPERTY:parakeet_crypro,INCLUDE_DIRECTORIES>
)
