cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 20)
project(traffic_sniffer)


set(SOURCES
    src/ethDevice.cpp
    src/additional.cpp
    src/hostInfo.cpp
)

add_executable(traffic_sniffer ${SOURCES} src/main.cpp)
target_link_libraries(traffic_sniffer pcap fmt spdlog)


add_executable(sniffer_tests ${SOURCES} test/test.cpp)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

target_link_libraries(sniffer_tests GTest::gtest_main fmt spdlog)
target_link_libraries(sniffer_tests pcap fmt spdlog)

include(GoogleTest)
gtest_discover_tests(sniffer_tests)