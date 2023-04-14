add_executable(project_test 
    test.cpp 
    src/additional.cpp
)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

target_link_libraries(project_test GTest::gtest_main fmt spdlog)

include(GoogleTest)
gtest_discover_tests(project_test)