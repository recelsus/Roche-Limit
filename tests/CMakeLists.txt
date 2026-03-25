enable_testing()

add_executable(roche_limit_auth_core_tests
    auth_core/auth_service_test.cc
)

target_link_libraries(roche_limit_auth_core_tests
    PRIVATE
        roche_limit_auth_core
        roche_limit_common
)

target_include_directories(roche_limit_auth_core_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

add_test(
    NAME roche_limit_auth_core_tests
    COMMAND roche_limit_auth_core_tests
)
