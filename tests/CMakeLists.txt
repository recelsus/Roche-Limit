add_executable(roche_limit_auth_core_tests
    auth_core/auth_service_test.cc
)

add_executable(roche_limit_login_service_tests
    auth_core/login_service_test.cc
)

add_executable(roche_limit_client_ip_resolver_tests
    server/client_ip_resolver_test.cc
    ../server/http/client_ip_resolver.cc
)

add_executable(roche_limit_request_observability_tests
    server/request_observability_test.cc
    ../server/http/request_observability.cc
)

add_executable(roche_limit_auth_store_integration_tests
    auth_store/repository_integration_test.cc
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

target_link_libraries(roche_limit_login_service_tests
    PRIVATE
        roche_limit_auth_core
        roche_limit_common
)

target_link_libraries(roche_limit_client_ip_resolver_tests
    PRIVATE
        roche_limit_auth_core
        roche_limit_common
)

target_link_libraries(roche_limit_request_observability_tests
    PRIVATE
        roche_limit_common
)

target_link_libraries(roche_limit_auth_store_integration_tests
    PRIVATE
        roche_limit_auth_store
        roche_limit_auth_core
        roche_limit_common
)

target_include_directories(roche_limit_login_service_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(roche_limit_client_ip_resolver_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/server/http
)

target_include_directories(roche_limit_request_observability_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/server/http
)

target_include_directories(roche_limit_auth_store_integration_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

add_test(
    NAME roche_limit_auth_core_tests
    COMMAND roche_limit_auth_core_tests
)

add_test(
    NAME roche_limit_login_service_tests
    COMMAND roche_limit_login_service_tests
)

add_test(
    NAME roche_limit_client_ip_resolver_tests
    COMMAND roche_limit_client_ip_resolver_tests
)

add_test(
    NAME roche_limit_request_observability_tests
    COMMAND roche_limit_request_observability_tests
)

add_test(
    NAME roche_limit_auth_store_integration_tests
    COMMAND roche_limit_auth_store_integration_tests
)
