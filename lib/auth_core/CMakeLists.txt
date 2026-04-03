find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_library(roche_limit_auth_core
    src/api_key_hasher.cc
    src/auth_service.cc
    src/ip_rule_matcher.cc
    src/login_service.cc
    src/password_hasher.cc
)

target_include_directories(roche_limit_auth_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(roche_limit_auth_core
    PUBLIC
        roche_limit_common
        PkgConfig::SODIUM
)
