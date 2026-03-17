add_library(roche_limit_auth_core
    src/api_key_hasher.cc
    src/auth_service.cc
)

target_include_directories(roche_limit_auth_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(roche_limit_auth_core
    PUBLIC
        roche_limit_common
)
