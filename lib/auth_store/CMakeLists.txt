find_package(SQLite3 REQUIRED)

add_library(roche_limit_auth_store
    src/rule_repository.cc
    src/schema_bootstrap.cc
    src/sqlite_connection.cc
)

target_include_directories(roche_limit_auth_store
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(roche_limit_auth_store
    PUBLIC
        SQLite::SQLite3
        roche_limit_auth_core
        roche_limit_common
)

target_compile_definitions(roche_limit_auth_store
    PRIVATE
        ROCHE_LIMIT_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)
